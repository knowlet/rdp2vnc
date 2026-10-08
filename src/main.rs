mod config;
mod tls;
mod tui;
// Keep application modules small while sharing protocol primitives with tests.
use anyhow::{Context, Result};
use clap::Parser;
use ironrdp_server::Credentials;
use rdp2vnc::{auth, bridge, input, rfb, transport};
use std::{sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{Notify, mpsc, watch},
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    // Never enable upstream credential/packet debug logs through RUST_LOG.
    let level = std::env::var("RDP2VNC_LOG")
        .unwrap_or_else(|_| "info".into())
        .parse::<tracing::Level>()
        .context("RDP2VNC_LOG must be error, warn, info, debug, or trace")?;
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::new(format!(
            "off,rdp2vnc={level}"
        )))
        .init();
    let setup = if std::env::args_os().len() == 1 {
        let Some(setup) = tui::run()? else {
            return Ok(());
        };
        setup
    } else {
        tui::Setup {
            args: config::Args::parse(),
            vnc_password: None,
            rdp_password: None,
        }
    };
    let args = setup.args;
    args.validate()?;
    let password = config::vnc_password(&args, setup.vnc_password)?;
    let target = args.target.as_ref().context("VNC target is required")?;
    let options = rfb::Options {
        auth: args.auth,
        username: args.username.clone(),
        password,
        allow_insecure: args.allow_insecure_vnc,
        ca: args.vnc_ca.clone(),
    };
    eprintln!("Connecting to VNC {} …", target.authority());
    let client = tokio::time::timeout(Duration::from_secs(30), async {
        let (wire, protected) =
            transport::connect(target, args.ssh.as_deref(), args.ssh_port).await?;
        rfb::Client::handshake(wire, target, protected, &options).await
    })
    .await
    .context("VNC handshake timed out")??;
    eprintln!(
        "VNC ready: {}×{}; {}; Apple compatibility: {}",
        client.frame.width, client.frame.height, client.security, client.apple
    );
    if args.probe {
        return Ok(());
    }
    let rdp_password = config::rdp_password(&args, setup.rdp_password)?;
    let (tls, public_key) = tls::identity(&args)?;
    let listener = TcpListener::bind(args.listen).await.with_context(|| {
        format!(
            "cannot listen on {}; choose --listen ADDRESS:PORT",
            args.listen
        )
    })?;
    tls::profile(&args)?;
    let (frames, receiver) = watch::channel(Arc::new(client.frame.clone()));
    let (inputs, input_rx) = mpsc::channel(256);
    let fatal = Arc::new(Notify::new());
    let mac = match args.keymap {
        input::Keymap::Auto => client.apple,
        input::Keymap::Mac => true,
        input::Keymap::Pc => false,
    };
    let settings = bridge::Settings {
        listen: args.listen,
        tls,
        public_key,
        credentials: Credentials {
            username: args.rdp_username,
            password: rdp_password.to_string(),
            domain: None,
        },
        read_only: args.read_only,
        mac,
    };
    let mut vnc = tokio::spawn(client.run(frames, input_rx, args.fps));
    eprintln!(
        "RDP ready on {} (TLS + NLA). mstsc /v:{}",
        args.listen, args.listen
    );
    if args.allow_remote {
        eprintln!(
            "Remote RDP enabled: restrict this port with a VPN/firewall. Do not expose it to the Internet."
        );
    }
    let mut vnc_completed = false;
    let outcome = tokio::select! {
        signal=tokio::signal::ctrl_c()=>signal.context("handling Ctrl-C"),
        result=&mut vnc=>{vnc_completed=true;match result{Ok(result)=>result,Err(error)=>Err(error).context("VNC worker failed")}},
        _=fatal.notified()=>Err(anyhow::anyhow!("input queue exhausted; closing rather than losing key-release events")),
        result=bridge::run(listener,settings,receiver,inputs.clone(),fatal.clone())=>result,
    };
    // Best-effort release before closing the VNC/SSH stream. A dead peer must not
    // prevent cancellation. Dropping the SSH child terminates the helper.
    let _ = tokio::time::timeout(Duration::from_millis(250), inputs.send(rfb::Input::Reset)).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    if !vnc_completed {
        vnc.abort();
        let _ = vnc.await;
    }
    outcome
}
