use crate::{input::Keymap, rfb::Auth, transport::Endpoint};
use anyhow::{Context, Result, ensure};
use clap::Parser;
use std::{
    io::{IsTerminal, Read},
    net::SocketAddr,
    path::PathBuf,
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    version,
    about = "Use mstsc with a VNC desktop. No arguments opens the TUI.",
    after_help = "Examples:\n  rdp2vnc\n  rdp2vnc 127.0.0.1:5900 --ssh user@mac.local --username user\n  rdp2vnc server:5900 --vnc-ca ca.pem\n\nPasswords: RDP2VNC_VNC_PASSWORD and RDP2VNC_RDP_PASSWORD, files, or a masked prompt.\nNo plaintext password argument is accepted. RDP always requires TLS + NLA."
)]
pub struct Args {
    /// VNC host[:port], [IPv6]:port or vnc://host:port. Default VNC port: 5900.
    pub target: Option<Endpoint>,
    /// RDP bind address. Remote binds require --allow-remote.
    #[arg(short = 'l', long, default_value = "127.0.0.1:3390")]
    pub listen: SocketAddr,
    /// Explicitly permit a non-loopback RDP listener. Use a VPN/firewall.
    #[arg(long)]
    pub allow_remote: bool,
    /// Authenticate and forward through system OpenSSH. Target must be loopback on this host.
    #[arg(long)]
    pub ssh: Option<String>,
    #[arg(long,default_value_t=22,value_parser=clap::value_parser!(u16).range(1..))]
    pub ssh_port: u16,
    /// VNC account username: selects Apple ARD or VeNCrypt X509Plain in auto mode.
    #[arg(short = 'u', long, alias = "vnc-username")]
    pub username: Option<String>,
    #[arg(long,value_enum,default_value_t=Auth::Auto)]
    pub auth: Auth,
    /// Environment variable containing the VNC password.
    #[arg(
        long,
        default_value = "RDP2VNC_VNC_PASSWORD",
        conflicts_with = "vnc_password_file"
    )]
    pub vnc_password_env: String,
    /// UTF-8 password file, not a legacy encrypted .vnc/passwd file.
    #[arg(long)]
    pub vnc_password_file: Option<PathBuf>,
    /// Separate username for the RDP/NLA gateway, NOT the Mac/VNC account.
    #[arg(long, default_value = "rdp2vnc")]
    pub rdp_username: String,
    #[arg(
        long,
        default_value = "RDP2VNC_RDP_PASSWORD",
        conflicts_with = "rdp_password_file"
    )]
    pub rdp_password_env: String,
    #[arg(long)]
    pub rdp_password_file: Option<PathBuf>,
    /// PEM certificate for the RDP listener. Generated locally if omitted.
    #[arg(long, requires = "key")]
    pub cert: Option<PathBuf>,
    #[arg(long, requires = "cert")]
    pub key: Option<PathBuf>,
    /// Additional CA for X509 VeNCrypt. The hostname must still match.
    #[arg(long)]
    pub vnc_ca: Option<PathBuf>,
    /// Permit an unencrypted VNC leg on a trusted VPN/LAN. Never enables insecure RDP.
    #[arg(long)]
    pub allow_insecure_vnc: bool,
    #[arg(long,value_enum,default_value_t=Keymap::Auto)]
    pub keymap: Keymap,
    #[arg(long)]
    pub read_only: bool,
    /// Maximum requested VNC update frequency, not a guaranteed rendering frame rate.
    #[arg(long,default_value_t=20,value_parser=clap::value_parser!(u16).range(1..=60))]
    pub fps: u16,
    /// Test VNC authentication and report capabilities; do not start an RDP listener.
    #[arg(long)]
    pub probe: bool,
    /// Write an mstsc profile with no password (refuses to overwrite).
    #[arg(long)]
    pub rdp_file: Option<PathBuf>,
}
impl Args {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.target.is_some(),
            "specify a VNC target, or run without arguments for the TUI"
        );
        ensure!(self.listen.port() != 0, "RDP port must not be zero");
        ensure!(
            self.listen.ip().is_loopback() || self.allow_remote,
            "non-loopback RDP binding requires --allow-remote; default is 127.0.0.1:3390"
        );
        ensure!(
            !self.rdp_username.is_empty()
                && self.rdp_username.len() <= 128
                && !self.rdp_username.chars().any(|c| c.is_control())
                && !self.rdp_username.contains(['\\', '@']),
            "RDP username must be a simple local name (no domain or control characters)"
        );
        ensure!(
            self.username
                .as_ref()
                .is_none_or(|u| !u.is_empty() && !u.contains('\0')),
            "empty/NUL VNC username"
        );
        ensure!(
            self.cert.is_some() == self.key.is_some(),
            "--cert and --key must be supplied together"
        );
        ensure!(
            !matches!(self.auth, Auth::Ard) || self.username.is_some(),
            "--auth ard requires --username"
        );
        if self.ssh.is_some() {
            ensure!(
                self.target.as_ref().is_some_and(Endpoint::is_loopback_name),
                "--ssh must terminate on the VNC host; specify 127.0.0.1:5900 as target"
            );
        }
        Ok(())
    }
}

/// Secret values are never accepted in argv, Debug, URLs, or generated profiles.
/// Explicit empty values fail rather than unexpectedly falling back to prompting.
pub fn secret(env_name: &str, file: Option<&PathBuf>) -> Result<Option<Zeroizing<String>>> {
    let value = if let Some(path) = file {
        let metadata = std::fs::metadata(path).context("reading password file metadata")?;
        ensure!(
            metadata.is_file() && metadata.len() <= 4096,
            "password file must be a regular file <=4096 bytes"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                metadata.permissions().mode() & 0o077 == 0,
                "password file is readable by other users; chmod 600 it"
            );
        }
        // Keep the allocation guarded even on read/validation errors. Reserve
        // the full bounded read so growth cannot leave previous secret buffers.
        let mut value = Zeroizing::new(String::with_capacity(4097));
        std::fs::File::open(path)?
            .take(4097)
            .read_to_string(&mut value)
            .context("reading UTF-8 password file")?;
        ensure!(value.len() <= 4096, "password file exceeds 4096 bytes");
        // Strip exactly one conventional line ending in place; preserve spaces.
        if value.ends_with("\r\n") {
            let length = value.len() - 2;
            value.truncate(length);
        } else if value.ends_with('\n') {
            value.pop();
        }
        Some(value)
    } else {
        match std::env::var(env_name) {
            Ok(value) => Some(Zeroizing::new(value)),
            Err(std::env::VarError::NotPresent) => None,
            Err(error) => return Err(error).context("password environment variable is not UTF-8"),
        }
    };
    value
        .map(|v| {
            ensure!(
                !v.is_empty() && v.len() <= 1024 && !v.contains(['\0', '\r', '\n']),
                "password must be nonempty, at most 1024 bytes, and contain no NUL/newline"
            );
            Ok(v)
        })
        .transpose()
}

pub fn vnc_password(args: &Args, entered: Option<Zeroizing<String>>) -> Result<Zeroizing<String>> {
    if let Some(value) = entered {
        return Ok(value);
    }
    if args.auth == Auth::None {
        return Ok(Zeroizing::new(String::new()));
    }
    if let Some(value) = secret(&args.vnc_password_env, args.vnc_password_file.as_ref())? {
        return Ok(value);
    }
    ensure!(
        std::io::stdin().is_terminal() && std::io::stderr().is_terminal(),
        "missing VNC password: set RDP2VNC_VNC_PASSWORD or --vnc-password-file in non-interactive mode"
    );
    Ok(Zeroizing::new(rpassword::prompt_password(
        "VNC password (hidden): ",
    )?))
}

pub fn rdp_password(args: &Args, entered: Option<Zeroizing<String>>) -> Result<Zeroizing<String>> {
    if let Some(value) = entered {
        ensure!(
            value.len() >= 12,
            "RDP gateway password must be at least 12 bytes"
        );
        return Ok(value);
    }
    if let Some(value) = secret(&args.rdp_password_env, args.rdp_password_file.as_ref())? {
        ensure!(
            value.len() >= 12,
            "RDP gateway password must be at least 12 bytes"
        );
        return Ok(value);
    }
    ensure!(
        std::io::stderr().is_terminal(),
        "missing RDP password: set RDP2VNC_RDP_PASSWORD or --rdp-password-file for unattended operation"
    );
    let mut bytes = [0u8; 16];
    crate::auth::random_bytes(&mut bytes)?;
    let password: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    eprintln!(
        "One-time RDP/NLA login: {}\nPassword: {}\nThis generated password is shown only to this terminal; it is not persisted.",
        args.rdp_username, password
    );
    Ok(Zeroizing::new(password))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn defaults_do_not_compete_with_system_rdp() {
        let args = Args::try_parse_from(["rdp2vnc", "localhost"]).unwrap();
        assert_eq!(args.listen, "127.0.0.1:3390".parse().unwrap());
        assert!(args.validate().is_ok());
    }
    #[test]
    fn requires_explicit_remote_bind_and_valid_flags() {
        let args =
            Args::try_parse_from(["rdp2vnc", "localhost", "--listen", "0.0.0.0:3390"]).unwrap();
        assert!(args.validate().is_err());
        assert!(Args::try_parse_from(["rdp2vnc", "localhost", "--password", "secret"]).is_err());
        assert!(Args::try_parse_from(["rdp2vnc", "localhost", "--fps", "0"]).is_err());
        assert!(Args::try_parse_from(["rdp2vnc", "localhost", "--cert", "only.pem"]).is_err());
    }
    #[test]
    fn password_files_preserve_spaces_and_trim_only_one_line_ending() {
        use std::io::Write;
        for ending in ["", "\n", "\r\n"] {
            let mut file = tempfile::NamedTempFile::new().unwrap();
            write!(file, "  password  {ending}").unwrap();
            let value = secret("UNUSED", Some(&file.path().to_owned()))
                .unwrap()
                .unwrap();
            assert_eq!(value.as_str(), "  password  ");
        }
        for invalid in ["", "\n", "password\n\n", "password\r", "pass\0word"] {
            let mut file = tempfile::NamedTempFile::new().unwrap();
            file.write_all(invalid.as_bytes()).unwrap();
            assert!(secret("UNUSED", Some(&file.path().to_owned())).is_err());
        }
    }
}
