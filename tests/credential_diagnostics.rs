#![cfg(any(unix, windows))]

use std::{
    ffi::OsString,
    io::{Read, Write},
    net::TcpListener,
    process::{Command, Output},
    thread,
    time::{Duration, Instant},
};

const CANARY: &str = "credential-canary-never-log";

fn invalid_unicode_secret() -> OsString {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        let mut bytes = CANARY.as_bytes().to_vec();
        bytes.push(0xff);
        OsString::from_vec(bytes)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        let mut units: Vec<_> = CANARY.encode_utf16().collect();
        units.push(0xd800);
        OsString::from_wide(&units)
    }
}

fn assert_redacted(output: Output) {
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("password environment variable is not UTF-8")
    );
    for bytes in [&output.stdout, &output.stderr] {
        assert!(
            !String::from_utf8_lossy(bytes).contains(CANARY),
            "credential bytes leaked into process output"
        );
    }
}

#[test]
fn invalid_unicode_vnc_password_is_redacted() {
    let output = Command::new(env!("CARGO_BIN_EXE_rdp2vnc"))
        .args([
            "127.0.0.1:5900",
            "--vnc-password-env",
            "RDP2VNC_TEST_INVALID_PASSWORD",
        ])
        .env("RDP2VNC_TEST_INVALID_PASSWORD", invalid_unicode_secret())
        .env_remove("RDP2VNC_LOG")
        .output()
        .unwrap();
    assert_redacted(output);
}

#[test]
fn invalid_unicode_rdp_password_is_redacted() {
    // A disposable loopback RFB fixture gets the CLI as far as its RDP
    // password check, before it creates any listener certificate or profile.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = listener.local_addr().unwrap().to_string();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut wire = loop {
            match listener.accept() {
                Ok((wire, _)) => break wire,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "CLI did not connect to the fixture"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("accepting fixture connection: {error}"),
            }
        };
        // Accepted sockets inherit nonblocking mode on macOS and Windows.
        wire.set_nonblocking(false).unwrap();
        wire.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        wire.set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        wire.write_all(b"RFB 003.008\n").unwrap();
        let mut version = [0; 12];
        wire.read_exact(&mut version).unwrap();
        assert_eq!(&version, b"RFB 003.008\n");
        wire.write_all(&[1, 1]).unwrap(); // Only None, on loopback.
        let mut selected = [0];
        wire.read_exact(&mut selected).unwrap();
        assert_eq!(selected, [1]);
        wire.write_all(&0u32.to_be_bytes()).unwrap();
        let mut shared = [0];
        wire.read_exact(&mut shared).unwrap();
        assert_eq!(shared, [1]);
        wire.write_all(&[0, 1, 0, 1]).unwrap(); // 1x1 framebuffer.
        wire.write_all(&[32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0])
            .unwrap();
        wire.write_all(&0u32.to_be_bytes()).unwrap(); // Empty name.
        let mut format = [0; 20];
        wire.read_exact(&mut format).unwrap();
        assert_eq!(&format[..4], &[0, 0, 0, 0]);
        let mut encodings = [0; 4];
        wire.read_exact(&mut encodings).unwrap();
        assert_eq!(&encodings[..2], &[2, 0]);
        let mut values = vec![0; usize::from(u16::from_be_bytes([encodings[2], encodings[3]])) * 4];
        wire.read_exact(&mut values).unwrap();
        let mut refresh = [0; 10];
        wire.read_exact(&mut refresh).unwrap();
        assert_eq!(refresh, [3, 0, 0, 0, 0, 0, 0, 1, 0, 1]);
    });
    let output = Command::new(env!("CARGO_BIN_EXE_rdp2vnc"))
        .args([
            &target,
            "--auth",
            "none",
            "--rdp-password-env",
            "RDP2VNC_TEST_INVALID_PASSWORD",
        ])
        .env("RDP2VNC_TEST_INVALID_PASSWORD", invalid_unicode_secret())
        .env_remove("RDP2VNC_LOG")
        .output()
        .unwrap();
    server.join().unwrap();
    assert_redacted(output);
}
