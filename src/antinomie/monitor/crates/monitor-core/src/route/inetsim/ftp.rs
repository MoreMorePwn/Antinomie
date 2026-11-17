// SPDX-License-Identifier: GPL-3.0-only
//! The fake FTP server of port 21: any login, passive mode (PASV and EPSV),
//! RETR, STOR, LIST. A download gets a stand-in or the fake file; an upload
//! is kept for the run. The data connection is the guest's own connection to
//! the port PASV named, which the gateway hands to this session.
use super::{
    log::{printable, Line, Login, Transfer, MAX_LINES},
    services::{now_ms, Services},
    stand_in,
};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::Ipv4Addr,
    os::unix::net::UnixStream,
    sync::{mpsc::Receiver, Arc},
    time::{Duration, Instant},
};

const IDLE: Duration = Duration::from_secs(60);
/// How long a transfer command waits for the guest's data connection.
const DATA_WAIT: Duration = Duration::from_secs(10);

/// Serves one FTP control connection to `ip:port`.
pub(super) fn serve(services: Arc<Services>, stream: UnixStream, ip: Ipv4Addr, port: u16) {
    let view = services.view();
    let endpoint = format!("{ip}:{port}");
    let Some(id) = services.open_session("ftp", endpoint.clone()) else {
        return;
    };
    let deadline = Instant::now() + Duration::from_secs(view.options.session_seconds);
    let mut writer = &stream;
    let mut reader = BufReader::new(&stream);
    let mut data: Option<(u16, Receiver<UnixStream>)> = None;
    let mut user = String::new();
    let mut bytes = 0u64;
    let session = services.session_number(id);
    let ended = 'session: {
        if writer.write_all(b"220 (vsFTPd 3.0.3)\r\n").is_err() {
            break 'session "closed by the guest";
        }
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break 'session "time limit";
            }
            let _ = stream.set_read_timeout(Some(left.min(IDLE)));
            let mut raw = Vec::new();
            match (&mut reader).take(4096).read_until(b'\n', &mut raw) {
                Ok(0) => break 'session "closed by the guest",
                Ok(n) => bytes += n as u64,
                Err(_) if Instant::now() >= deadline => break 'session "time limit",
                Err(_) => break 'session "idle",
            }
            if bytes > view.options.session_bytes {
                break 'session "byte limit";
            }
            let text = printable(raw.trim_ascii_end());
            let (verb, arg) = match text.split_once(' ') {
                Some((verb, arg)) => (verb.to_ascii_uppercase(), arg.trim().to_owned()),
                None => (text.to_ascii_uppercase(), String::new()),
            };
            let ms = now_ms();
            if verb != "PASS" {
                services.update(id, |s| {
                    if s.lines.len() < MAX_LINES {
                        s.lines.push(Line { ms, text: text.clone() });
                    } else {
                        s.lines_omitted += 1;
                    }
                });
            }
            let reply: String = match verb.as_str() {
                "USER" => {
                    user = arg;
                    "331 Please specify the password.\r\n".into()
                }
                "PASS" => {
                    let login = Login {
                        user: user.clone(),
                        password: arg,
                        accepted: true,
                    };
                    services.update(id, |s| s.logins.push(login));
                    "230 Login successful.\r\n".into()
                }
                "SYST" => "215 UNIX Type: L8\r\n".into(),
                "FEAT" => "211-Features:\r\n EPSV\r\n PASV\r\n SIZE\r\n211 End\r\n".into(),
                "TYPE" => "200 Switching to Binary mode.\r\n".into(),
                "PWD" | "XPWD" => "257 \"/\" is the current directory\r\n".into(),
                "CWD" | "CDUP" => "250 Directory successfully changed.\r\n".into(),
                "NOOP" | "OPTS" | "MODE" | "STRU" | "ALLO" => "200 OK.\r\n".into(),
                "SIZE" => {
                    let (served, _) = stand_in::serve(&arg, view.arch, view.options.stand_ins);
                    format!("213 {}\r\n", served.len())
                }
                "MDTM" => "213 20240101000000\r\n".into(),
                "DELE" | "RMD" | "RNTO" => "250 OK.\r\n".into(),
                "RNFR" => "350 Ready for RNTO.\r\n".into(),
                "MKD" => format!("257 \"{arg}\" created\r\n"),
                "PASV" | "EPSV" => {
                    if let Some((old, _)) = data.take() {
                        services.forget_passive(ip, old);
                    }
                    let (port, rx) = services.passive(ip);
                    data = Some((port, rx));
                    let o = ip.octets();
                    if verb == "PASV" {
                        format!(
                            "227 Entering Passive Mode ({},{},{},{},{},{}).\r\n",
                            o[0], o[1], o[2], o[3], port >> 8, port & 0xff
                        )
                    } else {
                        format!("229 Entering Extended Passive Mode (|||{port}|)\r\n")
                    }
                }
                "PORT" | "EPRT" => "502 Active mode is not supported; use PASV.\r\n".into(),
                "RETR" | "STOR" | "APPE" | "LIST" | "NLST" => {
                    let Some((port, rx)) = data.take() else {
                        let _ = writer.write_all(b"425 Use PORT or PASV first.\r\n");
                        continue;
                    };
                    let Ok(channel) = rx.recv_timeout(DATA_WAIT) else {
                        services.forget_passive(ip, port);
                        let _ = writer.write_all(b"425 Failed to establish connection.\r\n");
                        continue;
                    };
                    let _ = channel.set_read_timeout(Some(IDLE));
                    let _ = channel.set_write_timeout(Some(IDLE));
                    let transfer = Transfer {
                        ms,
                        protocol: "ftp".into(),
                        endpoint: endpoint.clone(),
                        host: ip.to_string(),
                        name: arg.clone(),
                        url: format!("ftp://{ip}/{}", arg.trim_start_matches('/')),
                        session,
                        ..Transfer::default()
                    };
                    match verb.as_str() {
                        "RETR" => {
                            let (body, served) = stand_in::serve(&arg, view.arch, view.options.stand_ins);
                            let _ = writer.write_all(
                                format!(
                                    "150 Opening BINARY mode data connection for {arg} ({} bytes).\r\n",
                                    body.len()
                                )
                                .as_bytes(),
                            );
                            let _ = (&channel).write_all(&body);
                            drop(channel);
                            services.transfer(
                                view.generation,
                                Transfer {
                                    direction: "download".into(),
                                    size: body.len() as u64,
                                    sha256: crate::storage::sha256_hex(&body),
                                    served,
                                    ..transfer
                                },
                            );
                        }
                        "STOR" | "APPE" => {
                            let _ = writer.write_all(b"150 Ok to send data.\r\n");
                            let mut upload = services.upload(view.generation, &arg);
                            let mut chunk = [0u8; 16 * 1024];
                            while let Ok(n) = (&channel).read(&mut chunk) {
                                if n == 0 {
                                    break;
                                }
                                upload.write(&chunk[..n]);
                            }
                            let done = upload.finish();
                            services.uploaded(view.generation, done.kept);
                            services.transfer(
                                view.generation,
                                Transfer {
                                    direction: "upload".into(),
                                    size: done.size,
                                    sha256: done.sha256,
                                    artifact: done.artifact,
                                    truncated: done.truncated,
                                    ..transfer
                                },
                            );
                        }
                        _ => {
                            let _ = writer.write_all(b"150 Here comes the directory listing.\r\n");
                            let listing: &[u8] = if verb == "LIST" {
                                b"-rwxr-xr-x    1 0        0          102400 Jan 01 00:00 update\r\n"
                            } else {
                                b"update\r\n"
                            };
                            let _ = (&channel).write_all(listing);
                        }
                    }
                    "226 Transfer complete.\r\n".into()
                }
                "QUIT" => {
                    let _ = writer.write_all(b"221 Goodbye.\r\n");
                    break 'session "logged out";
                }
                _ => "500 Unknown command.\r\n".into(),
            };
            if writer.write_all(reply.as_bytes()).is_err() {
                break 'session "closed by the guest";
            }
        }
    };
    if let Some((port, _)) = data {
        services.forget_passive(ip, port);
    }
    let end = now_ms();
    services.update(id, |s| {
        s.end_ms = end;
        s.bytes = bytes;
        s.ended = ended.into();
    });
}
