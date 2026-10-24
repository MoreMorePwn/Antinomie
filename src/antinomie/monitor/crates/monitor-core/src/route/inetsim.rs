// SPDX-License-Identifier: GPL-3.0-only
//! Antinomie's own fake services for the InetSim route: HTTP, SMTP and a
//! catch-all that reads and discards. Each guest connection to a port is
//! served on a thread of its own over an in-process socket pair, so nothing
//! listens on the host and nothing can be reached from outside. There is no
//! TLS: a connection to port 443 (or any other port) is accepted and the
//! guest's bytes are discarded; run INetSim (External mode) for HTTPS.
use std::{
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::UnixStream,
    thread,
    time::Duration,
};

const IDLE: Duration = Duration::from_secs(20);
const MAX_LINE: usize = 16 * 1024;
const MAX_BODY: u64 = 1 << 20;
const MAX_REQUESTS: usize = 64;

const PAGE: &str = "<html>\n  <head>\n    <title>Antinomie InetSim default page</title>\n  </head>\n  <body>\n    <p>This is the default page of the built-in fake web server.</p>\n  </body>\n</html>\n";

/// Serves one guest connection to `port` on a new thread.
pub(crate) fn spawn(port: u16, stream: UnixStream) -> Result<(), String> {
    stream
        .set_read_timeout(Some(IDLE))
        .and_then(|()| stream.set_write_timeout(Some(IDLE)))
        .map_err(|e| format!("built-in service: {e}"))?;
    thread::Builder::new()
        .name("route-inetsim".into())
        .spawn(move || {
            let _ = match port {
                80 | 8080 => http(stream),
                25 | 587 => smtp(stream),
                _ => sink(stream),
            };
        })
        .map(|_| ())
        .map_err(|e| format!("built-in service: {e}"))
}

fn sink(mut stream: UnixStream) -> std::io::Result<()> {
    let mut buffer = [0u8; 4096];
    while stream.read(&mut buffer)? != 0 {}
    Ok(())
}

/// A line without its line ending; `None` at end of input.
fn line(reader: &mut impl BufRead) -> std::io::Result<Option<String>> {
    let mut bytes = Vec::new();
    let mut limited = reader.take(MAX_LINE as u64);
    if limited.read_until(b'\n', &mut bytes)? == 0 {
        return Ok(None);
    }
    Ok(Some(
        String::from_utf8_lossy(&bytes)
            .trim_end_matches(['\r', '\n'])
            .to_owned(),
    ))
}

fn content_type(path: &str) -> &'static str {
    let name = path.split(['?', '#']).next().unwrap_or("");
    match name
        .rsplit_once('.')
        .map(|(_, ext)| ext.to_ascii_lowercase())
    {
        Some(ext) => match ext.as_str() {
            "txt" | "log" | "ini" | "cfg" => "text/plain",
            "json" => "application/json",
            "xml" => "text/xml",
            "js" => "application/javascript",
            "css" => "text/css",
            "png" => "image/png",
            "gif" => "image/gif",
            "jpg" | "jpeg" => "image/jpeg",
            "html" | "htm" => "text/html",
            _ => "application/octet-stream",
        },
        None => "text/html",
    }
}

fn http(stream: UnixStream) -> std::io::Result<()> {
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    for _ in 0..MAX_REQUESTS {
        let Some(request) = line(&mut reader)? else {
            return Ok(());
        };
        if request.is_empty() {
            continue;
        }
        let mut parts = request.split_whitespace();
        let (method, path) = (
            parts.next().unwrap_or("").to_ascii_uppercase(),
            parts.next().unwrap_or("/").to_owned(),
        );
        let mut length = 0u64;
        let mut close = parts.next() == Some("HTTP/1.0");
        loop {
            let Some(header) = line(&mut reader)? else {
                return Ok(());
            };
            if header.is_empty() {
                break;
            }
            if let Some((name, value)) = header.split_once(':') {
                match name.trim().to_ascii_lowercase().as_str() {
                    "content-length" => length = value.trim().parse().unwrap_or(0),
                    "connection" => close = value.trim().eq_ignore_ascii_case("close"),
                    _ => {}
                }
            }
        }
        // Read and drop a request body so the next request lines up.
        if length > MAX_BODY {
            return Ok(());
        }
        std::io::copy(&mut (&mut reader).take(length), &mut std::io::sink())?;
        let (status, body) = match method.as_str() {
            "GET" | "POST" | "PUT" | "HEAD" | "DELETE" | "OPTIONS" => ("200 OK", PAGE),
            _ => ("501 Not Implemented", ""),
        };
        let kind = content_type(&path);
        let body = if kind == "text/html" || status != "200 OK" {
            body
        } else {
            "Antinomie fake file\n"
        };
        let head = format!(
            "HTTP/1.1 {status}\r\nServer: Apache\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n",
            body.len(),
            if close { "close" } else { "keep-alive" }
        );
        writer.write_all(head.as_bytes())?;
        if method != "HEAD" {
            writer.write_all(body.as_bytes())?;
        }
        if close {
            return Ok(());
        }
    }
    Ok(())
}

fn smtp(stream: UnixStream) -> std::io::Result<()> {
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    writer.write_all(b"220 mail.example.com ESMTP ready\r\n")?;
    let mut data = false;
    let mut taken = 0u64;
    while let Some(text) = line(&mut reader)? {
        if data {
            taken += text.len() as u64 + 2;
            if text == "." {
                data = false;
                writer.write_all(b"250 OK message queued\r\n")?;
            } else if taken > MAX_BODY {
                writer.write_all(b"552 message too large\r\n")?;
                return Ok(());
            }
            continue;
        }
        let verb = text
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        let reply: &[u8] = match verb.as_str() {
            "HELO" => b"250 mail.example.com\r\n",
            "EHLO" => b"250-mail.example.com\r\n250 8BITMIME\r\n",
            "MAIL" | "RCPT" | "RSET" | "NOOP" => b"250 OK\r\n",
            "DATA" => {
                data = true;
                taken = 0;
                b"354 end data with <CR><LF>.<CR><LF>\r\n"
            }
            "QUIT" => {
                writer.write_all(b"221 bye\r\n")?;
                return Ok(());
            }
            _ => b"502 command not implemented\r\n",
        };
        writer.write_all(reply)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn talk(port: u16, send: &[u8]) -> String {
        let (mut guest, service) = UnixStream::pair().unwrap();
        spawn(port, service).unwrap();
        guest
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        guest.write_all(send).unwrap();
        guest.shutdown(std::net::Shutdown::Write).unwrap();
        let mut out = String::new();
        guest.read_to_string(&mut out).unwrap();
        out
    }

    #[test]
    fn http_answers_get_head_and_bodies() {
        let reply = talk(
            80,
            b"GET /index.html HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        );
        assert!(reply.starts_with("HTTP/1.1 200 OK"));
        assert!(reply.contains("InetSim default page"));
        let head = talk(80, b"HEAD /a.exe HTTP/1.0\r\n\r\n");
        assert!(head.contains("application/octet-stream") && !head.contains("fake file"));
        let post = talk(
            8080,
            b"POST /x HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcdGET /two HTTP/1.1\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(post.matches("HTTP/1.1 200 OK").count(), 2);
        assert!(talk(80, b"BREW / HTTP/1.1\r\n\r\n").starts_with("HTTP/1.1 501"));
    }

    #[test]
    fn smtp_takes_a_message() {
        let reply = talk(
            25,
            b"EHLO me\r\nMAIL FROM:<a@b>\r\nRCPT TO:<c@d>\r\nDATA\r\nSubject: x\r\n\r\nhello\r\n.\r\nQUIT\r\n",
        );
        assert!(reply.starts_with("220 "));
        assert!(reply.contains("354 ") && reply.contains("250 OK message queued"));
        assert!(reply.ends_with("221 bye\r\n"));
    }

    #[test]
    fn other_ports_discard_what_the_guest_sends() {
        assert_eq!(talk(443, b"\x16\x03\x01 client hello"), "");
        assert_eq!(talk(31337, b"anything"), "");
    }
}
