// SPDX-License-Identifier: GPL-3.0-only
//! A SOCKS5 client (RFC 1928, with RFC 1929 user name and password): CONNECT
//! to an IPv4 address or to a host name the proxy resolves.
use super::config::SocksProxy;
use std::{
    io::{Read, Write},
    net::{Ipv4Addr, TcpStream, ToSocketAddrs},
    time::Duration,
};

/// What the guest connected to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Target {
    Ip(Ipv4Addr),
    /// A name the guest looked up; the proxy resolves it.
    Name(String),
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Ip(ip) => write!(f, "{ip}"),
            Target::Name(name) => f.write_str(name),
        }
    }
}

fn reply_text(code: u8) -> &'static str {
    match code {
        1 => "general failure",
        2 => "not allowed by the proxy's rules",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused",
        6 => "TTL expired",
        7 => "command not supported",
        8 => "address type not supported",
        _ => "unknown error",
    }
}

fn read_exact(stream: &mut TcpStream, len: usize) -> Result<Vec<u8>, String> {
    let mut buffer = vec![0u8; len];
    stream
        .read_exact(&mut buffer)
        .map_err(|e| format!("SOCKS5 proxy: {e}"))?;
    Ok(buffer)
}

/// Greets the proxy, authenticates when it asks to, and returns the stream
/// ready for a request.
pub(crate) fn open(proxy: &SocksProxy, timeout: Duration) -> Result<TcpStream, String> {
    let mut last = format!("cannot resolve {}", proxy.host);
    let mut connected = None;
    for address in (proxy.host.as_str(), proxy.port)
        .to_socket_addrs()
        .map_err(|e| format!("SOCKS5 proxy {}:{}: {e}", proxy.host, proxy.port))?
    {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => {
                connected = Some(stream);
                break;
            }
            Err(error) => last = error.to_string(),
        }
    }
    let mut stream =
        connected.ok_or_else(|| format!("SOCKS5 proxy {}:{}: {last}", proxy.host, proxy.port))?;
    stream
        .set_read_timeout(Some(timeout))
        .and_then(|()| stream.set_write_timeout(Some(timeout)))
        .and_then(|()| stream.set_nodelay(true))
        .map_err(|e| format!("SOCKS5 proxy: {e}"))?;
    let greeting: &[u8] = if proxy.credentials.is_some() {
        &[5, 2, 0, 2]
    } else {
        &[5, 1, 0]
    };
    stream
        .write_all(greeting)
        .map_err(|e| format!("SOCKS5 proxy: {e}"))?;
    let choice = read_exact(&mut stream, 2)?;
    if choice[0] != 5 {
        return Err("the proxy does not speak SOCKS5".into());
    }
    match choice[1] {
        0 => {}
        2 => {
            let credentials = proxy
                .credentials
                .as_ref()
                .ok_or("the proxy asks for a user name and password; none are set")?;
            let mut request = vec![1, credentials.username.len() as u8];
            request.extend_from_slice(credentials.username.as_bytes());
            request.push(credentials.password.len() as u8);
            request.extend_from_slice(credentials.password.as_bytes());
            stream
                .write_all(&request)
                .map_err(|e| format!("SOCKS5 proxy: {e}"))?;
            if read_exact(&mut stream, 2)?[1] != 0 {
                return Err("the proxy refused the user name and password".into());
            }
        }
        0xff => return Err("the proxy accepts none of the offered login methods".into()),
        other => return Err(format!("the proxy chose an unsupported method {other}")),
    }
    Ok(stream)
}

/// A TCP connection to `target:port` through the proxy.
pub(crate) fn connect(
    proxy: &SocksProxy,
    target: &Target,
    port: u16,
    timeout: Duration,
) -> Result<TcpStream, String> {
    let mut stream = open(proxy, timeout)?;
    let mut request = vec![5, 1, 0];
    match target {
        Target::Ip(ip) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        Target::Name(name) => {
            if name.is_empty() || name.len() > 255 {
                return Err("destination name has an invalid length".into());
            }
            request.push(3);
            request.push(name.len() as u8);
            request.extend_from_slice(name.as_bytes());
        }
    }
    request.extend_from_slice(&port.to_be_bytes());
    stream
        .write_all(&request)
        .map_err(|e| format!("SOCKS5 proxy: {e}"))?;
    let head = read_exact(&mut stream, 4)?;
    if head[0] != 5 {
        return Err("the proxy does not speak SOCKS5".into());
    }
    if head[1] != 0 {
        return Err(format!(
            "the proxy could not connect to {target}:{port}: {}",
            reply_text(head[1])
        ));
    }
    let bound = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => usize::from(read_exact(&mut stream, 1)?[0]) + 2,
        _ => return Err("the proxy answered with an unknown address type".into()),
    };
    read_exact(&mut stream, bound)?;
    stream
        .set_read_timeout(None)
        .and_then(|()| stream.set_write_timeout(None))
        .map_err(|e| format!("SOCKS5 proxy: {e}"))?;
    Ok(stream)
}
