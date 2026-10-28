// SPDX-License-Identifier: GPL-3.0-only
//! The reader worker's request loop: JSON lines on stdin and stdout.
use super::{
    image::Image,
    protocol::{DiskRequest, Envelope, ReadError, Reply},
};
use std::{
    io::{self, BufRead, Read, Write},
    path::{Path, PathBuf},
};

/// A request line is at most this long; a longer one ends the worker.
const REQUEST_LIMIT: u64 = 64 * 1024;
/// Where the sandbox mounts the image and the extraction folder.
const IMAGE_PATH: &str = "/image";
const OUT_PATH: &str = "/out";
/// The reference image of a diff, when one is mounted.
const OTHER_PATH: &str = "/other";

/// Answer requests until `input` ends.
pub fn serve(image: &Image, mut input: impl BufRead, mut output: impl Write) -> io::Result<()> {
    loop {
        let mut line = String::new();
        let count = (&mut input).take(REQUEST_LIMIT).read_line(&mut line)?;
        if count == 0 {
            return Ok(());
        }
        if !line.ends_with('\n') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "oversized or truncated request",
            ));
        }
        let (id, reply): (u64, Reply) = match serde_json::from_str::<Envelope<DiskRequest>>(&line) {
            Ok(request) => (request.id, image.handle(request.id, request.body)),
            Err(error) => (0, Err(ReadError::Io(format!("bad request: {error}")))),
        };
        let mut encoded = serde_json::to_vec(&Envelope { id, body: reply })
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        encoded.push(b'\n');
        output.write_all(&encoded)?;
        output.flush()?;
    }
}

/// Dispatch the private `--disk-reader` entry point before CLI parsing.
/// `None` for an ordinary invocation, or the worker's exit code.
pub fn worker_main_if_requested() -> Option<i32> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.get(1).is_none_or(|arg| arg != "--disk-reader") {
        return None;
    }
    let result = (|| -> Result<(), String> {
        if args.len() != 2
            || std::env::var_os("ANTINOMIE_ISOLATED_WORKER").as_deref()
                != Some(std::ffi::OsStr::new("1"))
            || !Path::new(IMAGE_PATH).is_file()
        {
            return Err("the disk reader requires its sandbox".into());
        }
        let other = Path::new(OTHER_PATH)
            .is_file()
            .then(|| Path::new(OTHER_PATH));
        // Layers of a qcow2 chain below the image, when the parent mounted any.
        let lower: Vec<_> = (1..)
            .map(|index| PathBuf::from(format!("/layer{index}")))
            .take_while(|path| path.is_file())
            .collect();
        let image = if lower.is_empty() {
            Image::open_with(Path::new(IMAGE_PATH), other, Path::new(OUT_PATH))
        } else {
            Image::open_chain(Path::new(IMAGE_PATH), &lower, Path::new(OUT_PATH))
        };
        serve(&image, io::stdin().lock(), io::stdout().lock()).map_err(|error| error.to_string())
    })();
    if let Err(error) = &result {
        eprintln!("disk reader: {error}");
    }
    Some(i32::from(result.is_err()))
}
