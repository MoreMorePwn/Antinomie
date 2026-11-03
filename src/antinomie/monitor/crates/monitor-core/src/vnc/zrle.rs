// SPDX-License-Identifier: GPL-3.0-only
//! The ZRLE encoding of RFB: one zlib stream for the whole connection, each
//! update a sync-flushed chunk of it, cut into 64x64 tiles. The pixel format
//! this client asks for (32 bits, R, G, B in the low three bytes) makes every
//! compressed pixel three bytes: R, G, B.
use super::{Fb, Rect};
use flate2::{Decompress, FlushDecompress};

/// A rectangle's decompressed tiles never come near this.
const OUTPUT_LIMIT: usize = 256 * 1024 * 1024;

pub(super) struct Zrle {
    inflate: Decompress,
}

impl Zrle {
    pub(super) fn new() -> Self {
        Self {
            inflate: Decompress::new(true),
        }
    }

    /// Decode one rectangle's compressed data into the framebuffer. The rectangle
    /// lies inside it (checked by the caller).
    pub(super) fn decode(&mut self, data: &[u8], rect: Rect, fb: &mut Fb) -> Result<(), String> {
        let tiles = rect.w.div_ceil(64) * rect.h.div_ceil(64);
        let mut out = Vec::with_capacity(rect.w * rect.h * 3 + tiles + 64);
        let mut input = data;
        loop {
            if out.len() == out.capacity() {
                if out.len() > OUTPUT_LIMIT {
                    return Err("ZRLE data is too large".into());
                }
                out.reserve(64 * 1024);
            }
            let before = self.inflate.total_in();
            self.inflate
                .decompress_vec(input, &mut out, FlushDecompress::Sync)
                .map_err(|e| format!("ZRLE zlib: {e}"))?;
            let used = (self.inflate.total_in() - before) as usize;
            input = &input[used.min(input.len())..];
            if out.len() < out.capacity() && (input.is_empty() || used == 0) {
                break;
            }
        }
        let mut reader = Bytes { data: &out, pos: 0 };
        for ty in (0..rect.h).step_by(64) {
            let th = (rect.h - ty).min(64);
            for tx in (0..rect.w).step_by(64) {
                let tw = (rect.w - tx).min(64);
                tile(&mut reader, fb, rect.x + tx, rect.y + ty, tw, th)?;
            }
        }
        Ok(())
    }
}

struct Bytes<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Bytes<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], String> {
        let end = self.pos.checked_add(n).filter(|end| *end <= self.data.len());
        let end = end.ok_or("ZRLE data ends inside a tile")?;
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
    fn byte(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn pixel(&mut self) -> Result<[u8; 3], String> {
        let p = self.take(3)?;
        Ok([p[0], p[1], p[2]])
    }
}

fn tile(r: &mut Bytes, fb: &mut Fb, x: usize, y: usize, w: usize, h: usize) -> Result<(), String> {
    let sub = r.byte()?;
    let rle = sub & 0x80 != 0;
    let size = usize::from(sub & 0x7f);
    let total = w * h;
    let at = |i: usize| (x + i % w, y + i / w);
    match (rle, size) {
        (false, 0) => {
            for i in 0..total {
                let (px, py) = at(i);
                let color = r.pixel()?;
                fb.set(px, py, color);
            }
        }
        (false, 1) => {
            let color = r.pixel()?;
            fb.fill(x, y, w, h, color);
        }
        (false, 2..=16) => {
            let mut palette = [[0u8; 3]; 16];
            for entry in palette.iter_mut().take(size) {
                *entry = r.pixel()?;
            }
            let bits = match size {
                2 => 1,
                3..=4 => 2,
                _ => 4,
            };
            let row_bytes = (w * bits).div_ceil(8);
            for row in 0..h {
                let packed = r.take(row_bytes)?;
                for col in 0..w {
                    let shift = 8 - bits - (col * bits) % 8;
                    let index = usize::from(packed[col * bits / 8] >> shift) & ((1 << bits) - 1);
                    fb.set(x + col, y + row, palette[index.min(size - 1)]);
                }
            }
        }
        (true, 0) => {
            let mut i = 0;
            while i < total {
                let color = r.pixel()?;
                let run = run_length(r)?;
                put_run(fb, &at, &mut i, total, run, color)?;
            }
        }
        (true, 2..=127) => {
            let mut palette = [[0u8; 3]; 127];
            for entry in palette.iter_mut().take(size) {
                *entry = r.pixel()?;
            }
            let mut i = 0;
            while i < total {
                let code = r.byte()?;
                let run = if code & 0x80 != 0 { run_length(r)? } else { 1 };
                let index = usize::from(code & 0x7f);
                if index >= size {
                    return Err("ZRLE palette index out of range".into());
                }
                put_run(fb, &at, &mut i, total, run, palette[index])?;
            }
        }
        _ => return Err(format!("ZRLE tile type {sub} is not valid")),
    }
    Ok(())
}

fn run_length(r: &mut Bytes) -> Result<usize, String> {
    let mut run = 1usize;
    loop {
        let b = r.byte()?;
        run += usize::from(b);
        if b != 255 {
            return Ok(run);
        }
    }
}

fn put_run(
    fb: &mut Fb,
    at: &dyn Fn(usize) -> (usize, usize),
    i: &mut usize,
    total: usize,
    run: usize,
    color: [u8; 3],
) -> Result<(), String> {
    if run > total - *i {
        return Err("ZRLE run is longer than its tile".into());
    }
    for _ in 0..run {
        let (px, py) = at(*i);
        fb.set(px, py, color);
        *i += 1;
    }
    Ok(())
}
