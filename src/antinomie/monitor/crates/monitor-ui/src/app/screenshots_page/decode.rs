// SPDX-License-Identifier: GPL-3.0-only
//! Reading a PNG for the gallery: 8-bit samples of any colour type, taken
//! down by a whole-number step so that no side is longer than `max_side`
//! (thumbnails) and averaged over each block.
use eframe::egui::ColorImage;
use std::{fs::File, io::BufReader, path::Path};

/// Pixels a picture may have before it is refused.
const LIMIT: u64 = 100_000_000;

/// The picture at `path`, scaled down to at most `max_side` pixels wide or
/// high (thumbnails ask for their width; the viewer for its longest side).
pub(super) fn load(path: &Path, max_side: usize) -> Result<ColorImage, String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    let mut decoder = png::Decoder::new(BufReader::new(file));
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder.read_info().map_err(|e| e.to_string())?;
    let (width, height) = {
        let info = reader.info();
        (info.width as usize, info.height as usize)
    };
    if width == 0 || height == 0 || (width as u64) * (height as u64) > LIMIT {
        return Err("the picture has no usable size".into());
    }
    let size = reader
        .output_buffer_size()
        .ok_or("the picture is too large")?;
    let mut buffer = vec![0; size];
    let frame = reader.next_frame(&mut buffer).map_err(|e| e.to_string())?;
    let channels = match frame.color_type {
        png::ColorType::Grayscale => 1,
        png::ColorType::GrayscaleAlpha => 2,
        png::ColorType::Rgb => 3,
        png::ColorType::Rgba => 4,
        png::ColorType::Indexed => return Err("unsupported palette picture".into()),
    };
    if frame.bit_depth != png::BitDepth::Eight {
        return Err("unsupported bit depth".into());
    }
    let step = width.max(height).div_ceil(max_side.max(1)).max(1);
    let (out_w, out_h) = (width.div_ceil(step), height.div_ceil(step));
    let mut pixels = Vec::with_capacity(out_w * out_h * 4);
    let pixel = |x: usize, y: usize| -> [u32; 4] {
        let at = y * frame.line_size + x * channels;
        let p = &buffer[at..at + channels];
        match channels {
            1 => [p[0].into(), p[0].into(), p[0].into(), 255],
            2 => [p[0].into(), p[0].into(), p[0].into(), p[1].into()],
            3 => [p[0].into(), p[1].into(), p[2].into(), 255],
            _ => [p[0].into(), p[1].into(), p[2].into(), p[3].into()],
        }
    };
    for oy in 0..out_h {
        for ox in 0..out_w {
            let (x0, y0) = (ox * step, oy * step);
            let (x1, y1) = ((x0 + step).min(width), (y0 + step).min(height));
            let mut sum = [0u32; 4];
            for y in y0..y1 {
                for x in x0..x1 {
                    let p = pixel(x, y);
                    for (total, value) in sum.iter_mut().zip(p) {
                        *total += value;
                    }
                }
            }
            let count = ((x1 - x0) * (y1 - y0)) as u32;
            pixels.extend(sum.iter().map(|total| (total / count) as u8));
        }
    }
    Ok(ColorImage::from_rgba_unmultiplied([out_w, out_h], &pixels))
}
