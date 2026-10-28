// SPDX-License-Identifier: GPL-3.0-only
// Copyright (c) 2026 MikiMiku (MoreMorePwn)
//! The PDF writer: a small, deterministic PDF 1.4 file from the laid-out
//! pages. Standard fonts, Flate-compressed content streams, a bookmark per
//! section, a document title and a page number footer. Nothing is fetched
//! and no browser is involved.
use super::layout::Document;
use super::pdf_font::{Font, encode, width};
use super::pdf_layout::{Laid, Op, PAGE_H, PAGE_W, Rgb, lay_out};
use flate2::{Compression, write::ZlibEncoder};
use std::fmt::Write as _;
use std::io::Write as _;

fn num(value: f32) -> String {
    let text = format!("{value:.2}");
    text.trim_end_matches('0').trim_end_matches('.').to_owned()
}

fn color(rgb: Rgb) -> String {
    format!("{} {} {}", num(rgb[0]), num(rgb[1]), num(rgb[2]))
}

/// A PDF literal string for WinAnsi bytes.
fn literal(bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![b'('];
    for &byte in bytes {
        match byte {
            b'(' | b')' | b'\\' => {
                out.push(b'\\');
                out.push(byte);
            }
            0x20..=0x7e => out.push(byte),
            other => out.extend(format!("\\{other:03o}").bytes()),
        }
    }
    out.push(b')');
    out
}

fn content(ops: &[Op], footer: &str) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for op in ops {
        match op {
            Op::Text {
                x,
                y,
                font,
                size,
                color: rgb,
                text,
            } => {
                out.extend(
                    format!(
                        "BT /{} {} Tf {} rg {} {} Td ",
                        font.resource(),
                        num(*size),
                        color(*rgb),
                        num(*x),
                        num(*y)
                    )
                    .bytes(),
                );
                out.extend(literal(&encode(text)));
                out.extend(b" Tj ET\n");
            }
            Op::Rect { x, y, w, h, fill } => {
                out.extend(
                    format!(
                        "{} rg {} {} {} {} re f\n",
                        color(*fill),
                        num(*x),
                        num(*y),
                        num(*w),
                        num(*h)
                    )
                    .bytes(),
                );
            }
            Op::Rule {
                x1,
                x2,
                y,
                color: rgb,
            } => {
                out.extend(
                    format!(
                        "{} RG 0.6 w {} {} m {} {} l S\n",
                        color(*rgb),
                        num(*x1),
                        num(*y),
                        num(*x2),
                        num(*y)
                    )
                    .bytes(),
                );
            }
            Op::Frame {
                x,
                y,
                w,
                h,
                color: rgb,
            } => {
                out.extend(
                    format!(
                        "{} RG 0.4 w {} {} {} {} re S\n",
                        color(*rgb),
                        num(*x),
                        num(*y),
                        num(*w),
                        num(*h)
                    )
                    .bytes(),
                );
            }
        }
    }
    let footer_width = width(Font::Regular, 7.5, footer);
    out.extend(
        format!(
            "BT /F1 7.5 Tf 0.45 0.45 0.45 rg {} 18 Td ",
            num(PAGE_W - 36.0 - footer_width)
        )
        .bytes(),
    );
    out.extend(literal(&encode(footer)));
    out.extend(b" Tj ET\n");
    out
}

fn pdf_date(ms: u64) -> String {
    let text = super::utc(ms);
    format!(
        "D:{}{}{}{}{}{}Z",
        &text[0..4],
        &text[5..7],
        &text[8..10],
        &text[11..13],
        &text[14..16],
        &text[17..19]
    )
}

/// Objects are numbered in this order: catalog 1, pages 2, fonts 3 to 6, info
/// 7, outline root 8, the outline items, then a page and its stream each.
pub(super) fn render(document: &Document, generated_ms: u64) -> Result<Vec<u8>, String> {
    let Laid { pages, bookmarks } = lay_out(document);
    let first_item = 9;
    let first_page = first_item + bookmarks.len();
    let page_obj = |index: usize| first_page + index * 2;
    let total = pages.len();

    let mut objects: Vec<(usize, Vec<u8>)> = Vec::new();
    objects.push((
        1,
        b"<< /Type /Catalog /Pages 2 0 R /Outlines 8 0 R /PageMode /UseOutlines >>".to_vec(),
    ));
    let kids: String = (0..total)
        .map(|i| format!("{} 0 R", page_obj(i)))
        .collect::<Vec<_>>()
        .join(" ");
    objects.push((
        2,
        format!("<< /Type /Pages /Kids [{kids}] /Count {total} >>").into_bytes(),
    ));
    for (offset, font) in [Font::Regular, Font::Bold, Font::Oblique, Font::Mono]
        .into_iter()
        .enumerate()
    {
        objects.push((
            3 + offset,
            format!(
                "<< /Type /Font /Subtype /Type1 /BaseFont /{} /Encoding /WinAnsiEncoding >>",
                font.base_name()
            )
            .into_bytes(),
        ));
    }
    let mut info = b"<< /Title ".to_vec();
    info.extend(literal(&encode(&document.title)));
    info.extend(b" /Producer (Antinomie) /Creator (Antinomie Triage report) /CreationDate ");
    info.extend(literal(pdf_date(generated_ms).as_bytes()));
    info.extend(b" >>");
    objects.push((7, info));
    if bookmarks.is_empty() {
        objects.push((8, b"<< /Type /Outlines /Count 0 >>".to_vec()));
    } else {
        let last = first_item + bookmarks.len() - 1;
        objects.push((
            8,
            format!(
                "<< /Type /Outlines /First {first_item} 0 R /Last {last} 0 R /Count {} >>",
                bookmarks.len()
            )
            .into_bytes(),
        ));
        for (index, bookmark) in bookmarks.iter().enumerate() {
            let id = first_item + index;
            let mut item = b"<< /Title ".to_vec();
            item.extend(literal(&encode(&bookmark.title)));
            let mut tail = format!(
                " /Parent 8 0 R /Dest [{} 0 R /XYZ 0 {} 0]",
                page_obj(bookmark.page),
                num(bookmark.y)
            );
            if index > 0 {
                write!(tail, " /Prev {} 0 R", id - 1).map_err(|e| e.to_string())?;
            }
            if index + 1 < bookmarks.len() {
                write!(tail, " /Next {} 0 R", id + 1).map_err(|e| e.to_string())?;
            }
            tail.push_str(" >>");
            item.extend(tail.bytes());
            objects.push((id, item));
        }
    }
    for (index, page) in pages.iter().enumerate() {
        let id = page_obj(index);
        objects.push((
            id,
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {} {}] /Resources << /Font << \
                 /F1 3 0 R /F2 4 0 R /F3 5 0 R /F4 6 0 R >> >> /Contents {} 0 R >>",
                num(PAGE_W),
                num(PAGE_H),
                id + 1
            )
            .into_bytes(),
        ));
        let raw = content(&page.ops, &format!("Page {} of {total}", index + 1));
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(6));
        encoder.write_all(&raw).map_err(|e| e.to_string())?;
        let packed = encoder.finish().map_err(|e| e.to_string())?;
        let mut stream = format!(
            "<< /Length {} /Filter /FlateDecode >>\nstream\n",
            packed.len()
        )
        .into_bytes();
        stream.extend(packed);
        stream.extend(b"\nendstream");
        objects.push((id + 1, stream));
    }
    objects.sort_by_key(|(id, _)| *id);

    let mut out: Vec<u8> = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offsets = Vec::new();
    for (id, body) in &objects {
        offsets.push(out.len());
        out.extend(format!("{id} 0 obj\n").bytes());
        out.extend(body);
        out.extend(b"\nendobj\n");
    }
    let xref = out.len();
    out.extend(format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).bytes());
    for offset in &offsets {
        out.extend(format!("{offset:010} 00000 n \n").bytes());
    }
    // A stable file id from the content so far.
    let id = {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(&out);
        digest[..16]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    out.extend(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R /Info 7 0 R /ID [<{id}> <{id}>] >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .bytes(),
    );
    Ok(out)
}
