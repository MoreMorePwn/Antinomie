// SPDX-License-Identifier: GPL-3.0-only
//! TShark's packet details (PDML) for one frame, as a bounded tree.
//!
//! TShark prints every protocol and field with the line Wireshark shows for
//! it and the byte range it covers. This reads that XML with a small strict
//! reader (the output is untrusted: its size, depth and node count are
//! capped, and a byte range that does not fit the frame is dropped rather
//! than trusted). It decodes nothing itself.
use std::collections::HashMap;

/// Nodes kept for one frame.
pub const MAX_NODES: usize = 20_000;
/// Nesting kept; deeper nodes are counted as cut.
pub const MAX_DEPTH: usize = 24;
/// Characters kept of a node's line.
const MAX_LABEL_LEN: usize = 1024;
/// Characters kept of a field's name and shown value.
const MAX_NAME_LEN: usize = 128;
/// Bytes of XML read for one frame.
pub const MAX_PDML_SIZE: usize = 16 * 1024 * 1024;

/// One line of the packet details tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetailNode {
    /// Nesting: 0 for a protocol, 1 and more for the fields inside it.
    pub depth: u8,
    /// The line, as Wireshark's details pane shows it.
    pub label: String,
    /// TShark's field or protocol name (`ip.src`, `tls`), for state keyed by
    /// type of node.
    pub name: String,
    /// Bytes of the frame this node covers, when TShark's range fits the
    /// frame; `len` 0 means none.
    pub start: usize,
    pub len: usize,
    /// Index one past this node's last descendant: collapsing it skips there.
    pub end: usize,
}

impl DetailNode {
    pub fn has_children(&self, index: usize) -> bool {
        self.end > index + 1
    }
    /// The frame bytes this node covers.
    pub fn range(&self) -> Option<std::ops::Range<usize>> {
        (self.len > 0).then(|| self.start..self.start + self.len)
    }
}

/// The parsed details of one frame.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PacketTree {
    pub nodes: Vec<DetailNode>,
    /// Nodes or levels left out by the limits.
    pub cut: bool,
}

enum Token<'a> {
    Start {
        name: &'a str,
        attributes: Vec<(&'a str, String)>,
        empty: bool,
    },
    End,
}

struct Reader<'a> {
    text: &'a str,
    at: usize,
}

impl<'a> Reader<'a> {
    fn next(&mut self) -> Result<Option<Token<'a>>, String> {
        loop {
            let rest = &self.text[self.at..];
            let Some(open) = rest.find('<') else {
                return Ok(None);
            };
            self.at += open;
            let rest = &self.text[self.at..];
            if rest.starts_with("<?") {
                self.skip_to("?>")?;
            } else if rest.starts_with("<!--") {
                self.skip_to("-->")?;
            } else if rest.starts_with("<!") {
                self.skip_to(">")?;
            } else if rest.starts_with("</") {
                self.skip_to(">")?;
                return Ok(Some(Token::End));
            } else {
                return self.tag().map(Some);
            }
        }
    }

    fn skip_to(&mut self, end: &str) -> Result<(), String> {
        let found = self.text[self.at..]
            .find(end)
            .ok_or("TShark printed an unterminated XML construct")?;
        self.at += found + end.len();
        Ok(())
    }

    fn tag(&mut self) -> Result<Token<'a>, String> {
        let bytes = self.text.as_bytes();
        let mut at = self.at + 1;
        let name_start = at;
        while at < bytes.len()
            && !bytes[at].is_ascii_whitespace()
            && !matches!(bytes[at], b'>' | b'/')
        {
            at += 1;
        }
        let name = &self.text[name_start..at];
        let mut attributes = Vec::new();
        loop {
            while at < bytes.len() && bytes[at].is_ascii_whitespace() {
                at += 1;
            }
            match bytes.get(at) {
                None => return Err("TShark printed an unterminated XML tag".into()),
                Some(b'>') => {
                    self.at = at + 1;
                    return Ok(Token::Start {
                        name,
                        attributes,
                        empty: false,
                    });
                }
                Some(b'/') => {
                    if bytes.get(at + 1) != Some(&b'>') {
                        return Err("TShark printed a malformed XML tag".into());
                    }
                    self.at = at + 2;
                    return Ok(Token::Start {
                        name,
                        attributes,
                        empty: true,
                    });
                }
                Some(_) => {}
            }
            let key_start = at;
            while at < bytes.len() && !matches!(bytes[at], b'=' | b'>' | b'/') {
                if bytes[at].is_ascii_whitespace() {
                    break;
                }
                at += 1;
            }
            let key = &self.text[key_start..at];
            while at < bytes.len() && bytes[at].is_ascii_whitespace() {
                at += 1;
            }
            if bytes.get(at) != Some(&b'=') {
                return Err("TShark printed an XML attribute without a value".into());
            }
            at += 1;
            while at < bytes.len() && bytes[at].is_ascii_whitespace() {
                at += 1;
            }
            let quote = match bytes.get(at) {
                Some(&quote @ (b'"' | b'\'')) => quote,
                _ => return Err("TShark printed an unquoted XML attribute".into()),
            };
            at += 1;
            let value_start = at;
            let close = bytes[at..]
                .iter()
                .position(|&byte| byte == quote)
                .ok_or("TShark printed an unterminated XML attribute")?;
            at += close;
            let raw = &self.text[value_start..at];
            at += 1;
            if matches!(key, "name" | "showname" | "show" | "pos" | "size" | "hide") {
                attributes.push((key, unescape(raw)));
            }
        }
    }
}

fn unescape(text: &str) -> String {
    if !text.contains('&') {
        return text.to_owned();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        rest = &rest[at..];
        let Some(end) = rest.find(';').filter(|end| *end <= 10) else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let entity = &rest[1..end];
        let decoded = match entity {
            "lt" => Some('<'),
            "gt" => Some('>'),
            "amp" => Some('&'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix("#x")
                .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                .or_else(|| entity.strip_prefix('#').and_then(|n| n.parse().ok()))
                .and_then(char::from_u32),
        };
        match decoded {
            Some(ch) => out.push(ch),
            None => out.push_str(&rest[..=end]),
        }
        rest = &rest[end + 1..];
    }
    out.push_str(rest);
    out
}

fn limited(text: &str, limit: usize) -> String {
    text.chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .take(limit)
        .collect()
}

/// The details tree of the one packet in `xml`. `frame_len` is the number of
/// bytes of the frame the tree's byte ranges must fit in.
pub fn parse(xml: &[u8], frame_len: usize) -> Result<PacketTree, String> {
    let text = std::str::from_utf8(xml).map_err(|_| "TShark packet details are not UTF-8")?;
    let mut reader = Reader { text, at: 0 };
    let mut tree = PacketTree::default();
    // The open elements: whether each one was kept as a node, and its depth.
    let mut open: Vec<Option<usize>> = Vec::new();
    let mut hidden_depth = 0usize;
    let mut seen_packet = false;
    while let Some(token) = reader.next()? {
        match token {
            Token::End => {
                let Some(kept) = open.pop() else {
                    continue;
                };
                if hidden_depth > 0 {
                    hidden_depth -= 1;
                } else if let Some(index) = kept {
                    tree.nodes[index].end = tree.nodes.len();
                }
            }
            Token::Start {
                name,
                attributes,
                empty,
            } => {
                let attribute: HashMap<&str, &str> = attributes
                    .iter()
                    .map(|(key, value)| (*key, value.as_str()))
                    .collect();
                let is_node = matches!(name, "proto" | "field");
                if name == "packet" {
                    if seen_packet {
                        break;
                    }
                    seen_packet = true;
                }
                let mut kept = None;
                if is_node {
                    let hide = attribute.get("hide") == Some(&"yes");
                    let wrapper = attribute.get("name") == Some(&"fake-field-wrapper");
                    let general = name == "proto" && attribute.get("name") == Some(&"geninfo");
                    if hidden_depth > 0 || hide || general {
                        hidden_depth += 1;
                    } else if !wrapper {
                        let depth = open.iter().flatten().count();
                        if depth >= MAX_DEPTH || tree.nodes.len() >= MAX_NODES {
                            tree.cut = true;
                            hidden_depth += 1;
                        } else {
                            let label = ["showname", "show", "name"]
                                .iter()
                                .filter_map(|key| attribute.get(key))
                                .find(|text| !text.is_empty())
                                .copied()
                                .unwrap_or("");
                            let number = |key: &str| {
                                attribute
                                    .get(key)
                                    .and_then(|text| text.parse::<usize>().ok())
                            };
                            let (start, len) = match (number("pos"), number("size")) {
                                (Some(pos), Some(size))
                                    if size > 0
                                        && pos
                                            .checked_add(size)
                                            .is_some_and(|end| end <= frame_len) =>
                                {
                                    (pos, size)
                                }
                                _ => (0, 0),
                            };
                            tree.nodes.push(DetailNode {
                                depth: depth as u8,
                                label: limited(label, MAX_LABEL_LEN),
                                name: limited(
                                    attribute.get("name").copied().unwrap_or(""),
                                    MAX_NAME_LEN,
                                ),
                                start,
                                len,
                                end: 0,
                            });
                            kept = Some(tree.nodes.len() - 1);
                        }
                    }
                }
                if empty {
                    if is_node {
                        if hidden_depth > 0 && kept.is_none() {
                            hidden_depth -= 1;
                        } else if let Some(index) = kept {
                            tree.nodes[index].end = tree.nodes.len();
                        }
                    }
                } else {
                    // Other elements only nest; a fake-field-wrapper's
                    // children stay siblings of its own.
                    open.push(kept);
                }
            }
        }
    }
    // A reply cut short still nests what it opened.
    for &index in open.iter().flatten() {
        tree.nodes[index].end = tree.nodes.len();
    }
    if tree.nodes.is_empty() {
        return Err("TShark printed no packet details for this frame".into());
    }
    Ok(tree)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<pdml version="0"><packet>
  <proto name="geninfo" pos="0" showname="General information" size="20"><field name="num" show="1"/></proto>
  <proto name="frame" showname="Frame 1: 20 bytes" size="20" pos="0">
    <field name="frame.len" showname="Frame Length: 20" size="0" pos="0" show="20"/>
  </proto>
  <proto name="ip" showname="Internet Protocol &amp; more" size="4" pos="14">
    <field name="ip.src" showname="Source Address: 10.0.0.1" size="4" pos="16" show="10.0.0.1" value="0a000001"/>
    <field name="ip.addr" showname="hidden" hide="yes" size="4" pos="16" show="10.0.0.1"><field name="x" showname="child of hidden" pos="0" size="1"/></field>
    <field name="ip.bad" showname="Outside the frame" size="8" pos="18" show="1"/>
    <field name="ip.flags" showname="Flags: 0x0" size="1" pos="20" show="0x00">
      <field name="ip.flags.df" showname="Don&#x27;t fragment" size="1" pos="20" show="0"/>
    </field>
  </proto>
</packet></pdml>"#;

    #[test]
    fn reads_labels_ranges_and_nesting_and_drops_hidden_and_misfit_ranges() {
        let tree = parse(SAMPLE.as_bytes(), 22).unwrap();
        let lines: Vec<_> = tree
            .nodes
            .iter()
            .map(|n| (n.depth, n.label.as_str(), n.range()))
            .collect();
        assert_eq!(
            lines,
            [
                (0, "Frame 1: 20 bytes", Some(0..20)),
                (1, "Frame Length: 20", None),
                (0, "Internet Protocol & more", Some(14..18)),
                (1, "Source Address: 10.0.0.1", Some(16..20)),
                (1, "Outside the frame", None),
                (1, "Flags: 0x0", Some(20..21)),
                (2, "Don't fragment", Some(20..21)),
            ]
        );
        assert_eq!(tree.nodes[0].end, 2);
        assert_eq!(tree.nodes[2].end, 7);
        assert!(tree.nodes[5].has_children(5));
        assert!(!tree.cut);
    }

    #[test]
    fn a_frame_shorter_than_the_range_drops_it() {
        let tree = parse(SAMPLE.as_bytes(), 19).unwrap();
        assert_eq!(tree.nodes[3].range(), None);
        assert_eq!(tree.nodes[0].range(), None);
    }

    #[test]
    fn depth_and_node_limits_are_counted_not_trusted() {
        let mut xml = String::from("<pdml><packet>");
        for _ in 0..40 {
            xml.push_str(r#"<proto name="p" showname="p" pos="0" size="1">"#);
        }
        for _ in 0..40 {
            xml.push_str("</proto>");
        }
        xml.push_str("</packet></pdml>");
        let tree = parse(xml.as_bytes(), 10).unwrap();
        assert_eq!(tree.nodes.len(), MAX_DEPTH);
        assert!(tree.cut);
        let mut wide = String::from("<pdml><packet><proto name=\"p\" showname=\"p\">");
        for _ in 0..MAX_NODES + 10 {
            wide.push_str(r#"<field name="f" showname="f"/>"#);
        }
        wide.push_str("</proto></packet></pdml>");
        let tree = parse(wide.as_bytes(), 10).unwrap();
        assert_eq!(tree.nodes.len(), MAX_NODES);
        assert!(tree.cut);
    }

    #[test]
    fn malformed_xml_is_an_error_not_a_panic() {
        for bad in [
            "<pdml><packet><proto name=\"a",
            "<pdml><packet><proto name=a>",
            "<pdml><packet><proto name",
            "<pdml><packet><proto/",
            "<?xml",
            "",
            "<pdml></pdml>",
        ] {
            assert!(parse(bad.as_bytes(), 10).is_err(), "{bad}");
        }
        assert!(parse(&[0xff, 0xfe], 10).is_err());
    }

    #[test]
    fn control_characters_in_labels_are_blanked() {
        let xml =
            "<pdml><packet><proto name=\"p\" showname=\"a\u{1b}[31mb\u{7}\"/></packet></pdml>";
        let tree = parse(xml.as_bytes(), 1).unwrap();
        assert_eq!(tree.nodes[0].label, "a [31mb ");
    }
}
