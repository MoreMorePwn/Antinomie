// SPDX-License-Identifier: GPL-3.0-only
//! A flattened device tree (DTB, version 17) read into nodes and written
//! back, for the arm64 board disguise (MA-17): QEMU's own tree of the `virt`
//! machine (`-machine dumpdtb=`) with its QEMU-only nodes taken out and the
//! board's names put in, booted with `-dtb`.

const MAGIC: u32 = 0xd00d_feed;
const BEGIN_NODE: u32 = 1;
const END_NODE: u32 = 2;
const PROP: u32 = 3;
const NOP: u32 = 4;
const END: u32 = 9;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Node {
    pub name: String,
    pub props: Vec<(String, Vec<u8>)>,
    pub children: Vec<Node>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fdt {
    pub root: Node,
    pub reserved: Vec<(u64, u64)>,
    pub boot_cpuid: u32,
}

fn be32(data: &[u8], at: usize) -> Result<u32, String> {
    data.get(at..at + 4)
        .map(|bytes| u32::from_be_bytes(bytes.try_into().unwrap()))
        .ok_or_else(|| format!("device tree cut short at {at}"))
}

fn align4(at: usize) -> usize {
    (at + 3) & !3
}

/// A NUL-terminated string at `at` and where it ends.
fn c_string(data: &[u8], at: usize) -> Result<(String, usize), String> {
    let rest = data.get(at..).ok_or("device tree cut short")?;
    let end = rest
        .iter()
        .position(|byte| *byte == 0)
        .ok_or("unterminated device tree string")?;
    Ok((
        String::from_utf8_lossy(&rest[..end]).into_owned(),
        at + end + 1,
    ))
}

impl Fdt {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if be32(data, 0)? != MAGIC {
            return Err("not a flattened device tree".into());
        }
        let (structs, strings) = (be32(data, 8)? as usize, be32(data, 12)? as usize);
        let (reserve, version) = (be32(data, 16)? as usize, be32(data, 20)?);
        if version < 17 {
            return Err(format!("device tree version {version}"));
        }
        let mut reserved = Vec::new();
        let mut at = reserve;
        loop {
            let address = (u64::from(be32(data, at)?) << 32) | u64::from(be32(data, at + 4)?);
            let size = (u64::from(be32(data, at + 8)?) << 32) | u64::from(be32(data, at + 12)?);
            at += 16;
            if address == 0 && size == 0 {
                break;
            }
            reserved.push((address, size));
        }
        let mut stack: Vec<Node> = Vec::new();
        let mut root = None;
        let mut at = structs;
        loop {
            let token = be32(data, at)?;
            at += 4;
            match token {
                BEGIN_NODE => {
                    let (name, end) = c_string(data, at)?;
                    at = align4(end);
                    stack.push(Node {
                        name,
                        ..Node::default()
                    });
                }
                END_NODE => {
                    let node = stack.pop().ok_or("unbalanced device tree")?;
                    match stack.last_mut() {
                        Some(parent) => parent.children.push(node),
                        None => root = Some(node),
                    }
                }
                PROP => {
                    let (len, name_at) = (be32(data, at)? as usize, be32(data, at + 4)? as usize);
                    let value = data
                        .get(at + 8..at + 8 + len)
                        .ok_or("device tree property cut short")?
                        .to_vec();
                    let (name, _) = c_string(data, strings + name_at)?;
                    at = align4(at + 8 + len);
                    stack
                        .last_mut()
                        .ok_or("property outside a node")?
                        .props
                        .push((name, value));
                }
                NOP => {}
                END => break,
                other => return Err(format!("device tree token {other}")),
            }
        }
        Ok(Self {
            root: root.ok_or("device tree without a root node")?,
            reserved,
            boot_cpuid: be32(data, 28)?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut structs = Vec::new();
        let mut strings: Vec<u8> = Vec::new();
        let mut offsets: Vec<(String, u32)> = Vec::new();
        fn put(
            node: &Node,
            out: &mut Vec<u8>,
            strings: &mut Vec<u8>,
            offsets: &mut Vec<(String, u32)>,
        ) {
            out.extend(BEGIN_NODE.to_be_bytes());
            out.extend(node.name.as_bytes());
            out.push(0);
            out.resize(align4(out.len()), 0);
            for (name, value) in &node.props {
                let offset = match offsets.iter().find(|(known, _)| known == name) {
                    Some((_, offset)) => *offset,
                    None => {
                        let offset = strings.len() as u32;
                        strings.extend(name.as_bytes());
                        strings.push(0);
                        offsets.push((name.clone(), offset));
                        offset
                    }
                };
                out.extend(PROP.to_be_bytes());
                out.extend((value.len() as u32).to_be_bytes());
                out.extend(offset.to_be_bytes());
                out.extend(value);
                out.resize(align4(out.len()), 0);
            }
            for child in &node.children {
                put(child, out, strings, offsets);
            }
            out.extend(END_NODE.to_be_bytes());
        }
        put(&self.root, &mut structs, &mut strings, &mut offsets);
        structs.extend(END.to_be_bytes());
        let reserve_at = 40usize;
        let structs_at = reserve_at + 16 * (self.reserved.len() + 1);
        let strings_at = structs_at + structs.len();
        let total = strings_at + strings.len();
        let mut out = Vec::with_capacity(total);
        for value in [
            MAGIC,
            total as u32,
            structs_at as u32,
            strings_at as u32,
            reserve_at as u32,
            17,
            16,
            self.boot_cpuid,
            strings.len() as u32,
            structs.len() as u32,
        ] {
            out.extend(value.to_be_bytes());
        }
        for (address, size) in self.reserved.iter().chain(std::iter::once(&(0, 0))) {
            out.extend(address.to_be_bytes());
            out.extend(size.to_be_bytes());
        }
        out.extend(structs);
        out.extend(strings);
        out
    }
}

impl Node {
    pub fn prop(&self, name: &str) -> Option<&[u8]> {
        self.props
            .iter()
            .find(|(known, _)| known == name)
            .map(|(_, value)| value.as_slice())
    }

    /// Sets `name` to `value`, in place or as a new last property.
    pub fn set(&mut self, name: &str, value: Vec<u8>) {
        match self.props.iter_mut().find(|(known, _)| known == name) {
            Some((_, old)) => *old = value,
            None => self.props.push((name.into(), value)),
        }
    }

    pub fn child_mut(&mut self, name: &str) -> Option<&mut Node> {
        self.children.iter_mut().find(|child| child.name == name)
    }
}

/// A string list property's value (each string NUL-terminated).
pub fn strings(values: &[&str]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.bytes().chain(std::iter::once(0)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tree_reads_back_as_written() {
        let tree = Fdt {
            root: Node {
                name: String::new(),
                props: vec![
                    ("compatible".into(), strings(&["linux,dummy-virt"])),
                    ("#address-cells".into(), 2u32.to_be_bytes().to_vec()),
                ],
                children: vec![
                    Node {
                        name: "chosen".into(),
                        props: vec![("bootargs".into(), strings(&["console=ttyAMA0"]))],
                        children: Vec::new(),
                    },
                    Node {
                        name: "fw-cfg@9020000".into(),
                        props: vec![("compatible".into(), strings(&["qemu,fw-cfg-mmio"]))],
                        children: Vec::new(),
                    },
                ],
            },
            reserved: vec![(0x4000_0000, 0x1000)],
            boot_cpuid: 0,
        };
        let bytes = tree.to_bytes();
        assert_eq!(&bytes[..4], &MAGIC.to_be_bytes());
        assert_eq!(be32(&bytes, 4).unwrap() as usize, bytes.len());
        let back = Fdt::parse(&bytes).unwrap();
        assert_eq!(back, tree);
        let mut edited = back;
        edited.root.set(
            "compatible",
            strings(&["raspberrypi,4-model-b", "brcm,bcm2711"]),
        );
        edited
            .root
            .children
            .retain(|child| !child.name.starts_with("fw-cfg"));
        let again = Fdt::parse(&edited.to_bytes()).unwrap();
        assert_eq!(
            again.root.prop("compatible").unwrap(),
            b"raspberrypi,4-model-b\0brcm,bcm2711\0"
        );
        assert_eq!(again.root.children.len(), 1);
        assert!(Fdt::parse(b"not a tree at all, not at all......................").is_err());
    }
}
