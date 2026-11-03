// SPDX-License-Identifier: GPL-3.0-only
//! egui keys to what the VM screen sends: the PC (scancode set 1) key number,
//! with 0x80 added for the extended (E0) keys, and the US-layout X11 keysym.
//! The guest's own layout gives the keys their meaning; the scancode is the
//! key's place on the keyboard.
use eframe::egui::Key;

pub(super) const SHIFT: (u32, u32) = (0x2a, 0xffe1);
pub(super) const CTRL: (u32, u32) = (0x1d, 0xffe3);
pub(super) const ALT: (u32, u32) = (0x38, 0xffe9);

/// Key, scancode, keysym.
const KEYS: &[(Key, u32, u32)] = &[
    (Key::Escape, 0x01, 0xff1b),
    (Key::Num1, 0x02, '1' as u32),
    (Key::Num2, 0x03, '2' as u32),
    (Key::Num3, 0x04, '3' as u32),
    (Key::Num4, 0x05, '4' as u32),
    (Key::Num5, 0x06, '5' as u32),
    (Key::Num6, 0x07, '6' as u32),
    (Key::Num7, 0x08, '7' as u32),
    (Key::Num8, 0x09, '8' as u32),
    (Key::Num9, 0x0a, '9' as u32),
    (Key::Num0, 0x0b, '0' as u32),
    (Key::Minus, 0x0c, '-' as u32),
    (Key::Equals, 0x0d, '=' as u32),
    (Key::Backspace, 0x0e, 0xff08),
    (Key::Tab, 0x0f, 0xff09),
    (Key::Q, 0x10, 'q' as u32),
    (Key::W, 0x11, 'w' as u32),
    (Key::E, 0x12, 'e' as u32),
    (Key::R, 0x13, 'r' as u32),
    (Key::T, 0x14, 't' as u32),
    (Key::Y, 0x15, 'y' as u32),
    (Key::U, 0x16, 'u' as u32),
    (Key::I, 0x17, 'i' as u32),
    (Key::O, 0x18, 'o' as u32),
    (Key::P, 0x19, 'p' as u32),
    (Key::OpenBracket, 0x1a, '[' as u32),
    (Key::CloseBracket, 0x1b, ']' as u32),
    (Key::Enter, 0x1c, 0xff0d),
    (Key::A, 0x1e, 'a' as u32),
    (Key::S, 0x1f, 's' as u32),
    (Key::D, 0x20, 'd' as u32),
    (Key::F, 0x21, 'f' as u32),
    (Key::G, 0x22, 'g' as u32),
    (Key::H, 0x23, 'h' as u32),
    (Key::J, 0x24, 'j' as u32),
    (Key::K, 0x25, 'k' as u32),
    (Key::L, 0x26, 'l' as u32),
    (Key::Semicolon, 0x27, ';' as u32),
    (Key::Quote, 0x28, '\'' as u32),
    (Key::Backtick, 0x29, '`' as u32),
    (Key::Backslash, 0x2b, '\\' as u32),
    (Key::Z, 0x2c, 'z' as u32),
    (Key::X, 0x2d, 'x' as u32),
    (Key::C, 0x2e, 'c' as u32),
    (Key::V, 0x2f, 'v' as u32),
    (Key::B, 0x30, 'b' as u32),
    (Key::N, 0x31, 'n' as u32),
    (Key::M, 0x32, 'm' as u32),
    (Key::Comma, 0x33, ',' as u32),
    (Key::Period, 0x34, '.' as u32),
    (Key::Slash, 0x35, '/' as u32),
    (Key::Space, 0x39, ' ' as u32),
    (Key::F1, 0x3b, 0xffbe),
    (Key::F2, 0x3c, 0xffbf),
    (Key::F3, 0x3d, 0xffc0),
    (Key::F4, 0x3e, 0xffc1),
    (Key::F5, 0x3f, 0xffc2),
    (Key::F6, 0x40, 0xffc3),
    (Key::F7, 0x41, 0xffc4),
    (Key::F8, 0x42, 0xffc5),
    (Key::F9, 0x43, 0xffc6),
    (Key::F10, 0x44, 0xffc7),
    (Key::F11, 0x57, 0xffc8),
    (Key::F12, 0x58, 0xffc9),
    (Key::Home, 0xc7, 0xff50),
    (Key::ArrowUp, 0xc8, 0xff52),
    (Key::PageUp, 0xc9, 0xff55),
    (Key::ArrowLeft, 0xcb, 0xff51),
    (Key::ArrowRight, 0xcd, 0xff53),
    (Key::End, 0xcf, 0xff57),
    (Key::ArrowDown, 0xd0, 0xff54),
    (Key::PageDown, 0xd1, 0xff56),
    (Key::Insert, 0xd2, 0xff63),
    (Key::Delete, 0xd3, 0xffff),
];

/// The scancode and keysym of an egui key; keys that are a shifted form of
/// another (a colon, a plus) give that key, and the Shift state does the rest.
pub(super) fn of(key: Key) -> Option<(u32, u32)> {
    let key = match key {
        Key::Colon => Key::Semicolon,
        Key::Plus => Key::Equals,
        Key::Questionmark => Key::Slash,
        Key::Exclamationmark => Key::Num1,
        Key::Pipe => Key::Backslash,
        Key::OpenCurlyBracket => Key::OpenBracket,
        Key::CloseCurlyBracket => Key::CloseBracket,
        other => other,
    };
    KEYS.iter()
        .find(|(candidate, ..)| *candidate == key)
        .map(|(_, scancode, keysym)| (*scancode, *keysym))
}
