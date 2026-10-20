//! The token sets. One `Palette` per theme, mirroring the mockup's
//! `css/tokens.css` variable for variable (dark and light are its values;
//! blue is the dark theme on navy surfaces). Nothing else in the app holds
//! a literal color: widgets read the active palette through `theme::*`.

use eframe::egui::Color32;

/// One palette. Backgrounds go from `bg` (deepest: tables, text fields,
/// lists) through `panel` to `raised` (windows, buttons) and `hover`;
/// `heading` names sections.
#[derive(Clone, Copy, Debug)]
pub struct Palette {
    pub bg: Color32,
    pub panel: Color32,
    pub raised: Color32,
    pub hover: Color32,
    pub line: Color32,
    /// Hairlines inside a surface: table rules, tab strips, window footers.
    pub line_soft: Color32,
    pub text: Color32,
    pub muted: Color32,
    /// Placeholder text in empty inputs: grayer than `muted`, still legible.
    pub hint: Color32,
    /// Links, focus ring, selected-tab underline.
    pub accent: Color32,
    /// Section titles only.
    pub heading: Color32,
    /// The one filled primary button of a surface.
    pub primary: Color32,
    pub primary_text: Color32,
    /// Bright call to action (Open in Wireshark, Install).
    pub cta: Color32,
    pub selection: Color32,
    /// A faint accent wash: active toggles, hovered chips.
    pub selection_soft: Color32,
    /// Zebra stripe of tables and grids (translucent, over `bg`).
    pub stripe: Color32,
    pub good: Color32,
    pub warn: Color32,
    pub error: Color32,
    pub info: Color32,
    /// Recording / live indicator.
    pub live: Color32,
    /// Translucent tints of the semantic colors, for chips and banners.
    pub good_bg: Color32,
    pub warn_bg: Color32,
    pub error_bg: Color32,
    pub info_bg: Color32,
    pub neutral_bg: Color32,
    pub terminal: Color32,
    pub terminal_text: Color32,
    /// Syntax colors for values.
    pub number: Color32,
    pub string: Color32,
    pub pointer: Color32,
    pub flag: Color32,
    pub name: Color32,
    /// Branch colors of tree views, one per level, cycling.
    pub tree: [Color32; TREE_COLOR_COUNT],
    /// Row tints of the syscall groups, in `SYSCALL_TINT_ORDER`.
    pub syscall: [Color32; 10],
    /// Row tints of the packet list, in `PacketColor::ALL` order.
    pub packet: [Color32; 10],
    /// Window drop shadow.
    pub shadow: Color32,
}

/// How many distinct branch colors a tree cycles through.
pub const TREE_COLOR_COUNT: usize = 6;

const fn rgb(r: u8, g: u8, b: u8) -> Color32 {
    Color32::from_rgb(r, g, b)
}

const fn scale(channel: u8, alpha: u8) -> u8 {
    ((channel as u16 * alpha as u16) / 255) as u8
}

/// A translucent color (`alpha` of 255), premultiplied as egui wants it.
const fn alpha(r: u8, g: u8, b: u8, alpha: u8) -> Color32 {
    Color32::from_rgba_premultiplied(scale(r, alpha), scale(g, alpha), scale(b, alpha), alpha)
}

/// The neutral grey dark theme (the mockup's default).
pub const DARK: Palette = Palette {
    bg: rgb(22, 24, 29),
    panel: rgb(30, 33, 40),
    raised: rgb(39, 43, 52),
    hover: rgb(50, 56, 68),
    line: rgb(58, 64, 78),
    line_soft: rgb(46, 51, 62),
    text: rgb(222, 226, 234),
    muted: rgb(146, 156, 174),
    hint: rgb(110, 117, 131),
    accent: rgb(110, 176, 255),
    heading: rgb(130, 196, 255),
    primary: rgb(46, 110, 196),
    primary_text: rgb(242, 246, 252),
    cta: rgb(30, 130, 255),
    selection: rgb(38, 79, 135),
    selection_soft: alpha(110, 176, 255, 36),
    stripe: alpha(127, 140, 160, 15),
    good: rgb(110, 214, 150),
    warn: rgb(246, 192, 92),
    error: rgb(255, 120, 120),
    info: rgb(98, 214, 226),
    live: rgb(255, 107, 107),
    good_bg: alpha(110, 214, 150, 36),
    warn_bg: alpha(246, 192, 92, 36),
    error_bg: alpha(255, 120, 120, 36),
    info_bg: alpha(98, 214, 226, 36),
    neutral_bg: alpha(146, 156, 174, 36),
    terminal: rgb(16, 18, 22),
    terminal_text: rgb(216, 221, 230),
    number: rgb(120, 214, 236),
    string: rgb(242, 176, 112),
    pointer: rgb(196, 160, 255),
    flag: rgb(120, 172, 255),
    name: rgb(255, 214, 128),
    tree: [
        rgb(110, 176, 255),
        rgb(246, 168, 84),
        rgb(110, 214, 150),
        rgb(244, 134, 190),
        rgb(98, 214, 226),
        rgb(200, 140, 255),
    ],
    syscall: [
        rgb(70, 50, 96),
        rgb(38, 58, 92),
        rgb(36, 78, 52),
        rgb(30, 74, 68),
        rgb(84, 76, 32),
        rgb(98, 62, 30),
        rgb(28, 76, 98),
        rgb(110, 40, 46),
        rgb(78, 28, 38),
        rgb(58, 58, 64),
    ],
    packet: DARK_PACKET,
    shadow: alpha(0, 0, 0, 115),
};

/// Packet row tints of the dark themes (Wireshark's default rules, darkened):
/// reset, syn/fin, http, tls, dns, dhcp, arp, icmp, tcp, udp.
const DARK_PACKET: [Color32; 10] = [
    rgb(112, 34, 40),
    rgb(66, 66, 72),
    rgb(36, 80, 50),
    rgb(74, 48, 100),
    rgb(22, 74, 80),
    rgb(80, 74, 26),
    rgb(100, 64, 26),
    rgb(98, 38, 78),
    rgb(46, 52, 96),
    rgb(24, 60, 102),
];

pub const LIGHT: Palette = Palette {
    bg: rgb(255, 255, 255),
    panel: rgb(244, 246, 250),
    raised: rgb(233, 237, 244),
    hover: rgb(220, 228, 240),
    line: rgb(200, 207, 220),
    line_soft: rgb(221, 227, 237),
    text: rgb(28, 32, 40),
    muted: rgb(96, 106, 124),
    hint: rgb(140, 147, 160),
    accent: rgb(20, 104, 204),
    heading: rgb(18, 88, 176),
    primary: rgb(28, 108, 208),
    primary_text: rgb(255, 255, 255),
    cta: rgb(10, 100, 230),
    selection: rgb(190, 216, 250),
    selection_soft: alpha(20, 104, 204, 31),
    stripe: alpha(127, 140, 160, 15),
    good: rgb(20, 132, 66),
    warn: rgb(170, 104, 0),
    error: rgb(196, 36, 44),
    info: rgb(0, 126, 146),
    live: rgb(214, 48, 58),
    good_bg: alpha(20, 132, 66, 31),
    warn_bg: alpha(170, 104, 0, 31),
    error_bg: alpha(196, 36, 44, 31),
    info_bg: alpha(0, 126, 146, 31),
    neutral_bg: alpha(96, 106, 124, 31),
    terminal: rgb(250, 250, 252),
    terminal_text: rgb(28, 32, 40),
    number: rgb(0, 116, 150),
    string: rgb(166, 82, 0),
    pointer: rgb(112, 64, 196),
    flag: rgb(28, 92, 196),
    name: rgb(140, 92, 0),
    tree: [
        rgb(28, 92, 196),
        rgb(190, 86, 0),
        rgb(20, 132, 66),
        rgb(190, 40, 130),
        rgb(0, 122, 142),
        rgb(130, 60, 200),
    ],
    syscall: [
        rgb(236, 227, 246),
        rgb(225, 233, 246),
        rgb(223, 241, 228),
        rgb(221, 240, 236),
        rgb(243, 239, 216),
        rgb(246, 232, 218),
        rgb(220, 236, 244),
        rgb(248, 223, 224),
        rgb(243, 221, 225),
        rgb(235, 235, 238),
    ],
    packet: [
        rgb(248, 223, 224),
        rgb(235, 235, 238),
        rgb(223, 241, 228),
        rgb(236, 227, 246),
        rgb(220, 240, 242),
        rgb(243, 239, 216),
        rgb(246, 232, 218),
        rgb(243, 223, 236),
        rgb(227, 229, 246),
        rgb(221, 232, 246),
    ],
    shadow: alpha(20, 30, 50, 46),
};

/// The dark theme on deep navy surfaces: the neutral greys are replaced by
/// blues; every role color, value color and tint is the dark theme's.
pub const BLUE: Palette = Palette {
    bg: rgb(11, 20, 38),
    panel: rgb(16, 28, 51),
    raised: rgb(23, 38, 67),
    hover: rgb(33, 53, 92),
    line: rgb(46, 68, 110),
    line_soft: rgb(32, 51, 86),
    text: rgb(224, 233, 248),
    muted: rgb(146, 165, 198),
    hint: rgb(108, 128, 164),
    accent: rgb(116, 182, 255),
    heading: rgb(136, 200, 255),
    primary: rgb(44, 112, 206),
    primary_text: rgb(244, 248, 255),
    cta: rgb(34, 136, 255),
    selection: rgb(34, 76, 140),
    selection_soft: alpha(116, 182, 255, 38),
    stripe: alpha(120, 150, 210, 15),
    neutral_bg: alpha(146, 165, 198, 36),
    terminal: rgb(7, 14, 28),
    terminal_text: rgb(214, 225, 244),
    shadow: alpha(0, 4, 16, 140),
    ..DARK
};

/// Which theme is active; stored in Settings and chosen in Settings.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    #[default]
    Dark,
    Light,
    Blue,
}

impl Theme {
    pub const ALL: [Theme; 3] = [Theme::Dark, Theme::Light, Theme::Blue];

    pub fn label(self) -> &'static str {
        match self {
            Theme::Dark => "Dark",
            Theme::Light => "Light",
            Theme::Blue => "Blue",
        }
    }

    pub fn palette(self) -> &'static Palette {
        match self {
            Theme::Dark => &DARK,
            Theme::Light => &LIGHT,
            Theme::Blue => &BLUE,
        }
    }

    /// Whether egui should start from its light visuals.
    pub fn is_light(self) -> bool {
        self == Theme::Light
    }

    pub(super) fn index(self) -> u8 {
        self as u8
    }

    pub(super) fn from_index(index: u8) -> Theme {
        Theme::ALL.get(index as usize).copied().unwrap_or_default()
    }
}
