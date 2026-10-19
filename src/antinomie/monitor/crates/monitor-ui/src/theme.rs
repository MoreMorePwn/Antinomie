//! Colors, fonts and spacing. Two palettes (dark, light) chosen at runtime;
//! widgets read the active one through the functions below. Data (numbers,
//! addresses, strings, flags, errors) gets syntax colors so dense views stay
//! readable, and tables size their rows from the density setting.
// The value colors, headings and density are adopted view by view.
use eframe::egui::{self, Color32, FontData, FontFamily, FontId, Stroke, TextStyle};
use std::sync::atomic::{AtomicBool, Ordering};

/// One palette. Backgrounds go from `bg` (deepest: text fields, lists) to
/// `raised` (windows, buttons); `heading` names sections.
#[derive(Clone, Copy, Debug)]
pub struct Palette {
    pub bg: Color32,
    pub panel: Color32,
    pub raised: Color32,
    pub hover: Color32,
    pub line: Color32,
    pub text: Color32,
    pub muted: Color32,
    /// Placeholder text in empty inputs: grayer than `muted`, still legible.
    pub hint: Color32,
    pub accent: Color32,
    pub heading: Color32,
    pub primary: Color32,
    pub primary_text: Color32,
    pub selection: Color32,
    pub good: Color32,
    pub warn: Color32,
    pub error: Color32,
    pub info: Color32,
    pub terminal: Color32,
    /// Syntax colors for values.
    pub number: Color32,
    pub string: Color32,
    pub pointer: Color32,
    pub flag: Color32,
    pub name: Color32,
    /// Branch colors of tree views, one per level, cycling.
    pub tree: [Color32; TREE_COLOR_COUNT],
}

/// How many distinct branch colors a tree cycles through.
pub const TREE_COLOR_COUNT: usize = 6;

pub const DARK: Palette = Palette {
    bg: Color32::from_rgb(22, 24, 29),
    panel: Color32::from_rgb(30, 33, 40),
    raised: Color32::from_rgb(39, 43, 52),
    hover: Color32::from_rgb(50, 56, 68),
    line: Color32::from_rgb(58, 64, 78),
    text: Color32::from_rgb(222, 226, 234),
    muted: Color32::from_rgb(146, 156, 174),
    hint: Color32::from_rgb(110, 117, 131),
    accent: Color32::from_rgb(110, 176, 255),
    heading: Color32::from_rgb(130, 196, 255),
    primary: Color32::from_rgb(46, 110, 196),
    primary_text: Color32::from_rgb(242, 246, 252),
    selection: Color32::from_rgb(38, 79, 135),
    good: Color32::from_rgb(110, 214, 150),
    warn: Color32::from_rgb(246, 192, 92),
    error: Color32::from_rgb(255, 120, 120),
    info: Color32::from_rgb(98, 214, 226),
    terminal: Color32::from_rgb(16, 18, 22),
    number: Color32::from_rgb(120, 214, 236),
    string: Color32::from_rgb(242, 176, 112),
    pointer: Color32::from_rgb(196, 160, 255),
    flag: Color32::from_rgb(120, 172, 255),
    name: Color32::from_rgb(255, 214, 128),
    tree: [
        Color32::from_rgb(110, 176, 255),
        Color32::from_rgb(246, 168, 84),
        Color32::from_rgb(110, 214, 150),
        Color32::from_rgb(244, 134, 190),
        Color32::from_rgb(98, 214, 226),
        Color32::from_rgb(200, 140, 255),
    ],
};

pub const LIGHT: Palette = Palette {
    bg: Color32::from_rgb(255, 255, 255),
    panel: Color32::from_rgb(244, 246, 250),
    raised: Color32::from_rgb(233, 237, 244),
    hover: Color32::from_rgb(220, 228, 240),
    line: Color32::from_rgb(200, 207, 220),
    text: Color32::from_rgb(28, 32, 40),
    muted: Color32::from_rgb(96, 106, 124),
    hint: Color32::from_rgb(140, 147, 160),
    accent: Color32::from_rgb(20, 104, 204),
    heading: Color32::from_rgb(18, 88, 176),
    primary: Color32::from_rgb(28, 108, 208),
    primary_text: Color32::from_rgb(255, 255, 255),
    selection: Color32::from_rgb(190, 216, 250),
    good: Color32::from_rgb(20, 132, 66),
    warn: Color32::from_rgb(170, 104, 0),
    error: Color32::from_rgb(196, 36, 44),
    info: Color32::from_rgb(0, 126, 146),
    terminal: Color32::from_rgb(250, 250, 252),
    number: Color32::from_rgb(0, 116, 150),
    string: Color32::from_rgb(166, 82, 0),
    pointer: Color32::from_rgb(112, 64, 196),
    flag: Color32::from_rgb(28, 92, 196),
    name: Color32::from_rgb(140, 92, 0),
    tree: [
        Color32::from_rgb(28, 92, 196),
        Color32::from_rgb(190, 86, 0),
        Color32::from_rgb(20, 132, 66),
        Color32::from_rgb(190, 40, 130),
        Color32::from_rgb(0, 122, 142),
        Color32::from_rgb(130, 60, 200),
    ],
};

static LIGHT_THEME: AtomicBool = AtomicBool::new(false);
static COMPACT: AtomicBool = AtomicBool::new(true);

/// The active palette.
pub fn palette() -> &'static Palette {
    if LIGHT_THEME.load(Ordering::Relaxed) {
        &LIGHT
    } else {
        &DARK
    }
}
pub fn is_light() -> bool {
    LIGHT_THEME.load(Ordering::Relaxed)
}

pub fn bg() -> Color32 {
    palette().bg
}
pub fn panel() -> Color32 {
    palette().panel
}
pub fn raised() -> Color32 {
    palette().raised
}
pub fn line() -> Color32 {
    palette().line
}
pub fn text() -> Color32 {
    palette().text
}
pub fn muted() -> Color32 {
    palette().muted
}
/// `text` styled as the placeholder of an empty input.
pub fn hint_text(text: impl Into<String>) -> egui::RichText {
    egui::RichText::new(text).color(hint())
}
/// Placeholder (hint) text color of an empty input.
pub fn hint() -> Color32 {
    palette().hint
}
/// Links, focus and accents.
pub fn blue() -> Color32 {
    palette().accent
}
pub fn heading() -> Color32 {
    palette().heading
}
pub fn primary() -> Color32 {
    palette().primary
}
pub fn good() -> Color32 {
    palette().good
}
pub fn warn() -> Color32 {
    palette().warn
}
pub fn error() -> Color32 {
    palette().error
}
pub fn info() -> Color32 {
    palette().info
}
pub fn terminal() -> Color32 {
    palette().terminal
}

/// The branch color of tree level `level` (0 is the first level below the
/// roots); levels past the palette start over.
pub fn tree_branch(level: usize) -> Color32 {
    palette().tree[level % TREE_COLOR_COUNT]
}

/// What a value is, for its syntax color.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueKind {
    Number,
    Text,
    Pointer,
    Flags,
    /// Syscall and symbol names.
    Name,
    Error,
    Plain,
}
pub fn value(kind: ValueKind) -> Color32 {
    let palette = palette();
    match kind {
        ValueKind::Number => palette.number,
        ValueKind::Text => palette.string,
        ValueKind::Pointer => palette.pointer,
        ValueKind::Flags => palette.flag,
        ValueKind::Name => palette.name,
        ValueKind::Error => palette.error,
        ValueKind::Plain => palette.text,
    }
}

/// Density (Settings): compact by default. Comfortable gives taller table
/// rows and roomier spacing, padding and margins everywhere.
pub fn set_compact(ctx: &egui::Context, compact: bool) {
    COMPACT.store(compact, Ordering::Relaxed);
    ctx.style_mut(density);
}

/// Spacing of the current density.
fn density(style: &mut egui::Style) {
    let roomy = !is_compact();
    let body = style
        .text_styles
        .get(&TextStyle::Body)
        .map_or(16.0, |font| font.size);
    if roomy {
        style.spacing.item_spacing = egui::vec2(10.0, 9.0);
        style.spacing.button_padding = egui::vec2(12.0, 7.0);
        style.spacing.menu_margin = egui::Margin::same(10);
        // Also the margin of every tab's content (egui_dock follows it).
        // With taller widgets or a wider margin, egui's window title bar
        // stops taking clicks on its close button at some text sizes (see
        // window_close_buttons_work_at_every_density_and_text_size).
        style.spacing.window_margin = egui::Margin::same(18);
        style.spacing.interact_size.y = body + 16.0;
        // Room between a menu item and its shortcut.
        style.spacing.menu_width = 260.0;
    } else {
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(10.0, 5.0);
        style.spacing.menu_margin = egui::Margin::same(8);
        style.spacing.window_margin = egui::Margin::same(16);
        style.spacing.interact_size.y = body + 12.0;
        style.spacing.menu_width = 220.0;
    }
}

/// The dock's tab bars at the current density: taller than egui_dock's
/// default, so tab names do not touch the bar's edges.
pub fn dock_style(style: &egui::Style) -> egui_dock::Style {
    let mut dock = egui_dock::Style::from_egui(style);
    let body = style
        .text_styles
        .get(&TextStyle::Body)
        .map_or(16.0, |font| font.size);
    dock.tab_bar.height = body + if is_compact() { 12.0 } else { 18.0 };
    dock
}

/// A dock tab's name with room on both sides (egui_dock pads only 8 points).
pub fn tab_title(title: &str) -> String {
    if is_compact() {
        format!(" {title} ")
    } else {
        format!("  {title}  ")
    }
}
pub fn is_compact() -> bool {
    COMPACT.load(Ordering::Relaxed)
}
/// Height of one table row for text of `font_size`.
pub fn row_height(font_size: f32) -> f32 {
    if is_compact() {
        font_size + 6.0
    } else {
        font_size + 14.0
    }
}

/// Monospace font for data (times, PIDs, addresses, results, bytes).
pub fn mono(size: f32) -> FontId {
    FontId::monospace(size)
}

/// Inner margin of text fields: room around the text so fields don't feel
/// cramped.
pub const TEXT_EDIT_MARGIN: egui::Margin = egui::Margin::symmetric(8, 5);

/// A section heading in the heading color, with room above it when it
/// follows something in a column.
pub fn section(ui: &mut egui::Ui, title: &str) -> egui::Response {
    if !ui.layout().main_dir().is_horizontal() && ui.min_rect().height() > 1.0 {
        ui.add_space(if is_compact() { 4.0 } else { 8.0 });
    }
    ui.label(egui::RichText::new(title).strong().color(heading()))
}

fn fonts() -> egui::FontDefinitions {
    let mut fonts = egui::FontDefinitions::default();
    // DejaVu covers arrows, box drawing and most symbols the defaults lack;
    // the default fonts stay as fallbacks (emoji).
    fonts.font_data.insert(
        "dejavu-sans".into(),
        FontData::from_static(include_bytes!("../assets/fonts/DejaVuSans.ttf")).into(),
    );
    fonts.font_data.insert(
        "dejavu-sans-mono".into(),
        FontData::from_static(include_bytes!("../assets/fonts/DejaVuSansMono.ttf")).into(),
    );
    fonts
        .families
        .entry(FontFamily::Proportional)
        .or_default()
        .insert(0, "dejavu-sans".into());
    fonts
        .families
        .entry(FontFamily::Monospace)
        .or_default()
        .insert(0, "dejavu-sans-mono".into());
    egui_phosphor::add_to_fonts(&mut fonts, egui_phosphor::Variant::Regular);
    fonts
}

pub fn install(ctx: &egui::Context) {
    ctx.set_fonts(fonts());
    apply(ctx, false);
    text_size(ctx, 16.0);
}

/// Switch palette (light or dark) and restyle every widget.
pub fn apply(ctx: &egui::Context, light: bool) {
    LIGHT_THEME.store(light, Ordering::Relaxed);
    let palette = palette();
    let mut style = (*ctx.style()).clone();
    style.visuals = if light {
        egui::Visuals::light()
    } else {
        egui::Visuals::dark()
    };
    style.visuals.panel_fill = palette.panel;
    style.visuals.window_fill = palette.raised;
    style.visuals.extreme_bg_color = palette.bg;
    style.visuals.faint_bg_color = palette.panel;
    style.visuals.code_bg_color = palette.bg;
    style.visuals.override_text_color = Some(palette.text);
    style.visuals.hyperlink_color = palette.accent;
    style.visuals.warn_fg_color = palette.warn;
    style.visuals.error_fg_color = palette.error;
    style.visuals.selection.bg_fill = palette.selection;
    style.visuals.selection.stroke = Stroke::new(1.0_f32, palette.accent);
    style.visuals.window_stroke = Stroke::new(1.0_f32, palette.line);
    style.visuals.window_corner_radius = 6.into();
    style.visuals.menu_corner_radius = 6.into();
    for widgets in [
        &mut style.visuals.widgets.noninteractive,
        &mut style.visuals.widgets.inactive,
        &mut style.visuals.widgets.hovered,
        &mut style.visuals.widgets.active,
        &mut style.visuals.widgets.open,
    ] {
        widgets.corner_radius = 4.into();
        widgets.bg_stroke = Stroke::new(1.0_f32, palette.line);
        widgets.fg_stroke = Stroke::new(1.0_f32, palette.text);
    }
    style.visuals.widgets.noninteractive.bg_fill = palette.panel;
    style.visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, palette.muted);
    style.visuals.widgets.inactive.bg_fill = palette.raised;
    style.visuals.widgets.inactive.weak_bg_fill = palette.raised;
    style.visuals.widgets.hovered.bg_fill = palette.hover;
    style.visuals.widgets.hovered.weak_bg_fill = palette.hover;
    style.visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, palette.accent);
    style.visuals.widgets.active.bg_fill = palette.primary;
    style.visuals.widgets.active.weak_bg_fill = palette.primary;
    style.visuals.widgets.active.fg_stroke = Stroke::new(1.0_f32, palette.primary_text);
    style.visuals.widgets.open.bg_fill = palette.hover;
    // egui grows a hovered or pressed widget by a point; next to a panel or
    // window edge that point is cut off, so widgets keep their size.
    style.visuals.widgets.hovered.expansion = 0.0;
    style.visuals.widgets.active.expansion = 0.0;
    density(&mut style);
    let size = style
        .text_styles
        .get(&TextStyle::Body)
        .map_or(16.0, |font| font.size);
    ctx.set_style(style);
    text_size(ctx, size);
}

pub(crate) fn text_size(ctx: &egui::Context, size: f32) {
    let size = size.clamp(12.0, 24.0);
    ctx.style_mut(|style| {
        for text_style in [TextStyle::Body, TextStyle::Button] {
            style
                .text_styles
                .insert(text_style, FontId::proportional(size));
        }
        style.text_styles.insert(
            TextStyle::Small,
            FontId::proportional((size - 2.0).max(12.0)),
        );
        style
            .text_styles
            .insert(TextStyle::Heading, FontId::proportional(size + 4.0));
        style
            .text_styles
            .insert(TextStyle::Monospace, FontId::monospace(size - 1.0));
        density(style);
    });
}

/// Row tint of a syscall group in the trace (Wireshark-style coloring): dark
/// shades that keep the normal text readable. Info queries stay untinted.
pub fn syscall_tint(
    group: antinomie_monitor_core::syscall_groups::SyscallGroup,
) -> Option<Color32> {
    let tint = dark_syscall_tint(group)?;
    Some(if is_light() { lighten(tint) } else { tint })
}

/// A light-theme version of a dark tint: the same hue as a pale pastel, so
/// dark text stays readable on it.
pub fn lighten(tint: Color32) -> Color32 {
    // Pale, as Wireshark's light rules: hue kept, little chroma.
    let mix = |channel: u8| (250.0 - (120.0 - f32::from(channel).min(120.0)) * 0.32) as u8;
    let (r, g, b) = (tint.r(), tint.g(), tint.b());
    let max = r.max(g).max(b).max(1);
    // Keep the hue: scale so the strongest channel sits near white.
    let scale = |channel: u8| (f32::from(channel) / f32::from(max) * 120.0) as u8;
    Color32::from_rgb(mix(scale(r)), mix(scale(g)), mix(scale(b)))
}

fn dark_syscall_tint(
    group: antinomie_monitor_core::syscall_groups::SyscallGroup,
) -> Option<Color32> {
    use antinomie_monitor_core::syscall_groups::SyscallGroup as G;
    Some(match group {
        G::Process => Color32::from_rgb(70, 50, 96),
        G::File => Color32::from_rgb(38, 58, 92),
        G::Network => Color32::from_rgb(36, 78, 52),
        G::Memory => Color32::from_rgb(30, 74, 68),
        G::Ipc => Color32::from_rgb(84, 76, 32),
        G::Signal => Color32::from_rgb(98, 62, 30),
        G::Polling => Color32::from_rgb(28, 76, 98),
        G::Security => Color32::from_rgb(110, 40, 46),
        G::System => Color32::from_rgb(78, 28, 38),
        G::Time => Color32::from_rgb(58, 58, 64),
        G::Info => return None,
    })
}

/// Row colors of the network packet list, in the order the rules apply
/// (Wireshark's default coloring rules, in dark shades).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketColor {
    TcpReset,
    TcpSynFin,
    Http,
    Tls,
    Dns,
    Dhcp,
    Arp,
    Icmp,
    Tcp,
    Udp,
}

impl PacketColor {
    pub const ALL: [PacketColor; 10] = [
        PacketColor::TcpReset,
        PacketColor::TcpSynFin,
        PacketColor::Http,
        PacketColor::Tls,
        PacketColor::Dns,
        PacketColor::Dhcp,
        PacketColor::Arp,
        PacketColor::Icmp,
        PacketColor::Tcp,
        PacketColor::Udp,
    ];

    pub fn label(self) -> &'static str {
        match self {
            PacketColor::TcpReset => "TCP reset (RST)",
            PacketColor::TcpSynFin => "TCP open or close (SYN, FIN)",
            PacketColor::Http => "HTTP",
            PacketColor::Tls => "TLS",
            PacketColor::Dns => "DNS",
            PacketColor::Dhcp => "DHCP",
            PacketColor::Arp => "ARP",
            PacketColor::Icmp => "ICMP, ICMPv6",
            PacketColor::Tcp => "Other TCP",
            PacketColor::Udp => "Other UDP",
        }
    }

    /// Dark shades that keep the normal text readable (pastels in the
    /// light theme).
    pub fn tint(self) -> Color32 {
        let tint = self.dark_tint();
        if is_light() {
            lighten(tint)
        } else {
            tint
        }
    }

    fn dark_tint(self) -> Color32 {
        match self {
            PacketColor::TcpReset => Color32::from_rgb(112, 34, 40),
            PacketColor::TcpSynFin => Color32::from_rgb(66, 66, 72),
            PacketColor::Http => Color32::from_rgb(36, 80, 50),
            PacketColor::Tls => Color32::from_rgb(74, 48, 100),
            PacketColor::Dns => Color32::from_rgb(22, 74, 80),
            PacketColor::Dhcp => Color32::from_rgb(80, 74, 26),
            PacketColor::Arp => Color32::from_rgb(100, 64, 26),
            PacketColor::Icmp => Color32::from_rgb(98, 38, 78),
            PacketColor::Tcp => Color32::from_rgb(46, 52, 96),
            PacketColor::Udp => Color32::from_rgb(24, 60, 102),
        }
    }
}

pub fn frame(fill: Color32) -> egui::Frame {
    egui::Frame::new()
        .fill(fill)
        .stroke(Stroke::new(1.0_f32, line()))
        .inner_margin(egui::Margin::symmetric(12, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_groups_have_distinct_dark_tints_except_info() {
        use antinomie_monitor_core::syscall_groups::SyscallGroup;
        let tints: Vec<_> = SyscallGroup::ALL
            .iter()
            .filter_map(|group| syscall_tint(*group))
            .collect();
        assert_eq!(tints.len(), SyscallGroup::ALL.len() - 1);
        assert_eq!(syscall_tint(SyscallGroup::Info), None);
        let distinct: std::collections::HashSet<_> = tints.iter().collect();
        assert_eq!(distinct.len(), tints.len());
        // Dark enough that TEXT stays readable on every tint.
        for tint in tints {
            assert!(tint.r().max(tint.g()).max(tint.b()) <= 120, "{tint:?}");
        }
    }

    #[test]
    fn packet_colors_are_distinct_and_dark() {
        let tints: std::collections::HashSet<_> =
            PacketColor::ALL.iter().map(|color| color.tint()).collect();
        assert_eq!(tints.len(), PacketColor::ALL.len());
        for tint in tints {
            assert!(tint.r().max(tint.g()).max(tint.b()) <= 120, "{tint:?}");
        }
    }

    #[test]
    fn compact_native_theme_installs_readable_dark_controls() {
        let ctx = egui::Context::default();
        install(&ctx);
        let style = ctx.style();
        assert!(style.visuals.dark_mode);
        assert_eq!(style.visuals.panel_fill, panel());
        assert_eq!(style.visuals.window_fill, raised());
        assert_eq!(style.visuals.extreme_bg_color, bg());
        assert_eq!(style.visuals.override_text_color, Some(text()));
        assert_eq!(style.visuals.selection.stroke.color, blue());
        for (text_style, size) in [
            (TextStyle::Body, 16.0),
            (TextStyle::Button, 16.0),
            (TextStyle::Monospace, 15.0),
            (TextStyle::Small, 14.0),
            (TextStyle::Heading, 20.0),
        ] {
            assert_eq!(style.text_styles[&text_style].size, size);
        }
    }
}

#[cfg(test)]
mod close_button_tests {
    use eframe::egui;

    /// Whether a click near a window's top-right corner (where its close
    /// button is) closes it.
    fn close_button_works(compact: bool, font: f32) -> bool {
        let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1600.0, 1000.0));
        let input = |events: Vec<egui::Event>| egui::RawInput {
            screen_rect: Some(screen),
            events,
            ..Default::default()
        };
        let draw = |ctx: &egui::Context, open: &mut bool| {
            egui::Window::new("Probe")
                .id(egui::Id::new("probe"))
                .default_pos(egui::pos2(200.0, 200.0))
                .open(open)
                .show(ctx, |ui| {
                    ui.label("content");
                });
        };
        let setup = || {
            let ctx = egui::Context::default();
            super::install(&ctx);
            super::text_size(&ctx, font);
            super::set_compact(&ctx, compact);
            let mut open = true;
            for _ in 0..3 {
                let _ = ctx.run(input(vec![]), |ctx| draw(ctx, &mut open));
            }
            ctx
        };
        let Some(rect) = setup().memory(|m| m.area_rect(egui::Id::new("probe"))) else {
            return false;
        };
        for dy in (0..90).step_by(3) {
            for dx in (0..70).step_by(3) {
                let pos = egui::pos2(rect.right() - dx as f32, rect.top() + dy as f32);
                let ctx = setup();
                let mut open = true;
                let press = |pressed| egui::Event::PointerButton {
                    pos,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: Default::default(),
                };
                for events in [
                    vec![egui::Event::PointerMoved(pos)],
                    vec![press(true)],
                    vec![press(false)],
                    vec![],
                ] {
                    let _ = ctx.run(input(events), |ctx| draw(ctx, &mut open));
                }
                if !open {
                    return true;
                }
            }
        }
        false
    }

    #[test]
    fn window_close_buttons_work_at_every_density_and_text_size() {
        for compact in [true, false] {
            for font in [12.0, 14.0, 16.0, 17.0, 18.0, 20.0, 22.0, 24.0] {
                assert!(
                    close_button_works(compact, font),
                    "close button dead (compact {compact}, text {font})"
                );
            }
        }
    }
}
