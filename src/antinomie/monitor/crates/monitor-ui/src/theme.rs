use eframe::egui::{self, Color32, FontId, Stroke, TextStyle};

pub const BG: Color32 = Color32::from_rgb(31, 31, 32);
pub const PANEL: Color32 = Color32::from_rgb(37, 37, 38);
pub const RAISED: Color32 = Color32::from_rgb(44, 44, 46);
pub const LINE: Color32 = Color32::from_rgb(62, 62, 65);
pub const TEXT: Color32 = Color32::from_rgb(210, 214, 220);
pub const MUTED: Color32 = Color32::from_rgb(147, 155, 166);
pub const BLUE: Color32 = Color32::from_rgb(148, 188, 235);
pub const PRIMARY: Color32 = Color32::from_rgb(49, 93, 139);
pub const GOOD: Color32 = Color32::from_rgb(128, 192, 153);
pub const WARN: Color32 = Color32::from_rgb(224, 182, 111);
pub const ERROR: Color32 = Color32::from_rgb(235, 139, 139);
pub const TERMINAL: Color32 = Color32::from_rgb(26, 26, 27);

pub fn install(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    egui_phosphor::add_to_fonts(&mut fonts, egui_phosphor::Variant::Regular);
    ctx.set_fonts(fonts);
    let mut style = (*ctx.style()).clone();
    style.visuals = egui::Visuals::dark();
    style.visuals.panel_fill = PANEL;
    style.visuals.window_fill = RAISED;
    style.visuals.extreme_bg_color = BG;
    style.visuals.faint_bg_color = PANEL;
    style.visuals.override_text_color = Some(TEXT);
    style.visuals.selection.bg_fill = Color32::from_rgb(45, 62, 82);
    style.visuals.selection.stroke = Stroke::new(1.0_f32, BLUE);
    style.visuals.window_stroke = Stroke::new(1.0_f32, LINE);
    style.visuals.window_corner_radius = 3.into();
    for widgets in [
        &mut style.visuals.widgets.noninteractive,
        &mut style.visuals.widgets.inactive,
        &mut style.visuals.widgets.hovered,
        &mut style.visuals.widgets.active,
        &mut style.visuals.widgets.open,
    ] {
        widgets.corner_radius = 2.into();
        widgets.bg_stroke = Stroke::new(1.0_f32, LINE);
        widgets.fg_stroke = Stroke::new(1.0_f32, TEXT);
    }
    style.visuals.widgets.noninteractive.bg_fill = PANEL;
    style.visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, MUTED);
    style.visuals.widgets.inactive.bg_fill = RAISED;
    style.visuals.widgets.inactive.weak_bg_fill = RAISED;
    style.visuals.widgets.hovered.bg_fill = Color32::from_rgb(54, 54, 57);
    style.visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(54, 54, 57);
    style.visuals.widgets.active.bg_fill = PRIMARY;
    style.visuals.widgets.active.weak_bg_fill = PRIMARY;
    style.spacing.item_spacing = egui::vec2(8.0, 5.0);
    style.spacing.button_padding = egui::vec2(8.0, 4.0);
    style.spacing.interact_size.y = 28.0;
    style
        .text_styles
        .insert(TextStyle::Body, FontId::proportional(16.0));
    style
        .text_styles
        .insert(TextStyle::Button, FontId::proportional(16.0));
    style
        .text_styles
        .insert(TextStyle::Small, FontId::proportional(14.0));
    style
        .text_styles
        .insert(TextStyle::Heading, FontId::proportional(20.0));
    style
        .text_styles
        .insert(TextStyle::Monospace, FontId::monospace(16.0));
    ctx.set_style(style);
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
            .insert(TextStyle::Monospace, FontId::monospace(size));
        style.spacing.interact_size.y = size + 12.0;
    });
}

/// Row tint of a syscall group in the trace (Wireshark-style coloring): dark
/// shades that keep the normal text readable. Info queries stay untinted.
pub fn syscall_tint(
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

    /// Dark shades that keep the normal text readable.
    pub fn tint(self) -> Color32 {
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
        .stroke(Stroke::new(1.0_f32, LINE))
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
        assert_eq!(style.visuals.panel_fill, PANEL);
        assert_eq!(style.visuals.window_fill, RAISED);
        assert_eq!(style.visuals.extreme_bg_color, BG);
        assert_eq!(style.visuals.override_text_color, Some(TEXT));
        assert_eq!(style.visuals.selection.stroke.color, BLUE);
        for (text_style, size) in [
            (TextStyle::Body, 16.0),
            (TextStyle::Button, 16.0),
            (TextStyle::Monospace, 16.0),
            (TextStyle::Small, 14.0),
            (TextStyle::Heading, 20.0),
        ] {
            assert_eq!(style.text_styles[&text_style].size, size);
        }
    }
}
