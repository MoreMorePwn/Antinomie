//! Colors, fonts and spacing. Two palettes (dark, light) chosen at runtime;
//! widgets read the active one through the functions below. Data (numbers,
//! addresses, strings, flags, errors) gets syntax colors so dense views stay
//! readable, and tables size their rows from the density setting.
// The value colors, headings and density are adopted view by view.
use eframe::egui::{self, Color32, FontData, FontFamily, FontId, Stroke, TextStyle};
#[cfg(not(test))]
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

mod palettes;
pub use palettes::{translate, Palette, Theme, TREE_COLOR_COUNT};
#[cfg(test)]
pub use palettes::{BLUE, DARK, LIGHT};

#[cfg(not(test))]
static THEME: AtomicU8 = AtomicU8::new(0);
// Tests run in parallel threads, each with its own egui context: the active
// theme is per thread there, so one test's Light never restyles another's.
#[cfg(test)]
thread_local! {
    static THEME: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

fn load_theme() -> u8 {
    #[cfg(not(test))]
    return THEME.load(Ordering::Relaxed);
    #[cfg(test)]
    return THEME.with(std::cell::Cell::get);
}

fn store_theme(index: u8) {
    #[cfg(not(test))]
    THEME.store(index, Ordering::Relaxed);
    #[cfg(test)]
    THEME.with(|cell| cell.set(index));
}
// The density is per thread in tests for the same reason: one test's
// Comfortable must not change the spacing another test is laying out.
#[cfg(not(test))]
static COMPACT: AtomicBool = AtomicBool::new(true);
#[cfg(test)]
thread_local! {
    static COMPACT: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}

fn store_compact(compact: bool) {
    #[cfg(not(test))]
    COMPACT.store(compact, Ordering::Relaxed);
    #[cfg(test)]
    COMPACT.with(|cell| cell.set(compact));
}

/// The active palette.
pub fn palette() -> &'static Palette {
    theme().palette()
}
/// The active theme.
pub fn theme() -> Theme {
    Theme::from_index(load_theme())
}
/// Whether the active theme is the light one (blue and dark are both dark).
pub fn is_light() -> bool {
    theme().is_light()
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
/// Hairlines inside a surface (table rules, tab strips, footers).
pub fn line_soft() -> Color32 {
    palette().line_soft
}
/// Default text color of terminals and listings.
pub fn terminal_text() -> Color32 {
    palette().terminal_text
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
/// Fill of a bright call-to-action button; text on it is `primary_text`.
pub fn bright_blue() -> Color32 {
    palette().cta
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
    store_compact(compact);
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
    #[cfg(not(test))]
    return COMPACT.load(Ordering::Relaxed);
    #[cfg(test)]
    return COMPACT.with(std::cell::Cell::get);
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

/// Buttons without a border: nothing around them at rest, a tint when the
/// pointer is over one and a stronger tint while it is pressed. Call it on a
/// `Ui` scope that holds the buttons.
pub fn borderless_buttons(ui: &mut egui::Ui) {
    let palette = palette();
    let widgets = &mut ui.visuals_mut().widgets;
    widgets.inactive.weak_bg_fill = Color32::TRANSPARENT;
    widgets.inactive.bg_stroke = Stroke::NONE;
    widgets.hovered.weak_bg_fill = palette.hover;
    widgets.hovered.bg_stroke = Stroke::NONE;
    widgets.active.weak_bg_fill = palette.selection;
    widgets.active.bg_stroke = Stroke::NONE;
    widgets.open.weak_bg_fill = palette.hover;
    widgets.open.bg_stroke = Stroke::NONE;
}

/// How often a visible spinner moves. egui's own `Spinner` asks for a repaint
/// on every frame it is visible, which on a window that is otherwise idle
/// means drawing at the full frame rate (on software GL, several cores) for as
/// long as some work is pending.
const SPINNER_STEP: std::time::Duration = std::time::Duration::from_millis(100);

/// A spinner as tall as the body text, for rows whose work is still pending.
/// It turns in steps of [`SPINNER_STEP`], so a screen that only waits repaints
/// ten times a second, not once a frame. Show it only while the work runs.
pub fn spinner(ui: &mut egui::Ui) -> egui::Response {
    let color = ui.visuals().strong_text_color();
    spinner_colored(ui, color)
}

fn spinner_colored(ui: &mut egui::Ui, color: Color32) -> egui::Response {
    let size = ui.text_style_height(&TextStyle::Body);
    let (rect, response) = ui.allocate_exact_size(egui::vec2(size, size), egui::Sense::hover());
    response.widget_info(|| egui::WidgetInfo::new(egui::WidgetType::ProgressIndicator));
    if ui.is_rect_visible(rect) {
        ui.ctx().request_repaint_after(SPINNER_STEP);
        let step = SPINNER_STEP.as_secs_f64();
        let time = (ui.input(|input| input.time) / step).floor() * step;
        let radius = rect.height() / 2.0 - 2.0;
        let start = time * std::f64::consts::TAU;
        let end = start + 240f64.to_radians() * time.sin();
        let points: Vec<egui::Pos2> = (0..20)
            .map(|i| {
                let angle = start + (end - start) * f64::from(i) / 20.0;
                let (sin, cos) = angle.sin_cos();
                rect.center() + radius * egui::vec2(cos as f32, sin as f32)
            })
            .collect();
        ui.painter()
            .add(egui::Shape::line(points, Stroke::new(3.0_f32, color)));
    }
    response
}

/// `text` on one row with a spinner just left of it, in the default text color.
pub fn loading(ui: &mut egui::Ui, text: impl Into<egui::RichText>) -> egui::Response {
    ui.horizontal(|ui| {
        spinner(ui);
        ui.label(text.into());
    })
    .response
}

/// `loading` in the weak text color, like `Ui::weak`.
pub fn loading_weak(ui: &mut egui::Ui, text: impl Into<egui::RichText>) -> egui::Response {
    let color = ui.visuals().weak_text_color();
    loading_colored(ui, color, text)
}

/// `loading` with the text and the spinner in `color`, such as `muted()`.
pub fn loading_colored(
    ui: &mut egui::Ui,
    color: Color32,
    text: impl Into<egui::RichText>,
) -> egui::Response {
    ui.horizontal(|ui| {
        spinner_colored(ui, color);
        ui.colored_label(color, text);
    })
    .response
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

/// Switch between the dark and light themes (see `apply_theme`).
pub fn apply(ctx: &egui::Context, light: bool) {
    apply_theme(ctx, if light { Theme::Light } else { Theme::Dark });
}

/// Make `theme` the active theme and restyle every widget.
pub fn apply_theme(ctx: &egui::Context, theme: Theme) {
    store_theme(theme.index());
    let light = theme.is_light();
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
    style.visuals.faint_bg_color = palette.stripe;
    style.visuals.code_bg_color = palette.bg;
    style.visuals.override_text_color = Some(palette.text);
    style.visuals.hyperlink_color = palette.accent;
    style.visuals.warn_fg_color = palette.warn;
    style.visuals.error_fg_color = palette.error;
    style.visuals.selection.bg_fill = palette.selection;
    style.visuals.selection.stroke = Stroke::new(1.0_f32, palette.accent);
    style.visuals.window_stroke = Stroke::new(1.0_f32, palette.line);
    // Windows: 8 px corners, a 1 px line and a soft shadow (the mockup's
    // `.modal`); menus keep 6.
    style.visuals.window_corner_radius = 8.into();
    style.visuals.menu_corner_radius = 6.into();
    style.visuals.window_shadow = egui::Shadow {
        offset: [0, 8],
        blur: 28,
        spread: 0,
        color: palette.shadow,
    };
    style.visuals.popup_shadow = style.visuals.window_shadow;
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
    // egui draws `RichText::strong()` in the pressed state's text color, so
    // that color must read on the panel: the pressed fill is the selection
    // tint, not the primary fill. A primary button sets its own fill and text.
    style.visuals.widgets.active.bg_fill = palette.selection;
    style.visuals.widgets.active.weak_bg_fill = palette.selection;
    style.visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, palette.accent);
    style.visuals.widgets.active.fg_stroke = Stroke::new(1.0_f32, palette.text);
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
/// shades in the dark themes and pastels in the light one, so the normal text
/// stays readable. Info queries stay untinted.
pub fn syscall_tint(
    group: antinomie_monitor_core::syscall_groups::SyscallGroup,
) -> Option<Color32> {
    use antinomie_monitor_core::syscall_groups::SyscallGroup as G;
    let index = match group {
        G::Process => 0,
        G::File => 1,
        G::Network => 2,
        G::Memory => 3,
        G::Ipc => 4,
        G::Signal => 5,
        G::Polling => 6,
        G::Security => 7,
        G::System => 8,
        G::Time => 9,
        G::Info => return None,
    };
    Some(palette().syscall[index])
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
    #[cfg(test)]
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

    /// Dark shades that keep the normal text readable (pastels in the
    /// light theme).
    pub fn tint(self) -> Color32 {
        let index = match self {
            PacketColor::TcpReset => 0,
            PacketColor::TcpSynFin => 1,
            PacketColor::Http => 2,
            PacketColor::Tls => 3,
            PacketColor::Dns => 4,
            PacketColor::Dhcp => 5,
            PacketColor::Arp => 6,
            PacketColor::Icmp => 7,
            PacketColor::Tcp => 8,
            PacketColor::Udp => 9,
        };
        palette().packet[index]
    }
}

pub fn frame(fill: Color32) -> egui::Frame {
    egui::Frame::new()
        .fill(fill)
        .stroke(Stroke::new(1.0_f32, line()))
        .inner_margin(egui::Margin::symmetric(12, 0))
}

/// Spinners drawn in `shapes`: egui paints each one as a single path.
#[cfg(test)]
pub(crate) fn spinners_in(shapes: &[egui::epaint::ClippedShape]) -> usize {
    fn count(shape: &egui::Shape) -> usize {
        match shape {
            egui::Shape::Path(_) => 1,
            egui::Shape::Vec(shapes) => shapes.iter().map(count).sum(),
            _ => 0,
        }
    }
    shapes.iter().map(|clipped| count(&clipped.shape)).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn luminance(color: Color32) -> f32 {
        let linear = |channel: u8| {
            let c = f32::from(channel) / 255.0;
            if c <= 0.03928 {
                c / 12.92
            } else {
                ((c + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * linear(color.r()) + 0.7152 * linear(color.g()) + 0.0722 * linear(color.b())
    }

    fn contrast(a: Color32, b: Color32) -> f32 {
        let (a, b) = (luminance(a), luminance(b));
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }

    /// `RichText::strong()` and `Ui::strong` take the pressed text color; it
    /// must read on every surface in every theme (it was white in Light).
    #[test]
    fn strong_text_reads_on_the_surfaces_in_every_theme() {
        for theme in Theme::ALL {
            let ctx = egui::Context::default();
            install(&ctx);
            apply_theme(&ctx, theme);
            let p = theme.palette();
            let strong = ctx.style().visuals.strong_text_color();
            assert_eq!(strong, p.text, "{theme:?}");
            for ground in [p.bg, p.panel, p.raised, p.hover] {
                assert!(contrast(strong, ground) >= 7.0, "{theme:?} on {ground:?}");
            }
            let pressed = ctx.style().visuals.widgets.active.bg_fill;
            assert!(contrast(strong, pressed) >= 4.5, "{theme:?} pressed fill");
        }
    }

    /// Every token of every theme is set, opaque where it must be, and
    /// readable on the surfaces it is used on.
    #[test]
    fn every_theme_has_a_complete_readable_token_set() {
        for theme in Theme::ALL {
            let p = theme.palette();
            let name = theme.label();
            let surfaces = [p.bg, p.panel, p.raised, p.hover];
            for (i, a) in surfaces.iter().enumerate() {
                for b in &surfaces[i + 1..] {
                    assert_ne!(a, b, "{name}: surfaces must differ");
                }
            }
            assert_ne!(p.line, p.line_soft, "{name}");
            for color in [
                p.bg,
                p.panel,
                p.raised,
                p.hover,
                p.line,
                p.line_soft,
                p.text,
                p.muted,
                p.hint,
                p.accent,
                p.heading,
                p.primary,
                p.primary_text,
                p.cta,
                p.selection,
                p.good,
                p.warn,
                p.error,
                p.info,
                p.live,
                p.terminal,
                p.terminal_text,
                p.number,
                p.string,
                p.pointer,
                p.flag,
                p.name,
            ] {
                assert_eq!(color.a(), 255, "{name}: {color:?} must be opaque");
            }
            for color in [
                p.selection_soft,
                p.stripe,
                p.good_bg,
                p.warn_bg,
                p.error_bg,
                p.info_bg,
                p.neutral_bg,
                p.shadow,
            ] {
                assert!(
                    color.a() > 0 && color.a() < 255,
                    "{name}: {color:?} must be translucent"
                );
            }
            for ground in [p.bg, p.panel, p.raised] {
                assert!(
                    contrast(p.text, ground) >= 7.0,
                    "{name}: text on {ground:?}"
                );
                assert!(
                    contrast(p.muted, ground) >= 3.5,
                    "{name}: muted on {ground:?}"
                );
                for color in [
                    p.accent, p.heading, p.good, p.warn, p.error, p.info, p.live, p.number,
                    p.string, p.pointer, p.flag, p.name,
                ] {
                    assert!(
                        contrast(color, ground) >= 3.5,
                        "{name}: {color:?} on {ground:?}"
                    );
                }
            }
            assert!(contrast(p.hint, p.bg) >= 2.5, "{name}: hint");
            assert!(
                contrast(p.primary_text, p.primary) >= 4.5,
                "{name}: primary button"
            );
            assert!(contrast(p.text, p.selection) >= 4.5, "{name}: selected row");
            assert!(
                contrast(p.terminal_text, p.terminal) >= 7.0,
                "{name}: terminal"
            );
            let tints: std::collections::HashSet<_> = p.syscall.iter().collect();
            assert_eq!(tints.len(), p.syscall.len(), "{name}: syscall tints");
            let packets: std::collections::HashSet<_> = p.packet.iter().collect();
            assert_eq!(packets.len(), p.packet.len(), "{name}: packet tints");
            // Row text stays readable on every tint.
            for tint in p.syscall.iter().chain(&p.packet) {
                assert!(contrast(p.text, *tint) >= 4.5, "{name}: text on {tint:?}");
            }
        }
        // Blue is a dark theme on navy surfaces, not the grey ones.
        assert!(BLUE.bg.b() > BLUE.bg.r() + 10 && BLUE.panel.b() > BLUE.panel.r() + 15);
        assert!(luminance(BLUE.bg) < 0.05 && luminance(LIGHT.bg) > 0.9);
    }

    #[test]
    fn applying_a_theme_sets_the_visuals_and_the_active_palette() {
        for theme_choice in Theme::ALL {
            let ctx = egui::Context::default();
            install(&ctx);
            apply_theme(&ctx, theme_choice);
            let palette = theme_choice.palette();
            let style = ctx.style();
            assert_eq!(theme(), theme_choice);
            assert_eq!(is_light(), theme_choice == Theme::Light);
            assert_eq!(style.visuals.dark_mode, theme_choice != Theme::Light);
            assert_eq!(style.visuals.panel_fill, palette.panel);
            assert_eq!(style.visuals.window_fill, palette.raised);
            assert_eq!(style.visuals.extreme_bg_color, palette.bg);
            assert_eq!(style.visuals.window_stroke.color, palette.line);
            assert_eq!(style.visuals.selection.bg_fill, palette.selection);
            assert_eq!(bright_blue(), palette.cta);
            assert_eq!(
                syscall_tint(antinomie_monitor_core::syscall_groups::SyscallGroup::File),
                Some(palette.syscall[1])
            );
            assert_eq!(PacketColor::Dns.tint(), palette.packet[4]);
        }
        apply(&egui::Context::default(), false);
    }

    #[test]
    fn theme_keys_are_stable_and_round_trip() {
        let keys: Vec<String> = Theme::ALL
            .iter()
            .map(|theme| serde_json::to_string(theme).unwrap())
            .collect();
        assert_eq!(keys, [r#""dark""#, r#""light""#, r#""blue""#]);
        for theme in Theme::ALL {
            assert_eq!(Theme::from_index(theme.index()), theme);
        }
        assert_eq!(Theme::from_index(200), Theme::Dark);
    }

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
    fn loading_draws_a_spinner_left_of_the_text_on_one_row() {
        let ctx = egui::Context::default();
        let mut rows = None;
        let output = ctx.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let response = loading(ui, "Reading…");
                rows = Some(response.rect);
            });
        });
        let rect = rows.unwrap();
        let mut text = None;
        let mut spinner = None;
        for clipped in &output.shapes {
            collect_shapes(&clipped.shape, &mut text, &mut spinner);
        }
        let (text_rect, spinner_rect) = (text.expect("label"), spinner.expect("spinner"));
        assert!(
            spinner_rect.max.x <= text_rect.min.x + 0.5,
            "{spinner_rect:?} {text_rect:?}"
        );
        assert!((spinner_rect.center().y - text_rect.center().y).abs() < 4.0);
        assert!(rect.contains_rect(text_rect));
    }

    fn collect_shapes(
        shape: &egui::Shape,
        text: &mut Option<egui::Rect>,
        spinner: &mut Option<egui::Rect>,
    ) {
        match shape {
            egui::Shape::Vec(shapes) => {
                shapes.iter().for_each(|s| collect_shapes(s, text, spinner))
            }
            egui::Shape::Text(t) if t.galley.text() == "Reading…" => {
                *text = Some(t.visual_bounding_rect());
            }
            egui::Shape::Path(path) => {
                let rect = egui::Rect::from_points(&path.points);
                *spinner = Some(spinner.map_or(rect, |old| old.union(rect)));
            }
            _ => {}
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
