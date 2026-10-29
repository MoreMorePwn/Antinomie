# Official Antinomie identity

Adopted 2026-10-29: **A softer edge**, with **Comfortaa 700**, plain Latin
**Antinomie**, and letter spacing **−0.025 em**. The default is the horizontal
color lockup. Greek lettering remains an optional secondary study.

| Asset | Use |
|---|---|
| `antinomie-logo-color.svg` | Primary horizontal logo on a light surface |
| `antinomie-logo-black.svg` / `antinomie-logo-white.svg` | Single-color horizontal logos for light/dark surfaces |
| `antinomie-stacked-{color,black,white}.svg` | Symbol above the name |
| `antinomie-wordmark-{color,black,white}.svg` | Name without the symbol |
| `antinomie-symbol-{color,black,white}.svg` | Symbol with a close-fitting portrait view box |
| `antinomie-icon-{color,black,white}.svg` / `.png` | Square symbol for app icons and favicons |
| `antinomie-logo-{color,black,white}.png` | 1536-pixel-wide transparent raster derivatives |
| `identity.json` | Official selection, color values and provenance |

Black and white artwork has transparent cutouts, with no background rectangle.
All SVG lettering is outlined, so the logo does not depend on installed fonts.
Use the white logo on dark surfaces; use color or black on light surfaces.
Keep the existing proportions and leave the surrounding clear space intact.

The desktop installer and release script consume the canonical icon at
`src/antinomie/monitor/assets/antinomie.svg`. The native app embeds the PNG
derivatives in that directory, uses the symbol in window chrome and chooses the
color/white lockup for its About panel according to the application theme.
Future application archives include this complete branding directory alongside
the desktop icon and the required notices.

Source typeface: [Comfortaa in Google Fonts](https://github.com/google/fonts/tree/main/ofl/comfortaa),
static weight 700. Copyright 2011 The Comfortaa Project Authors; SIL OFL 1.1.
The notice is retained in `LICENSES/third-party/fonts/Comfortaa-OFL.txt`.
The penguin comes from the user's supplied artwork and the SVG reconstruction
and edits selected during the design session. This selection replaces the
earlier letter-A brand for current assets; historical release artifacts remain snapshots.
