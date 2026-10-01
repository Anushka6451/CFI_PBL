"""
Theme / Design System — WannaCry Forensic Lab
Centralized color palette and style constants for the dark forensics UI.
"""

# ── Color Palette ─────────────────────────────────────────────────────────────
COLORS = {
    # Backgrounds
    "bg_darkest":    "#050A0F",
    "bg_dark":       "#0A1628",
    "bg_panel":      "#0D1B2A",
    "bg_card":       "#112240",
    "bg_card2":      "#0F1C35",
    "bg_input":      "#0D1F38",
    "bg_hover":      "#1A2F4A",

    # Accents
    "accent_blue":   "#00A8FF",
    "accent_cyan":   "#00D4FF",
    "accent_green":  "#00FF88",
    "accent_yellow": "#FFD700",
    "accent_orange": "#FF8C00",

    # Status colors
    "safe":          "#00FF88",
    "compromised":   "#FF2D55",
    "affected":      "#FF6B35",
    "isolated":      "#FFD700",
    "recovering":    "#00A8FF",
    "recovered":     "#00FF88",
    "protected":     "#7B68EE",

    # Text
    "text_primary":  "#E8F4FD",
    "text_secondary":"#8BA7C7",
    "text_dim":      "#4A6480",
    "text_critical": "#FF2D55",
    "text_warning":  "#FFD700",
    "text_success":  "#00FF88",
    "text_info":     "#00A8FF",
    "text_header":   "#FFFFFF",

    # Borders
    "border":        "#1E3A5F",
    "border_accent": "#00A8FF",
    "border_danger": "#FF2D55",
    "border_success":"#00FF88",

    # Severity
    "sev_critical":  "#FF2D55",
    "sev_high":      "#FF6B35",
    "sev_medium":    "#FFD700",
    "sev_info":      "#00A8FF",
    "sev_success":   "#00FF88",
}

# ── Machine Status → Color ────────────────────────────────────────────────────
STATUS_COLORS = {
    "SAFE":        COLORS["safe"],
    "COMPROMISED": COLORS["compromised"],
    "AFFECTED":    COLORS["affected"],
    "ISOLATED":    COLORS["isolated"],
    "RECOVERING":  COLORS["recovering"],
    "RECOVERED":   COLORS["recovered"],
    "PROTECTED":   COLORS["protected"],
}

STATUS_EMOJI = {
    "SAFE":        "🟢",
    "COMPROMISED": "🔴",
    "AFFECTED":    "🟠",
    "ISOLATED":    "🟡",
    "RECOVERING":  "🔵",
    "RECOVERED":   "🟢",
    "PROTECTED":   "🟣",
}

# ── Font Definitions ──────────────────────────────────────────────────────────
FONTS = {
    "title":   ("Consolas", 22, "bold"),
    "heading": ("Consolas", 16, "bold"),
    "subhead": ("Consolas", 13, "bold"),
    "body":    ("Consolas", 11),
    "small":   ("Consolas", 10),
    "mono":    ("Courier New", 11),
    "mono_sm": ("Courier New", 10),
    "label":   ("Consolas", 12, "bold"),
}

# ── Widget Style Defaults ─────────────────────────────────────────────────────
BUTTON_STYLES = {
    "primary": {
        "fg_color": "#00A8FF",
        "hover_color": "#0088CC",
        "text_color": "#FFFFFF",
        "font": ("Consolas", 13, "bold"),
        "corner_radius": 6,
        "height": 40,
    },
    "danger": {
        "fg_color": "#CC1033",
        "hover_color": "#FF2D55",
        "text_color": "#FFFFFF",
        "font": ("Consolas", 13, "bold"),
        "corner_radius": 6,
        "height": 40,
    },
    "success": {
        "fg_color": "#006644",
        "hover_color": "#00FF88",
        "text_color": "#FFFFFF",
        "font": ("Consolas", 13, "bold"),
        "corner_radius": 6,
        "height": 40,
    },
    "warning": {
        "fg_color": "#9B7200",
        "hover_color": "#FFD700",
        "text_color": "#FFFFFF",
        "font": ("Consolas", 13, "bold"),
        "corner_radius": 6,
        "height": 40,
    },
    "secondary": {
        "fg_color": "#1E3A5F",
        "hover_color": "#2A4F7A",
        "text_color": "#8BA7C7",
        "font": ("Consolas", 12),
        "corner_radius": 6,
        "height": 36,
    },
    "large_danger": {
        "fg_color": "#8B0000",
        "hover_color": "#CC0000",
        "text_color": "#FFFFFF",
        "font": ("Consolas", 15, "bold"),
        "corner_radius": 8,
        "height": 56,
    },
}
