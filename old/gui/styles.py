# -*- coding: utf-8 -*-
"""
Стили и цвета для GUI
"""

# Цветовая схема
COLORS = {
    # Основные цвета
    "bg_dark": "#1a1a2e",
    "bg_medium": "#16213e",
    "bg_light": "#0f3460",
    "accent": "#e94560",
    "accent_hover": "#ff6b6b",
    
    # Текст
    "text_primary": "#ffffff",
    "text_secondary": "#a0a0a0",
    "text_muted": "#6c757d",
    
    # Статусы
    "safe": "#4caf50",
    "safe_bg": "#1b4332",
    "suspicious": "#ffc107",
    "suspicious_bg": "#3d3d00",
    "spam": "#ff9800",
    "spam_bg": "#4a3000",
    "phishing": "#f44336",
    "phishing_bg": "#4a1010",
    
    # Элементы интерфейса
    "border": "#2a2a4a",
    "input_bg": "#252545",
    "button_bg": "#0f3460",
    "button_hover": "#1a4a7a",
    "scrollbar": "#3a3a5a",
    "scrollbar_hover": "#4a4a6a",
    
    # Severity
    "severity_low": "#8bc34a",
    "severity_medium": "#ffc107",
    "severity_high": "#ff9800",
    "severity_critical": "#f44336",
}

# Шрифты
FONTS = {
    "title": ("Segoe UI", 16, "bold"),
    "subtitle": ("Segoe UI", 12, "bold"),
    "body": ("Segoe UI", 10),
    "body_bold": ("Segoe UI", 10, "bold"),
    "small": ("Segoe UI", 9),
    "mono": ("Consolas", 10),
    "mono_small": ("Consolas", 9),
}

# Стили для ttk
TTK_STYLE_CONFIG = """
    TFrame {
        background: #1a1a2e;
    }
    TLabel {
        background: #1a1a2e;
        foreground: #ffffff;
        font: 10pt "Segoe UI";
    }
    TButton {
        background: #0f3460;
        foreground: #ffffff;
        font: 10pt "Segoe UI";
        padding: 8 16;
    }
    TEntry {
        fieldbackground: #252545;
        foreground: #ffffff;
        insertcolor: #ffffff;
    }
    TCheckbutton {
        background: #1a1a2e;
        foreground: #ffffff;
    }
    Treeview {
        background: #16213e;
        foreground: #ffffff;
        fieldbackground: #16213e;
        rowheight: 30;
    }
    Treeview.Heading {
        background: #0f3460;
        foreground: #ffffff;
        font: 10pt "Segoe UI" bold;
    }
"""

def get_status_color(classification: str) -> tuple:
    """Получить цвета для статуса"""
    status_colors = {
        "Безопасное": (COLORS["safe"], COLORS["safe_bg"]),
        "Подозрительное": (COLORS["suspicious"], COLORS["suspicious_bg"]),
        "Спам": (COLORS["spam"], COLORS["spam_bg"]),
        "Фишинг": (COLORS["phishing"], COLORS["phishing_bg"]),
        "Фишинг (опасное вложение)": (COLORS["phishing"], COLORS["phishing_bg"]),
    }
    return status_colors.get(classification, (COLORS["text_secondary"], COLORS["bg_medium"]))

def get_severity_color(severity: str) -> str:
    """Получить цвет для severity"""
    severity_colors = {
        "low": COLORS["severity_low"],
        "medium": COLORS["severity_medium"],
        "high": COLORS["severity_high"],
        "critical": COLORS["severity_critical"],
    }
    return severity_colors.get(severity, COLORS["text_secondary"])

