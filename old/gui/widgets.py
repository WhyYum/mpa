# -*- coding: utf-8 -*-
"""
Кастомные виджеты для GUI
"""

import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional, Dict, List
from .styles import COLORS, FONTS, get_status_color, get_severity_color


class ToolTip:
    """Всплывающая подсказка"""
    
    def __init__(self, widget, text: str = "", delay: int = 500):
        self.widget = widget
        self.text = text
        self.delay = delay
        self.tooltip_window = None
        self.after_id = None
        
        self.widget.bind("<Enter>", self._on_enter)
        self.widget.bind("<Leave>", self._on_leave)
        self.widget.bind("<Motion>", self._on_motion)
    
    def _on_enter(self, event):
        self._schedule_show()
    
    def _on_leave(self, event):
        self._cancel_show()
        self._hide()
    
    def _on_motion(self, event):
        if self.tooltip_window:
            self._hide()
            self._schedule_show()
    
    def _schedule_show(self):
        self._cancel_show()
        self.after_id = self.widget.after(self.delay, self._show)
    
    def _cancel_show(self):
        if self.after_id:
            self.widget.after_cancel(self.after_id)
            self.after_id = None
    
    def _show(self):
        if not self.text:
            return
        
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        
        self.tooltip_window = tk.Toplevel(self.widget)
        self.tooltip_window.wm_overrideredirect(True)
        self.tooltip_window.wm_geometry(f"+{x}+{y}")
        
        frame = tk.Frame(
            self.tooltip_window,
            bg=COLORS["bg_light"],
            relief="solid",
            borderwidth=1
        )
        frame.pack()
        
        label = tk.Label(
            frame,
            text=self.text,
            bg=COLORS["bg_light"],
            fg=COLORS["text_primary"],
            font=FONTS["small"],
            justify="left",
            padx=10,
            pady=5
        )
        label.pack()
    
    def _hide(self):
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None
    
    def update_text(self, text: str):
        self.text = text


class DomainInfoTooltip(ToolTip):
    """Подсказка с информацией о домене"""
    
    def __init__(self, widget, domain_info: Dict = None):
        super().__init__(widget)
        self.domain_info = domain_info or {}
        self._update_tooltip_text()
    
    def _update_tooltip_text(self):
        if not self.domain_info:
            self.text = "Информация о домене недоступна"
            return
        
        lines = []
        
        domain = self.domain_info.get("domain", "")
        if domain:
            lines.append(f"🌐 Домен: {domain}")
        
        mx_records = self.domain_info.get("mx_records", [])
        if mx_records:
            lines.append(f"📧 Почтовый сервер: {mx_records[0]}")
        
        spf = self.domain_info.get("spf_record", "")
        if spf:
            lines.append(f"🔒 SPF: Настроен")
        else:
            lines.append(f"⚠️ SPF: Не настроен")
        
        if self.domain_info.get("has_dmarc"):
            lines.append(f"🔒 DMARC: Настроен")
        else:
            lines.append(f"⚠️ DMARC: Не настроен")
        
        self.text = "\n".join(lines)
    
    def set_domain_info(self, domain_info: Dict):
        self.domain_info = domain_info
        self._update_tooltip_text()


class CollapsibleFrame(tk.Frame):
    """Сворачиваемый фрейм"""
    
    def __init__(self, parent, title: str, **kwargs):
        super().__init__(parent, bg=COLORS["bg_medium"], **kwargs)
        
        self.is_expanded = False
        
        # Заголовок
        self.header = tk.Frame(self, bg=COLORS["bg_light"], cursor="hand2")
        self.header.pack(fill="x")
        self.header.bind("<Button-1>", self._toggle)
        
        self.arrow_label = tk.Label(
            self.header,
            text="▶",
            bg=COLORS["bg_light"],
            fg=COLORS["text_primary"],
            font=FONTS["body"],
            padx=5
        )
        self.arrow_label.pack(side="left")
        self.arrow_label.bind("<Button-1>", self._toggle)
        
        self.title_label = tk.Label(
            self.header,
            text=title,
            bg=COLORS["bg_light"],
            fg=COLORS["text_primary"],
            font=FONTS["body_bold"]
        )
        self.title_label.pack(side="left", padx=5, pady=5)
        self.title_label.bind("<Button-1>", self._toggle)
        
        # Контент
        self.content = tk.Frame(self, bg=COLORS["bg_medium"])
    
    def _toggle(self, event=None):
        if self.is_expanded:
            self.collapse()
        else:
            self.expand()
    
    def expand(self):
        self.content.pack(fill="both", expand=True, padx=10, pady=5)
        self.arrow_label.config(text="▼")
        self.is_expanded = True
    
    def collapse(self):
        self.content.pack_forget()
        self.arrow_label.config(text="▶")
        self.is_expanded = False
    
    def get_content_frame(self) -> tk.Frame:
        return self.content


class EmailLogItem(tk.Frame):
    """Элемент лога письма"""
    
    def __init__(self, parent, analysis_result, on_expand: Callable = None):
        super().__init__(parent, bg=COLORS["bg_medium"], pady=2)
        
        self.analysis_result = analysis_result
        self.is_expanded = False
        self.on_expand = on_expand
        
        # Получаем цвета статуса
        fg_color, bg_color = get_status_color(analysis_result.classification)
        
        # Главная строка
        self.main_row = tk.Frame(self, bg=bg_color, cursor="hand2")
        self.main_row.pack(fill="x", padx=2, pady=1)
        self.main_row.bind("<Button-1>", self._toggle)
        
        # Стрелка
        self.arrow = tk.Label(
            self.main_row,
            text="▶" if analysis_result.all_issues else "•",
            bg=bg_color,
            fg=fg_color,
            font=FONTS["body"],
            width=2
        )
        self.arrow.pack(side="left", padx=5)
        if analysis_result.all_issues:
            self.arrow.bind("<Button-1>", self._toggle)
        
        # Статус
        status_text = {
            "Безопасное": "✅",
            "Подозрительное": "⚠️",
            "Спам": "🚫",
            "Фишинг": "🎣",
            "Фишинг (опасное вложение)": "☠️"
        }.get(analysis_result.classification, "❓")
        
        self.status_label = tk.Label(
            self.main_row,
            text=status_text,
            bg=bg_color,
            font=FONTS["body"]
        )
        self.status_label.pack(side="left", padx=2)
        
        # Имя отправителя
        from_text = analysis_result.from_name or analysis_result.from_email
        if len(from_text) > 25:
            from_text = from_text[:22] + "..."
        
        self.from_label = tk.Label(
            self.main_row,
            text=from_text,
            bg=bg_color,
            fg=COLORS["text_primary"],
            font=FONTS["body_bold"],
            width=25,
            anchor="w"
        )
        self.from_label.pack(side="left", padx=5)
        self.from_label.bind("<Button-1>", self._toggle)
        
        # Знак вопроса для информации о домене
        self.info_btn = tk.Label(
            self.main_row,
            text="ℹ️",
            bg=bg_color,
            cursor="question_arrow"
        )
        self.info_btn.pack(side="left")
        
        # Создаём tooltip для информации о домене
        self.domain_tooltip = DomainInfoTooltip(
            self.info_btn,
            analysis_result.domain_info
        )
        
        # Email
        email_text = f"<{analysis_result.from_email}>"
        if len(email_text) > 35:
            email_text = email_text[:32] + "...>"
        
        self.email_label = tk.Label(
            self.main_row,
            text=email_text,
            bg=bg_color,
            fg=COLORS["text_secondary"],
            font=FONTS["small"],
            width=35,
            anchor="w"
        )
        self.email_label.pack(side="left", padx=5)
        self.email_label.bind("<Button-1>", self._toggle)
        
        # Тема письма
        subject_text = analysis_result.subject or "(без темы)"
        if len(subject_text) > 40:
            subject_text = subject_text[:37] + "..."
        
        self.subject_label = tk.Label(
            self.main_row,
            text=subject_text,
            bg=bg_color,
            fg=COLORS["text_primary"],
            font=FONTS["body"],
            anchor="w"
        )
        self.subject_label.pack(side="left", fill="x", expand=True, padx=5)
        self.subject_label.bind("<Button-1>", self._toggle)
        
        # Балл риска
        score_color = fg_color
        self.score_label = tk.Label(
            self.main_row,
            text=f"{analysis_result.total_score}",
            bg=bg_color,
            fg=score_color,
            font=FONTS["body_bold"],
            width=5
        )
        self.score_label.pack(side="right", padx=10)
        
        # Детали (скрыты по умолчанию)
        self.details_frame = tk.Frame(self, bg=COLORS["bg_dark"])
        self._create_details()
    
    def _create_details(self):
        """Создать детальную информацию"""
        if not self.analysis_result.all_issues:
            no_issues = tk.Label(
                self.details_frame,
                text="Проблем не обнаружено",
                bg=COLORS["bg_dark"],
                fg=COLORS["safe"],
                font=FONTS["body"]
            )
            no_issues.pack(pady=10)
            return
        
        # Группируем по категориям
        categories = {
            "sender": ("👤 Отправитель", []),
            "headers": ("📋 Заголовки", []),
            "body": ("📝 Содержимое", []),
            "attachments": ("📎 Вложения", [])
        }
        
        for issue in self.analysis_result.all_issues:
            cat = issue.category
            if cat in categories:
                categories[cat][1].append(issue)
        
        for cat_key, (cat_name, issues) in categories.items():
            if not issues:
                continue
            
            # Заголовок категории
            cat_frame = tk.Frame(self.details_frame, bg=COLORS["bg_dark"])
            cat_frame.pack(fill="x", padx=10, pady=5)
            
            cat_label = tk.Label(
                cat_frame,
                text=cat_name,
                bg=COLORS["bg_dark"],
                fg=COLORS["text_primary"],
                font=FONTS["body_bold"]
            )
            cat_label.pack(anchor="w")
            
            # Проблемы
            for issue in issues:
                issue_frame = tk.Frame(cat_frame, bg=COLORS["bg_dark"])
                issue_frame.pack(fill="x", padx=20, pady=2)
                
                severity_color = get_severity_color(issue.severity)
                severity_icons = {
                    "low": "ℹ️",
                    "medium": "⚠️",
                    "high": "🔶",
                    "critical": "🔴"
                }
                
                icon = severity_icons.get(issue.severity, "•")
                
                msg_label = tk.Label(
                    issue_frame,
                    text=f"{icon} {issue.message}",
                    bg=COLORS["bg_dark"],
                    fg=severity_color,
                    font=FONTS["body"],
                    anchor="w",
                    justify="left"
                )
                msg_label.pack(anchor="w")
                
                if issue.details:
                    detail_label = tk.Label(
                        issue_frame,
                        text=f"   └─ {issue.details}",
                        bg=COLORS["bg_dark"],
                        fg=COLORS["text_secondary"],
                        font=FONTS["small"],
                        anchor="w",
                        justify="left",
                        wraplength=700
                    )
                    detail_label.pack(anchor="w")
    
    def _toggle(self, event=None):
        if not self.analysis_result.all_issues:
            return
        
        if self.is_expanded:
            self.collapse()
        else:
            self.expand()
    
    def expand(self):
        self.details_frame.pack(fill="x", padx=20, pady=5)
        self.arrow.config(text="▼")
        self.is_expanded = True
        if self.on_expand:
            self.on_expand(self)
    
    def collapse(self):
        self.details_frame.pack_forget()
        self.arrow.config(text="▶")
        self.is_expanded = False


class AccountCard(tk.Frame):
    """Карточка аккаунта"""
    
    def __init__(self, parent, account, on_toggle: Callable = None, on_remove: Callable = None):
        super().__init__(parent, bg=COLORS["bg_light"], padx=10, pady=10)
        
        self.account = account
        self.on_toggle = on_toggle
        self.on_remove = on_remove
        
        # Email
        email_label = tk.Label(
            self,
            text=account.email,
            bg=COLORS["bg_light"],
            fg=COLORS["text_primary"],
            font=FONTS["body_bold"]
        )
        email_label.pack(anchor="w")
        
        # Хост и настройки
        security = getattr(account, 'security', 'SSL/TLS')
        host = getattr(account, 'host', getattr(account, 'imap_host', ''))
        port = getattr(account, 'port', getattr(account, 'imap_port', 993))
        
        host_label = tk.Label(
            self,
            text=f"IMAP: {host}:{port} ({security})",
            bg=COLORS["bg_light"],
            fg=COLORS["text_secondary"],
            font=FONTS["small"]
        )
        host_label.pack(anchor="w")
        
        # Кнопки
        btn_frame = tk.Frame(self, bg=COLORS["bg_light"])
        btn_frame.pack(fill="x", pady=(10, 0))
        
        # Переключатель
        self.enabled_var = tk.BooleanVar(value=account.enabled)
        self.toggle_btn = tk.Checkbutton(
            btn_frame,
            text="Фильтрация активна",
            variable=self.enabled_var,
            command=self._on_toggle,
            bg=COLORS["bg_light"],
            fg=COLORS["text_primary"],
            selectcolor=COLORS["bg_medium"],
            activebackground=COLORS["bg_light"],
            activeforeground=COLORS["text_primary"]
        )
        self.toggle_btn.pack(side="left")
        
        # Кнопка удаления
        remove_btn = tk.Button(
            btn_frame,
            text="✕",
            command=self._on_remove,
            bg=COLORS["accent"],
            fg=COLORS["text_primary"],
            font=FONTS["body"],
            relief="flat",
            cursor="hand2",
            padx=8,
            pady=2
        )
        remove_btn.pack(side="right")
    
    def _on_toggle(self):
        self.account.enabled = self.enabled_var.get()
        if self.on_toggle:
            self.on_toggle(self.account)
    
    def _on_remove(self):
        if self.on_remove:
            self.on_remove(self.account)


class ScrollableFrame(tk.Frame):
    """Прокручиваемый фрейм"""
    
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        
        # Canvas
        self.canvas = tk.Canvas(
            self,
            bg=COLORS["bg_dark"],
            highlightthickness=0
        )
        
        # Scrollbar
        self.scrollbar = ttk.Scrollbar(
            self,
            orient="vertical",
            command=self.canvas.yview
        )
        
        # Внутренний фрейм
        self.scrollable_frame = tk.Frame(self.canvas, bg=COLORS["bg_dark"])
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        
        self.canvas_frame = self.canvas.create_window(
            (0, 0),
            window=self.scrollable_frame,
            anchor="nw"
        )
        
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        
        # Привязка прокрутки колёсиком
        self.canvas.bind("<Enter>", self._bind_mousewheel)
        self.canvas.bind("<Leave>", self._unbind_mousewheel)
        
        # Упаковка
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        
        # Обновление ширины
        self.canvas.bind("<Configure>", self._on_canvas_configure)
    
    def _on_canvas_configure(self, event):
        self.canvas.itemconfig(self.canvas_frame, width=event.width)
    
    def _bind_mousewheel(self, event):
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
    
    def _unbind_mousewheel(self, event):
        self.canvas.unbind_all("<MouseWheel>")
    
    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
    
    def get_frame(self) -> tk.Frame:
        return self.scrollable_frame
    
    def scroll_to_bottom(self):
        self.canvas.update_idletasks()
        self.canvas.yview_moveto(1.0)

