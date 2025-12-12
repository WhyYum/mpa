# -*- coding: utf-8 -*-
"""
Виджет просмотра логов анализа
"""

import tkinter as tk
from tkinter import ttk
from typing import List, Optional, Callable
from datetime import datetime

from .styles import COLORS, FONTS
from analyzer import AnalysisResult, CheckResult, CheckStatus


class LogItem(tk.Frame):
  """Элемент лога - одно проанализированное письмо"""
  
  STATUS_COLORS = {
    "safe": "#4CAF50",
    "low": "#8BC34A",
    "medium": "#FFC107",
    "high": "#FF9800",
    "critical": "#F44336"
  }
  
  STATUS_LABELS = {
    "safe": "Безопасно",
    "low": "Низкий риск",
    "medium": "Средний риск",
    "high": "Высокий риск",
    "critical": "Критический"
  }
  
  def __init__(self, parent, result: AnalysisResult, **kwargs):
    super().__init__(parent, bg=COLORS["bg_card"], **kwargs)
    self.result = result
    self.expanded = False
    
    self._create_widgets()
  
  def _create_widgets(self):
    """Создать виджеты"""
    # Заголовок (кликабельный)
    self.header = tk.Frame(self, bg=COLORS["bg_card"], cursor="hand2")
    self.header.pack(fill="x", padx=10, pady=8)
    self.header.bind("<Button-1>", self._toggle_expand)
    
    # Статус (цветная полоска слева)
    status_color = self.STATUS_COLORS.get(self.result.risk_level, "#666")
    self.status_bar = tk.Frame(self.header, bg=status_color, width=4)
    self.status_bar.pack(side="left", fill="y", padx=(0, 10))
    self.status_bar.bind("<Button-1>", self._toggle_expand)
    
    # Информация о письме
    info_frame = tk.Frame(self.header, bg=COLORS["bg_card"])
    info_frame.pack(side="left", fill="x", expand=True)
    info_frame.bind("<Button-1>", self._toggle_expand)
    
    # Отправитель и тема
    sender_text = f"{self.result.from_name} <{self.result.from_email}>" if self.result.from_name else self.result.from_email
    self.sender_label = tk.Label(
      info_frame,
      text=sender_text[:60] + "..." if len(sender_text) > 60 else sender_text,
      bg=COLORS["bg_card"],
      fg=COLORS["text_white"],
      font=FONTS["normal"],
      anchor="w"
    )
    self.sender_label.pack(anchor="w")
    self.sender_label.bind("<Button-1>", self._toggle_expand)
    
    subject_text = self.result.subject or "(без темы)"
    self.subject_label = tk.Label(
      info_frame,
      text=subject_text[:70] + "..." if len(subject_text) > 70 else subject_text,
      bg=COLORS["bg_card"],
      fg=COLORS["text_secondary"],
      font=FONTS["small"],
      anchor="w"
    )
    self.subject_label.pack(anchor="w")
    self.subject_label.bind("<Button-1>", self._toggle_expand)
    
    # Правая часть - оценка и дата
    right_frame = tk.Frame(self.header, bg=COLORS["bg_card"])
    right_frame.pack(side="right")
    right_frame.bind("<Button-1>", self._toggle_expand)
    
    # Оценка
    score_text = f"{self.result.total_score:.1f}/10"
    self.score_label = tk.Label(
      right_frame,
      text=score_text,
      bg=COLORS["bg_card"],
      fg=status_color,
      font=FONTS["title"]
    )
    self.score_label.pack(anchor="e")
    self.score_label.bind("<Button-1>", self._toggle_expand)
    
    # Дата
    date_text = self.result.analyzed_at.strftime("%d.%m.%Y %H:%M") if self.result.analyzed_at else ""
    self.date_label = tk.Label(
      right_frame,
      text=date_text,
      bg=COLORS["bg_card"],
      fg=COLORS["text_muted"],
      font=FONTS["small"]
    )
    self.date_label.pack(anchor="e")
    self.date_label.bind("<Button-1>", self._toggle_expand)
    
    # Стрелка
    self.arrow_label = tk.Label(
      self.header,
      text=">",
      bg=COLORS["bg_card"],
      fg=COLORS["text_secondary"],
      font=FONTS["small"]
    )
    self.arrow_label.pack(side="right", padx=(10, 0))
    self.arrow_label.bind("<Button-1>", self._toggle_expand)
    
    # Контент (скрыт по умолчанию)
    self.content_frame = tk.Frame(self, bg=COLORS["bg_dark"])
    
    # Метки спам/фишинг
    if self.result.is_spam or self.result.is_phishing:
      tags_frame = tk.Frame(self.content_frame, bg=COLORS["bg_dark"])
      tags_frame.pack(fill="x", padx=10, pady=(5, 0))
      
      if self.result.is_spam:
        spam_tag = tk.Label(
          tags_frame,
          text="СПАМ",
          bg="#F44336",
          fg="white",
          font=FONTS["small"],
          padx=8,
          pady=2
        )
        spam_tag.pack(side="left", padx=(0, 5))
      
      if self.result.is_phishing:
        phishing_tag = tk.Label(
          tags_frame,
          text="ФИШИНГ",
          bg="#FF9800",
          fg="white",
          font=FONTS["small"],
          padx=8,
          pady=2
        )
        phishing_tag.pack(side="left")
    
    # Результаты проверок
    self._create_checks_list()
    
    # Разделитель
    separator = tk.Frame(self, bg=COLORS["border"], height=1)
    separator.pack(fill="x", pady=(8, 0))
  
  def _create_checks_list(self):
    """Создать список проверок"""
    checks_frame = tk.Frame(self.content_frame, bg=COLORS["bg_dark"])
    checks_frame.pack(fill="x", padx=10, pady=10)
    
    for check in self.result.checks:
      check_item = CheckItem(checks_frame, check)
      check_item.pack(fill="x", pady=2)
  
  def _toggle_expand(self, event=None):
    """Развернуть/свернуть детали"""
    self.expanded = not self.expanded
    
    if self.expanded:
      self.content_frame.pack(fill="x")
      self.arrow_label.config(text="v")
    else:
      self.content_frame.pack_forget()
      self.arrow_label.config(text=">")


class CheckItem(tk.Frame):
  """Элемент проверки"""
  
  STATUS_ICONS = {
    CheckStatus.PASS: ("+", "#4CAF50"),
    CheckStatus.WARN: ("!", "#FFC107"),
    CheckStatus.FAIL: ("x", "#F44336"),
    CheckStatus.INFO: ("i", "#2196F3"),
    CheckStatus.ERROR: ("?", "#9E9E9E")
  }
  
  def __init__(self, parent, check: CheckResult, **kwargs):
    super().__init__(parent, bg=COLORS["bg_dark"], **kwargs)
    self.check = check
    self.expanded = False
    self.text_labels = []  # Для обновления wraplength
    
    self._create_widgets()
    self.bind("<Configure>", self._on_configure)
  
  def _create_widgets(self):
    """Создать виджеты"""
    # Строка проверки
    row = tk.Frame(self, bg=COLORS["bg_dark"])
    row.pack(fill="x")
    
    # Иконка статуса
    icon, color = self.STATUS_ICONS.get(self.check.status, ("?", "#666"))
    status_label = tk.Label(
      row,
      text=f"[{icon}]",
      bg=COLORS["bg_dark"],
      fg=color,
      font=FONTS["small"],
      width=4
    )
    status_label.pack(side="left")
    
    # Название и описание
    title_label = tk.Label(
      row,
      text=self.check.title,
      bg=COLORS["bg_dark"],
      fg=COLORS["text_white"],
      font=FONTS["small"],
      anchor="w"
    )
    title_label.pack(side="left", fill="x", expand=True)
    
    # Баллы
    if self.check.score != 0:
      score_text = f"{self.check.score:+.1f}"
      score_color = "#4CAF50" if self.check.score > 0 else "#F44336"
      score_label = tk.Label(
        row,
        text=score_text,
        bg=COLORS["bg_dark"],
        fg=score_color,
        font=FONTS["small"]
      )
      score_label.pack(side="right")
    
    # Стрелка (если есть детали)
    if self.check.details or self.check.description:
      self.arrow = tk.Label(
        row,
        text=">",
        bg=COLORS["bg_dark"],
        fg=COLORS["text_muted"],
        font=FONTS["small"],
        cursor="hand2"
      )
      self.arrow.pack(side="right", padx=(5, 0))
      
      # Кликабельность
      row.bind("<Button-1>", self._toggle_details)
      title_label.bind("<Button-1>", self._toggle_details)
      self.arrow.bind("<Button-1>", self._toggle_details)
      row.config(cursor="hand2")
      title_label.config(cursor="hand2")
    
    # Детали (скрыты)
    self.details_frame = tk.Frame(self, bg=COLORS["bg_card"], padx=20, pady=5)
    
    if self.check.description:
      desc_label = tk.Label(
        self.details_frame,
        text=self.check.description,
        bg=COLORS["bg_card"],
        fg=COLORS["text_secondary"],
        font=FONTS["small"],
        anchor="w",
        wraplength=1,  # Будет обновлено
        justify="left"
      )
      desc_label.pack(anchor="w", fill="x")
      self.text_labels.append(desc_label)
    
    if self.check.details:
      details_text = self._format_details(self.check.details)
      if details_text:
        details_label = tk.Label(
          self.details_frame,
          text=details_text,
          bg=COLORS["bg_card"],
          fg=COLORS["text_muted"],
          font=("Consolas", 9),
          anchor="w",
          wraplength=1,  # Будет обновлено
          justify="left"
        )
        details_label.pack(anchor="w", fill="x", pady=(5, 0))
        self.text_labels.append(details_label)
  
  def _on_configure(self, event=None):
    """При изменении размера - обновить wraplength"""
    width = self.winfo_width() - 60  # Минус отступы
    if width > 100:
      for label in self.text_labels:
        label.config(wraplength=width)
  
  def _format_details(self, details: dict, indent: int = 0) -> str:
    """Форматировать детали"""
    lines = []
    prefix = "  " * indent
    
    for key, value in details.items():
      if isinstance(value, dict):
        lines.append(f"{prefix}{key}:")
        lines.append(self._format_details(value, indent + 1))
      elif isinstance(value, list):
        if value:
          lines.append(f"{prefix}{key}: {', '.join(str(v) for v in value[:5])}")
          if len(value) > 5:
            lines.append(f"{prefix}  ... и ещё {len(value) - 5}")
      else:
        lines.append(f"{prefix}{key}: {value}")
    
    return "\n".join(lines)
  
  def _toggle_details(self, event=None):
    """Показать/скрыть детали"""
    self.expanded = not self.expanded
    
    if self.expanded:
      self.details_frame.pack(fill="x")
      self.arrow.config(text="v")
      # Обновляем wraplength после показа
      self.after(10, self._on_configure)
    else:
      self.details_frame.pack_forget()
      self.arrow.config(text=">")


class LogViewer(tk.Frame):
  """Просмотрщик логов анализа"""
  
  def __init__(self, parent, **kwargs):
    super().__init__(parent, bg=COLORS["bg_dark"], **kwargs)
    
    self.logs: List[AnalysisResult] = []
    self._create_widgets()
  
  def _create_widgets(self):
    """Создать виджеты"""
    # Заголовок
    header = tk.Frame(self, bg=COLORS["bg_dark"])
    header.pack(fill="x", padx=15, pady=10)
    
    title = tk.Label(
      header,
      text="Журнал проверок",
      bg=COLORS["bg_dark"],
      fg=COLORS["text_white"],
      font=FONTS["title"]
    )
    title.pack(side="left")
    
    # Кнопка обновить
    self.refresh_btn = tk.Button(
      header,
      text="Обновить",
      bg=COLORS["bg_card"],
      fg=COLORS["text_white"],
      font=FONTS["small"],
      bd=0,
      padx=10,
      pady=3,
      cursor="hand2"
    )
    self.refresh_btn.pack(side="right")
    
    # Статистика
    self.stats_frame = tk.Frame(self, bg=COLORS["bg_dark"])
    self.stats_frame.pack(fill="x", padx=15, pady=(0, 10))
    
    self.stats_label = tk.Label(
      self.stats_frame,
      text="",
      bg=COLORS["bg_dark"],
      fg=COLORS["text_secondary"],
      font=FONTS["small"]
    )
    self.stats_label.pack(side="left")
    
    # Скроллируемая область
    self.canvas = tk.Canvas(self, bg=COLORS["bg_dark"], highlightthickness=0)
    self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
    
    self.scroll_frame = tk.Frame(self.canvas, bg=COLORS["bg_dark"])
    self.scroll_frame.bind(
      "<Configure>",
      lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
    )
    
    self.canvas_window = self.canvas.create_window((0, 0), window=self.scroll_frame, anchor="nw")
    self.canvas.configure(yscrollcommand=self.scrollbar.set)
    
    self.canvas.pack(side="left", fill="both", expand=True)
    self.scrollbar.pack(side="right", fill="y")
    
    # Привязка размера
    self.canvas.bind("<Configure>", self._on_canvas_configure)
    
    # Привязка колеса мыши при входе/выходе из области
    self.canvas.bind("<Enter>", self._bind_mousewheel)
    self.canvas.bind("<Leave>", self._unbind_mousewheel)
    self.scroll_frame.bind("<Enter>", self._bind_mousewheel)
    self.scroll_frame.bind("<Leave>", self._unbind_mousewheel)
    
    # Placeholder
    self.placeholder = tk.Label(
      self.scroll_frame,
      text="Нет записей в журнале\n\nЗапустите проверку писем,\nчтобы увидеть результаты",
      bg=COLORS["bg_dark"],
      fg=COLORS["text_muted"],
      font=FONTS["normal"],
      justify="center"
    )
  
  def _on_canvas_configure(self, event):
    """При изменении размера canvas"""
    self.canvas.itemconfig(self.canvas_window, width=event.width)
  
  def _bind_mousewheel(self, event=None):
    """Привязать скролл при входе мыши"""
    self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
    # Для Linux
    self.canvas.bind_all("<Button-4>", self._on_mousewheel_linux)
    self.canvas.bind_all("<Button-5>", self._on_mousewheel_linux)
  
  def _unbind_mousewheel(self, event=None):
    """Отвязать скролл при выходе мыши"""
    self.canvas.unbind_all("<MouseWheel>")
    self.canvas.unbind_all("<Button-4>")
    self.canvas.unbind_all("<Button-5>")
  
  def _on_mousewheel(self, event):
    """Скролл колесом мыши (Windows/macOS)"""
    self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
  
  def _on_mousewheel_linux(self, event):
    """Скролл колесом мыши (Linux)"""
    if event.num == 4:
      self.canvas.yview_scroll(-1, "units")
    elif event.num == 5:
      self.canvas.yview_scroll(1, "units")
  
  def set_logs(self, logs: List[AnalysisResult]):
    """Установить логи для отображения"""
    self.logs = logs
    self._render_logs()
  
  def _render_logs(self):
    """Отрисовать логи"""
    # Очищаем
    for widget in self.scroll_frame.winfo_children():
      widget.destroy()
    
    if not self.logs:
      self.placeholder = tk.Label(
        self.scroll_frame,
        text="Нет записей в журнале\n\nЗапустите проверку писем,\nчтобы увидеть результаты",
        bg=COLORS["bg_dark"],
        fg=COLORS["text_muted"],
        font=FONTS["normal"],
        justify="center"
      )
      self.placeholder.pack(expand=True, pady=50)
      self.stats_label.config(text="")
      return
    
    # Отрисовываем логи
    for log in self.logs:
      item = LogItem(self.scroll_frame, log)
      item.pack(fill="x", pady=1)
    
    # Обновляем статистику
    self._update_stats()
  
  def add_log(self, result: AnalysisResult):
    """Добавить лог без пересоздания существующих"""
    self.logs.insert(0, result)  # Новые сверху
    
    # Удаляем placeholder если есть
    for widget in self.scroll_frame.winfo_children():
      if isinstance(widget, tk.Label):
        widget.destroy()
        break
    
    # Получаем существующие LogItem ДО создания нового
    existing_items = [w for w in self.scroll_frame.winfo_children() if isinstance(w, LogItem) and w.winfo_ismapped()]
    
    # Создаём новый элемент
    item = LogItem(self.scroll_frame, result)
    
    # Размещаем новый элемент первым
    if existing_items:
      item.pack(fill="x", pady=1, before=existing_items[0])
    else:
      item.pack(fill="x", pady=1)
    
    # Обновляем статистику
    self._update_stats()
  
  def _update_stats(self):
    """Обновить статистику"""
    if not self.logs:
      self.stats_label.config(text="")
      return
    
    safe = sum(1 for l in self.logs if l.risk_level == "safe")
    warnings = sum(1 for l in self.logs if l.risk_level in ["low", "medium"])
    dangerous = sum(1 for l in self.logs if l.risk_level in ["high", "critical"])
    spam = sum(1 for l in self.logs if l.is_spam)
    phishing = sum(1 for l in self.logs if l.is_phishing)
    
    stats_text = f"Всего: {len(self.logs)} | Безопасных: {safe} | Подозрительных: {warnings} | Опасных: {dangerous}"
    if spam or phishing:
      stats_text += f" | Спам: {spam} | Фишинг: {phishing}"
    self.stats_label.config(text=stats_text)
  
  def clear(self):
    """Очистить логи"""
    self.logs = []
    self._render_logs()

