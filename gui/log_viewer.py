# -*- coding: utf-8 -*-
"""
Виджет просмотра логов анализа с пагинацией
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
  """Просмотрщик логов анализа с пагинацией"""
  
  # Варианты количества элементов на странице
  PAGE_SIZE_OPTIONS = [5, 10, 15, 25]
  
  def __init__(self, parent, **kwargs):
    super().__init__(parent, bg=COLORS["bg_dark"], **kwargs)
    
    self.logs: List[AnalysisResult] = []
    self._is_loading = False
    
    # Пагинация
    self._page_size = 10  # Элементов на странице
    self._current_page = 0  # Текущая страница (0-based)
    
    self._create_widgets()
  
  def _create_widgets(self):
    """Создать виджеты"""
    # === Заголовок ===
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
    
    # === Статистика ===
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
    
    # === Основная область со скроллом ===
    self.content_container = tk.Frame(self, bg=COLORS["bg_dark"])
    self.content_container.pack(fill="both", expand=True)
    
    self.canvas = tk.Canvas(self.content_container, bg=COLORS["bg_dark"], highlightthickness=0)
    self.scrollbar = ttk.Scrollbar(self.content_container, orient="vertical", command=self.canvas.yview)
    
    self.scroll_frame = tk.Frame(self.canvas, bg=COLORS["bg_dark"])
    self.scroll_frame.bind(
      "<Configure>",
      lambda e: self._update_scroll_region()
    )
    
    self.canvas_window = self.canvas.create_window((0, 0), window=self.scroll_frame, anchor="nw")
    self.canvas.configure(yscrollcommand=self.scrollbar.set)
    
    self.canvas.pack(side="left", fill="both", expand=True)
    self.scrollbar.pack(side="right", fill="y")
    
    # Привязка размера
    self.canvas.bind("<Configure>", self._on_canvas_configure)
    
    # Привязка колеса мыши
    self.canvas.bind("<Enter>", self._bind_mousewheel)
    self.canvas.bind("<Leave>", self._unbind_mousewheel)
    self.scroll_frame.bind("<Enter>", self._bind_mousewheel)
    self.scroll_frame.bind("<Leave>", self._unbind_mousewheel)
    
    # === Статичная панель пагинации снизу ===
    self._create_pagination_panel()
  
  def _create_pagination_panel(self):
    """Создать статичную панель пагинации"""
    self.pagination_frame = tk.Frame(self, bg=COLORS["bg_medium"], height=45)
    self.pagination_frame.pack(fill="x", side="bottom")
    self.pagination_frame.pack_propagate(False)
    
    # Внутренний контейнер для центрирования
    inner = tk.Frame(self.pagination_frame, bg=COLORS["bg_medium"])
    inner.pack(expand=True)
    
    # Выбор количества на странице
    size_frame = tk.Frame(inner, bg=COLORS["bg_medium"])
    size_frame.pack(side="left", padx=(0, 20))
    
    size_label = tk.Label(
      size_frame,
      text="Показать:",
      bg=COLORS["bg_medium"],
      fg=COLORS["text_secondary"],
      font=FONTS["small"]
    )
    size_label.pack(side="left", padx=(0, 5))
    
    self.page_size_var = tk.StringVar(value=str(self._page_size))
    self.page_size_combo = ttk.Combobox(
      size_frame,
      textvariable=self.page_size_var,
      values=[str(x) for x in self.PAGE_SIZE_OPTIONS],
      width=4,
      state="readonly"
    )
    self.page_size_combo.pack(side="left")
    self.page_size_combo.bind("<<ComboboxSelected>>", self._on_page_size_change)
    
    # Кнопки навигации
    nav_frame = tk.Frame(inner, bg=COLORS["bg_medium"])
    nav_frame.pack(side="left", padx=20)
    
    self.prev_btn = tk.Button(
      nav_frame,
      text="◀ Назад",
      command=self._prev_page,
      bg=COLORS["bg_light"],
      fg=COLORS["text_white"],
      font=FONTS["small"],
      relief="flat",
      cursor="hand2",
      padx=10,
      pady=3
    )
    self.prev_btn.pack(side="left", padx=(0, 10))
    
    self.page_label = tk.Label(
      nav_frame,
      text="1 / 1",
      bg=COLORS["bg_medium"],
      fg=COLORS["text_white"],
      font=FONTS["normal"],
      width=12
    )
    self.page_label.pack(side="left", padx=10)
    
    self.next_btn = tk.Button(
      nav_frame,
      text="Вперёд ▶",
      command=self._next_page,
      bg=COLORS["bg_light"],
      fg=COLORS["text_white"],
      font=FONTS["small"],
      relief="flat",
      cursor="hand2",
      padx=10,
      pady=3
    )
    self.next_btn.pack(side="left", padx=(10, 0))
  
  def _update_scroll_region(self):
    """Обновить scroll region и проверить нужен ли скролл"""
    self.canvas.configure(scrollregion=self.canvas.bbox("all"))
    self._check_scroll_needed()
  
  def _check_scroll_needed(self):
    """Проверить, нужен ли скроллбар"""
    self.update_idletasks()
    canvas_height = self.canvas.winfo_height()
    content_height = self.scroll_frame.winfo_reqheight()
    
    if content_height <= canvas_height:
      # Контент помещается - скрываем скроллбар
      self.scrollbar.pack_forget()
    else:
      # Нужен скролл
      if not self.scrollbar.winfo_ismapped():
        self.scrollbar.pack(side="right", fill="y")
  
  def _on_canvas_configure(self, event):
    """При изменении размера canvas"""
    self.canvas.itemconfig(self.canvas_window, width=event.width)
    self._check_scroll_needed()
  
  def show_loading(self, show: bool):
    """Показать/скрыть индикатор загрузки"""
    self._is_loading = show
    if show:
      # Очищаем и показываем индикатор
      for widget in self.scroll_frame.winfo_children():
        widget.destroy()
      loading_label = tk.Label(
        self.scroll_frame,
        text="⏳ Загрузка логов...",
        bg=COLORS["bg_dark"],
        fg=COLORS["accent"],
        font=FONTS["normal"],
        justify="center"
      )
      loading_label.pack(expand=True, pady=50)
  
  def _bind_mousewheel(self, event=None):
    """Привязать скролл при входе мыши"""
    self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
    self.canvas.bind_all("<Button-4>", self._on_mousewheel_linux)
    self.canvas.bind_all("<Button-5>", self._on_mousewheel_linux)
  
  def _unbind_mousewheel(self, event=None):
    """Отвязать скролл при выходе мыши"""
    self.canvas.unbind_all("<MouseWheel>")
    self.canvas.unbind_all("<Button-4>")
    self.canvas.unbind_all("<Button-5>")
  
  def _on_mousewheel(self, event):
    """Скролл колесом мыши (Windows/macOS)"""
    # Проверяем нужен ли скролл
    canvas_height = self.canvas.winfo_height()
    content_height = self.scroll_frame.winfo_reqheight()
    if content_height > canvas_height:
      self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
  
  def _on_mousewheel_linux(self, event):
    """Скролл колесом мыши (Linux)"""
    canvas_height = self.canvas.winfo_height()
    content_height = self.scroll_frame.winfo_reqheight()
    if content_height > canvas_height:
      if event.num == 4:
        self.canvas.yview_scroll(-1, "units")
      elif event.num == 5:
        self.canvas.yview_scroll(1, "units")
  
  def set_logs(self, logs: List[AnalysisResult]):
    """Установить логи для отображения"""
    self.logs = logs
    self._current_page = 0
    self._render_current_page()
    self._update_stats()
  
  def _get_total_pages(self) -> int:
    """Получить общее количество страниц"""
    if not self.logs:
      return 1
    return max(1, (len(self.logs) + self._page_size - 1) // self._page_size)
  
  def _get_page_logs(self) -> List[AnalysisResult]:
    """Получить логи для текущей страницы"""
    start_idx = self._current_page * self._page_size
    end_idx = start_idx + self._page_size
    return self.logs[start_idx:end_idx]
  
  def _render_current_page(self):
    """Отрисовать текущую страницу логов"""
    # Очищаем
    for widget in self.scroll_frame.winfo_children():
      widget.destroy()
    
    page_logs = self._get_page_logs()
    
    if not page_logs:
      placeholder = tk.Label(
        self.scroll_frame,
        text="Нет записей в журнале\n\nЗапустите проверку писем,\nчтобы увидеть результаты",
        bg=COLORS["bg_dark"],
        fg=COLORS["text_muted"],
        font=FONTS["normal"],
        justify="center"
      )
      placeholder.pack(expand=True, pady=50)
    else:
      # Отрисовываем логи текущей страницы
      for log in page_logs:
        item = LogItem(self.scroll_frame, log)
        item.pack(fill="x", pady=1)
    
    # Обновляем пагинацию
    self._update_pagination()
    
    # Скроллим наверх
    self.canvas.yview_moveto(0)
    
    # Проверяем скролл
    self.after(50, self._check_scroll_needed)
  
  def _update_pagination(self):
    """Обновить элементы пагинации"""
    total_pages = self._get_total_pages()
    current = self._current_page + 1
    
    self.page_label.config(text=f"{current} / {total_pages}")
    
    # Состояние кнопок
    if self._current_page <= 0:
      self.prev_btn.config(state="disabled", bg=COLORS["bg_dark"])
    else:
      self.prev_btn.config(state="normal", bg=COLORS["bg_light"])
    
    if self._current_page >= total_pages - 1:
      self.next_btn.config(state="disabled", bg=COLORS["bg_dark"])
    else:
      self.next_btn.config(state="normal", bg=COLORS["bg_light"])
  
  def _prev_page(self):
    """Предыдущая страница"""
    if self._current_page > 0:
      self._current_page -= 1
      self._render_current_page()
  
  def _next_page(self):
    """Следующая страница"""
    if self._current_page < self._get_total_pages() - 1:
      self._current_page += 1
      self._render_current_page()
  
  def _on_page_size_change(self, event=None):
    """Изменение количества элементов на странице"""
    try:
      new_size = int(self.page_size_var.get())
      if new_size in self.PAGE_SIZE_OPTIONS:
        self._page_size = new_size
        self._current_page = 0
        self._render_current_page()
    except ValueError:
      pass
  
  def add_log(self, result: AnalysisResult):
    """Добавить лог"""
    self.logs.insert(0, result)  # Новые сверху
    
    # Если на первой странице - перерисовываем
    if self._current_page == 0:
      self._render_current_page()
    else:
      # Просто обновляем пагинацию
      self._update_pagination()
    
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
    self._current_page = 0
    self._render_current_page()
