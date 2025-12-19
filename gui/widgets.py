# -*- coding: utf-8 -*-
"""
Базовые виджеты для GUI
"""

import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional
from .styles import COLORS, FONTS, PADDING


def bind_clipboard_hotkeys(entry_widget):
  """Привязать Ctrl+C/V/X/A для любой раскладки"""
  def paste(event=None):
    try:
      text = entry_widget.clipboard_get()
      try:
        entry_widget.delete("sel.first", "sel.last")
      except tk.TclError:
        pass
      entry_widget.insert("insert", text)
    except tk.TclError:
      pass
    return "break"
  
  def copy(event=None):
    try:
      text = entry_widget.selection_get()
      entry_widget.clipboard_clear()
      entry_widget.clipboard_append(text)
    except tk.TclError:
      pass
    return "break"
  
  def cut(event=None):
    try:
      text = entry_widget.selection_get()
      entry_widget.clipboard_clear()
      entry_widget.clipboard_append(text)
      entry_widget.delete("sel.first", "sel.last")
    except tk.TclError:
      pass
    return "break"
  
  def select_all(event=None):
    entry_widget.select_range(0, "end")
    entry_widget.icursor("end")
    return "break"
  
  def on_key(event):
    if event.state & 4:  # Ctrl
      if event.keycode == 86:  # V
        return paste(event)
      elif event.keycode == 67:  # C
        return copy(event)
      elif event.keycode == 88:  # X
        return cut(event)
      elif event.keycode == 65:  # A
        return select_all(event)
    return None
  
  entry_widget.bind("<Key>", on_key)


class StyledEntry(tk.Entry):
  """Стилизованное поле ввода"""
  
  def __init__(self, parent, placeholder: str = "", show: str = "", **kwargs):
    super().__init__(
      parent,
      bg=COLORS["input_bg"],
      fg=COLORS["text_primary"],
      insertbackground=COLORS["text_primary"],
      font=FONTS["body"],
      relief="flat",
      highlightthickness=1,
      highlightbackground=COLORS["border"],
      highlightcolor=COLORS["accent"],
      show=show,
      **kwargs
    )
    
    self.placeholder = placeholder
    self.showing_placeholder = False
    
    if placeholder:
      self._show_placeholder()
      self.bind("<FocusIn>", self._on_focus_in)
      self.bind("<FocusOut>", self._on_focus_out)
    
    bind_clipboard_hotkeys(self)
  
  def _show_placeholder(self):
    if not self.get():
      self.showing_placeholder = True
      self.config(fg=COLORS["text_muted"])
      self.insert(0, self.placeholder)
  
  def _on_focus_in(self, event):
    if self.showing_placeholder:
      self.delete(0, "end")
      self.config(fg=COLORS["text_primary"])
      self.showing_placeholder = False
  
  def _on_focus_out(self, event):
    if not self.get():
      self._show_placeholder()
  
  def get_value(self) -> str:
    """Получить значение (без placeholder)"""
    if self.showing_placeholder:
      return ""
    return self.get()


class StyledButton(tk.Button):
  """Стилизованная кнопка"""
  
  def __init__(self, parent, text: str, command: Callable = None, 
               style: str = "primary", **kwargs):
    
    if style == "primary":
      bg = COLORS["btn_primary"]
      hover = COLORS["btn_primary_hover"]
      fg = COLORS["text_white"]
    elif style == "secondary":
      bg = COLORS["btn_secondary"]
      hover = COLORS["btn_secondary_hover"]
      fg = COLORS["text_primary"]
    elif style == "danger":
      bg = COLORS["btn_danger"]
      hover = "#b71c1c"
      fg = COLORS["text_white"]
    else:
      bg = COLORS["btn_secondary"]
      hover = COLORS["btn_secondary_hover"]
      fg = COLORS["text_primary"]
    
    super().__init__(
      parent,
      text=text,
      command=command,
      bg=bg,
      fg=fg,
      font=FONTS["body"],
      relief="flat",
      cursor="hand2",
      padx=PADDING["large"],
      pady=PADDING["small"],
      activebackground=hover,
      activeforeground=fg,
      **kwargs
    )
    
    self._bg = bg
    self._hover = hover
    
    self.bind("<Enter>", lambda e: self.config(bg=self._hover))
    self.bind("<Leave>", lambda e: self.config(bg=self._bg))


class StyledLabel(tk.Label):
  """Стилизованная метка"""
  
  def __init__(self, parent, text: str, style: str = "body", **kwargs):
    font = FONTS.get(style, FONTS["body"])
    
    if style == "muted":
      fg = COLORS["text_muted"]
      font = FONTS["small"]
    elif style == "secondary":
      fg = COLORS["text_secondary"]
    else:
      fg = COLORS["text_primary"]
    
    super().__init__(
      parent,
      text=text,
      bg=COLORS["bg_dark"],
      fg=fg,
      font=font,
      **kwargs
    )


class StatusLabel(tk.Label):
  """Метка статуса с иконкой"""
  
  def __init__(self, parent, **kwargs):
    super().__init__(
      parent,
      bg=COLORS["bg_dark"],
      fg=COLORS["text_secondary"],
      font=FONTS["body"],
      anchor="w",
      **kwargs
    )
    self._status = "idle"
  
  def set_loading(self, text: str = "Загрузка..."):
    self._status = "loading"
    self.config(text=text, fg=COLORS["info"])
  
  def set_success(self, text: str):
    self._status = "success"
    self.config(text=text, fg=COLORS["success"])
  
  def set_error(self, text: str):
    self._status = "error"
    self.config(text=text, fg=COLORS["error"])
  
  def set_warning(self, text: str):
    self._status = "warning"
    self.config(text=text, fg=COLORS["warning"])
  
  def clear(self):
    self._status = "idle"
    self.config(text="", fg=COLORS["text_secondary"])


class AutoCheckSettingsDialog(tk.Toplevel):
  """Диалог настроек автоматической проверки"""
  
  def __init__(self, parent, account, on_save: Callable = None):
    super().__init__(parent)
    
    self.account = account
    self.on_save = on_save
    
    self.title(f"Автопроверка — {account.email}")
    self.configure(bg=COLORS["bg_dark"])
    self.resizable(False, False)
    
    # Размер и позиция
    width, height = 350, 200
    x = parent.winfo_rootx() + (parent.winfo_width() - width) // 2
    y = parent.winfo_rooty() + (parent.winfo_height() - height) // 2
    self.geometry(f"{width}x{height}+{x}+{y}")
    
    self.transient(parent)
    self.grab_set()
    
    self._create_widgets()
  
  def _create_widgets(self):
    # Основной контейнер
    main = tk.Frame(self, bg=COLORS["bg_dark"], padx=20, pady=15)
    main.pack(fill="both", expand=True)
    
    # Заголовок
    title = tk.Label(
      main,
      text="Настройки автопроверки",
      bg=COLORS["bg_dark"],
      fg=COLORS["text_white"],
      font=FONTS["subtitle"]
    )
    title.pack(anchor="w", pady=(0, 15))
    
    # Чекбокс включения
    self.auto_check_var = tk.BooleanVar(value=self.account.auto_check)
    check_frame = tk.Frame(main, bg=COLORS["bg_dark"])
    check_frame.pack(fill="x", pady=(0, 10))
    
    self.auto_check_cb = tk.Checkbutton(
      check_frame,
      text="Включить автоматическую проверку",
      variable=self.auto_check_var,
      bg=COLORS["bg_dark"],
      fg=COLORS["text_primary"],
      selectcolor=COLORS["bg_medium"],
      activebackground=COLORS["bg_dark"],
      activeforeground=COLORS["text_primary"],
      font=FONTS["body"],
      command=self._on_auto_check_changed
    )
    self.auto_check_cb.pack(side="left")
    
    # Интервал проверки
    interval_frame = tk.Frame(main, bg=COLORS["bg_dark"])
    interval_frame.pack(fill="x", pady=(0, 20))
    
    interval_label = tk.Label(
      interval_frame,
      text="Интервал проверки (секунды):",
      bg=COLORS["bg_dark"],
      fg=COLORS["text_secondary"],
      font=FONTS["body"]
    )
    interval_label.pack(side="left")
    
    self.interval_var = tk.StringVar(value=str(self.account.check_interval))
    self.interval_entry = tk.Entry(
      interval_frame,
      textvariable=self.interval_var,
      width=6,
      bg=COLORS["input_bg"],
      fg=COLORS["text_primary"],
      insertbackground=COLORS["text_primary"],
      font=FONTS["body"],
      relief="flat",
      justify="center"
    )
    self.interval_entry.pack(side="right")
    
    # Состояние поля интервала
    self._update_interval_state()
    
    # Кнопки
    btn_frame = tk.Frame(main, bg=COLORS["bg_dark"])
    btn_frame.pack(fill="x", side="bottom")
    
    save_btn = tk.Button(
      btn_frame,
      text="Сохранить",
      command=self._on_save,
      bg=COLORS["btn_primary"],
      fg=COLORS["text_white"],
      font=FONTS["body"],
      relief="flat",
      cursor="hand2",
      padx=15,
      pady=5
    )
    save_btn.pack(side="right", padx=(10, 0))
    
    cancel_btn = tk.Button(
      btn_frame,
      text="Отмена",
      command=self.destroy,
      bg=COLORS["btn_secondary"],
      fg=COLORS["text_primary"],
      font=FONTS["body"],
      relief="flat",
      cursor="hand2",
      padx=15,
      pady=5
    )
    cancel_btn.pack(side="right")
  
  def _on_auto_check_changed(self):
    """Обработчик изменения чекбокса"""
    self._update_interval_state()
  
  def _update_interval_state(self):
    """Обновить состояние поля интервала"""
    if self.auto_check_var.get():
      self.interval_entry.config(state="normal", bg=COLORS["input_bg"])
    else:
      self.interval_entry.config(state="disabled", bg=COLORS["bg_medium"])
  
  def _on_save(self):
    """Сохранить настройки"""
    try:
      interval = int(self.interval_var.get())
      if interval < 5:
        interval = 5  # Минимум 5 секунд
      elif interval > 3600:
        interval = 3600  # Максимум 1 час
    except ValueError:
      interval = 30
    
    self.account.auto_check = self.auto_check_var.get()
    self.account.check_interval = interval
    
    if self.on_save:
      self.on_save(self.account)
    
    self.destroy()


class AccountCard(tk.Frame):
  """Карточка аккаунта"""
  
  def __init__(self, parent, account, on_toggle: Callable = None, 
               on_remove: Callable = None, on_settings_changed: Callable = None):
    super().__init__(parent, bg=COLORS["bg_light"], padx=12, pady=10)
    
    self.account = account
    self.on_toggle = on_toggle
    self.on_remove = on_remove
    self.on_settings_changed = on_settings_changed
    
    self._create_widgets()
  
  def _create_widgets(self):
    # Верхняя строка: email + статусы
    top_row = tk.Frame(self, bg=COLORS["bg_light"])
    top_row.pack(fill="x")
    
    # Контейнер для статусов (справа, фиксированная ширина)
    status_frame = tk.Frame(top_row, bg=COLORS["bg_light"])
    status_frame.pack(side="right")
    
    # Статус (включен/выключен)
    status_text = "ON" if self.account.enabled else "OFF"
    status_color = COLORS["success"] if self.account.enabled else COLORS["text_muted"]
    self.status_label = tk.Label(
      status_frame,
      text=status_text,
      bg=COLORS["bg_light"],
      fg=status_color,
      font=("Segoe UI", 10, "bold")
    )
    self.status_label.pack(side="left")
    
    # Статус автопроверки
    auto_text = " ⟳" if self.account.auto_check else ""
    self.auto_label = tk.Label(
      status_frame,
      text=auto_text,
      bg=COLORS["bg_light"],
      fg=COLORS["info"],
      font=("Segoe UI", 11)
    )
    self.auto_label.pack(side="left")
    
    # Email (слева, занимает оставшееся место)
    self.email_label = tk.Label(
      top_row,
      text=self.account.email,
      bg=COLORS["bg_light"],
      fg=COLORS["text_white"],
      font=FONTS["body_bold"],
      anchor="w"
    )
    self.email_label.pack(side="left", fill="x", expand=True)
    
    # Информация о сервере
    info_text = f"{self.account.host}:{self.account.port} ({self.account.security})"
    info_label = tk.Label(
      self,
      text=info_text,
      bg=COLORS["bg_light"],
      fg=COLORS["text_secondary"],
      font=FONTS["small"],
      anchor="w"
    )
    info_label.pack(fill="x", pady=(2, 8))
    
    # Кнопки
    btn_frame = tk.Frame(self, bg=COLORS["bg_light"])
    btn_frame.pack(fill="x")
    
    # Переключатель
    toggle_text = "Выключить" if self.account.enabled else "Включить"
    self.toggle_btn = tk.Button(
      btn_frame,
      text=toggle_text,
      command=self._on_toggle,
      bg=COLORS["bg_medium"],
      fg=COLORS["text_primary"],
      font=FONTS["small"],
      relief="flat",
      cursor="hand2",
      padx=8,
      pady=2
    )
    self.toggle_btn.pack(side="left", padx=(0, 3))
    
    # Кнопка настроек (шестерёнка)
    settings_bg = COLORS["info"] if self.account.auto_check else COLORS["bg_medium"]
    settings_fg = COLORS["text_white"] if self.account.auto_check else COLORS["text_primary"]
    self.settings_btn = tk.Button(
      btn_frame,
      text="⚙",
      command=self._open_settings,
      bg=settings_bg,
      fg=settings_fg,
      font=FONTS["small"],
      relief="flat",
      cursor="hand2",
      padx=6,
      pady=2
    )
    self.settings_btn.pack(side="left", padx=(0, 3))
    
    # Удалить
    remove_btn = tk.Button(
      btn_frame,
      text="✕",
      command=self._on_remove,
      bg=COLORS["btn_danger"],
      fg=COLORS["text_white"],
      font=FONTS["small"],
      relief="flat",
      cursor="hand2",
      padx=6,
      pady=2
    )
    remove_btn.pack(side="right")
  
  def _on_toggle(self):
    self.account.enabled = not self.account.enabled
    self._update_ui()
    
    if self.on_toggle:
      self.on_toggle(self.account)
  
  def _open_settings(self):
    """Открыть диалог настроек автопроверки"""
    dialog = AutoCheckSettingsDialog(
      self.winfo_toplevel(),
      self.account,
      on_save=self._on_settings_saved
    )
  
  def _on_settings_saved(self, account):
    """Обработчик сохранения настроек"""
    self._update_ui()
    
    if self.on_settings_changed:
      self.on_settings_changed(account)
  
  def _update_ui(self):
    """Обновить UI карточки"""
    # Статус включения
    if self.account.enabled:
      self.status_label.config(text="ON", fg=COLORS["success"])
      self.toggle_btn.config(text="Выключить")
    else:
      self.status_label.config(text="OFF", fg=COLORS["text_muted"])
      self.toggle_btn.config(text="Включить")
    
    # Статус автопроверки
    if self.account.auto_check:
      self.auto_label.config(text=" ⟳")
      self.settings_btn.config(bg=COLORS["info"], fg=COLORS["text_white"])
    else:
      self.auto_label.config(text="")
      self.settings_btn.config(bg=COLORS["bg_medium"], fg=COLORS["text_primary"])
  
  def _on_remove(self):
    if self.on_remove:
      self.on_remove(self.account)


class ScrollableFrame(tk.Frame):
  """Прокручиваемый фрейм с автоматическим скрытием скроллбара"""
  
  def __init__(self, parent, **kwargs):
    super().__init__(parent, bg=COLORS["bg_dark"], **kwargs)
    
    self._scroll_enabled = False
    
    self.canvas = tk.Canvas(
      self,
      bg=COLORS["bg_dark"],
      highlightthickness=0
    )
    
    self.scrollbar = ttk.Scrollbar(
      self,
      orient="vertical",
      command=self.canvas.yview
    )
    
    self.scrollable_frame = tk.Frame(self.canvas, bg=COLORS["bg_dark"])
    
    self.scrollable_frame.bind(
      "<Configure>",
      lambda e: self._update_scroll_region()
    )
    
    self.canvas_frame = self.canvas.create_window(
      (0, 0),
      window=self.scrollable_frame,
      anchor="nw"
    )
    
    self.canvas.configure(yscrollcommand=self.scrollbar.set)
    
    self.canvas.bind("<Enter>", self._bind_mousewheel)
    self.canvas.bind("<Leave>", self._unbind_mousewheel)
    self.canvas.bind("<Configure>", self._on_canvas_configure)
    
    self.canvas.pack(side="left", fill="both", expand=True)
    # Скроллбар не показываем по умолчанию
  
  def _update_scroll_region(self):
    """Обновить scroll region и проверить нужен ли скролл"""
    self.canvas.configure(scrollregion=self.canvas.bbox("all"))
    self._check_scroll_needed()
  
  def _check_scroll_needed(self):
    """Проверить, нужен ли скроллбар"""
    self.update_idletasks()
    canvas_height = self.canvas.winfo_height()
    content_height = self.scrollable_frame.winfo_reqheight()
    
    if content_height <= canvas_height:
      # Контент помещается - скрываем скроллбар и отключаем скролл
      self._scroll_enabled = False
      if self.scrollbar.winfo_ismapped():
        self.scrollbar.pack_forget()
    else:
      # Нужен скролл
      self._scroll_enabled = True
      if not self.scrollbar.winfo_ismapped():
        self.scrollbar.pack(side="right", fill="y")
  
  def _on_canvas_configure(self, event):
    self.canvas.itemconfig(self.canvas_frame, width=event.width)
    self._check_scroll_needed()
  
  def _bind_mousewheel(self, event):
    self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
    # Для Linux
    self.canvas.bind_all("<Button-4>", self._on_mousewheel_linux)
    self.canvas.bind_all("<Button-5>", self._on_mousewheel_linux)
  
  def _unbind_mousewheel(self, event):
    self.canvas.unbind_all("<MouseWheel>")
    self.canvas.unbind_all("<Button-4>")
    self.canvas.unbind_all("<Button-5>")
  
  def _on_mousewheel(self, event):
    # Скроллим только если нужен скролл
    if self._scroll_enabled:
      self.canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
  
  def _on_mousewheel_linux(self, event):
    # Скроллим только если нужен скролл
    if self._scroll_enabled:
      if event.num == 4:
        self.canvas.yview_scroll(-1, "units")
      elif event.num == 5:
        self.canvas.yview_scroll(1, "units")
  
  def get_frame(self) -> tk.Frame:
    return self.scrollable_frame
  
  def clear(self):
    for widget in self.scrollable_frame.winfo_children():
      widget.destroy()

