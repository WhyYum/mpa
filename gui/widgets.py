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


class AccountCard(tk.Frame):
  """Карточка аккаунта"""
  
  def __init__(self, parent, account, on_toggle: Callable = None, 
               on_remove: Callable = None, on_edit: Callable = None):
    super().__init__(parent, bg=COLORS["bg_light"], padx=12, pady=10)
    
    self.account = account
    self.on_toggle = on_toggle
    self.on_remove = on_remove
    self.on_edit = on_edit
    
    self._create_widgets()
  
  def _create_widgets(self):
    # Верхняя строка: email + статус
    top_row = tk.Frame(self, bg=COLORS["bg_light"])
    top_row.pack(fill="x")
    
    # Email
    email_label = tk.Label(
      top_row,
      text=self.account.email,
      bg=COLORS["bg_light"],
      fg=COLORS["text_white"],
      font=FONTS["body_bold"]
    )
    email_label.pack(side="left")
    
    # Статус (включен/выключен)
    status_text = "[ON]" if self.account.enabled else "[OFF]"
    status_color = COLORS["success"] if self.account.enabled else COLORS["text_muted"]
    self.status_label = tk.Label(
      top_row,
      text=status_text,
      bg=COLORS["bg_light"],
      fg=status_color,
      font=("Segoe UI", 12)
    )
    self.status_label.pack(side="right")
    
    # Информация о сервере
    info_text = f"{self.account.host}:{self.account.port} ({self.account.security})"
    info_label = tk.Label(
      self,
      text=info_text,
      bg=COLORS["bg_light"],
      fg=COLORS["text_secondary"],
      font=FONTS["small"]
    )
    info_label.pack(anchor="w", pady=(2, 8))
    
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
    self.toggle_btn.pack(side="left", padx=(0, 5))
    
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
    
    # Обновляем UI
    if self.account.enabled:
      self.status_label.config(text="[ON]", fg=COLORS["success"])
      self.toggle_btn.config(text="Выключить")
    else:
      self.status_label.config(text="[OFF]", fg=COLORS["text_muted"])
      self.toggle_btn.config(text="Включить")
    
    if self.on_toggle:
      self.on_toggle(self.account)
  
  def _on_remove(self):
    if self.on_remove:
      self.on_remove(self.account)


class ScrollableFrame(tk.Frame):
  """Прокручиваемый фрейм"""
  
  def __init__(self, parent, **kwargs):
    super().__init__(parent, bg=COLORS["bg_dark"], **kwargs)
    
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
      lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
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
    self.scrollbar.pack(side="right", fill="y")
  
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
  
  def clear(self):
    for widget in self.scrollable_frame.winfo_children():
      widget.destroy()

