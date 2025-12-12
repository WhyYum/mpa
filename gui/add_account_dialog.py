# -*- coding: utf-8 -*-
"""
Диалог добавления аккаунта с автоопределением настроек (как в Thunderbird)
"""

import tkinter as tk
from tkinter import ttk
from typing import Optional, Dict, List
import threading
import json
import os

try:
  import dns.resolver
  HAS_DNS = True
except ImportError:
  HAS_DNS = False

from .styles import COLORS, FONTS, PADDING
from .widgets import StyledEntry, StyledButton, StyledLabel, StatusLabel, bind_clipboard_hotkeys
from config import EmailAccount, IMAP_HOSTS, DEFAULT_PORTS, SECURITY_TYPES, DATA_DIR
from imap_client import IMAPClient

WINDOW_SIZE = [530, 340, 510]


def load_error_messages() -> Dict:
  """Загрузить сообщения об ошибках из JSON"""
  path = os.path.join(DATA_DIR, "error_messages.json")
  try:
    with open(path, "r", encoding="utf-8") as f:
      return json.load(f)
  except Exception:
    return {"imap_errors": {}, "default_error": "Ошибка подключения", "unknown_error": "Ошибка"}


ERROR_MESSAGES = load_error_messages()


def get_mx_domain(domain: str) -> Optional[str]:
  """Получить домен почтового сервера из MX записи"""
  print(HAS_DNS)
  if not HAS_DNS:
    return None
  
  try:
    mx_records = dns.resolver.resolve(domain, 'MX')
    print(mx_records)
    
    # Берём MX с наивысшим приоритетом (наименьшее число)
    best_mx = min(mx_records, key=lambda x: x.preference)
    print(best_mx)
    mx_host = str(best_mx.exchange).rstrip('.')
    print(mx_host)
    
    # Извлекаем базовый домен (mx1.mail.ru -> mail.ru)
    parts = mx_host.split('.')
    if len(parts) >= 2:
      return '.'.join(parts[-2:])
    return mx_host
  except Exception as e:
    print(e.with_traceback())
    return None


class AddAccountDialog(tk.Toplevel):
  """Диалог добавления почтового аккаунта"""
  
  def __init__(self, parent, on_success=None):
    super().__init__(parent)
    
    self.title("Добавить почтовый аккаунт")
    self.configure(bg=COLORS["bg_dark"])
    self.resizable(False, False)
    
    self.on_success = on_success
    self.result: Optional[EmailAccount] = None
    self.is_checking = False
    self.show_manual = False
    
    # Размеры окна
    self.geometry(f"{WINDOW_SIZE[0]}x{WINDOW_SIZE[1]}")
    
    # Модальное окно
    self.transient(parent)
    self.grab_set()
    
    self._create_widgets()
    self._center_window(parent)
  
  def _center_window(self, parent):
    """Центрировать окно"""
    self.update_idletasks()
    x = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
    y = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
    self.geometry(f"+{x}+{y}")
  
  def _create_widgets(self):
    """Создать виджеты"""
    # Контейнер
    self.container = tk.Frame(self, bg=COLORS["bg_dark"], padx=25, pady=20)
    self.container.pack(fill="both", expand=True)
    
    # Заголовок
    title = tk.Label(
      self.container,
      text="Добавить почтовый ящик",
      bg=COLORS["bg_dark"],
      fg=COLORS["text_white"],
      font=FONTS["title"]
    )
    title.pack(anchor="w", pady=(0, 15))
    
    # === Основные поля ===
    self.main_frame = tk.Frame(self.container, bg=COLORS["bg_dark"])
    self.main_frame.pack(fill="x")
    
    # Email
    StyledLabel(self.main_frame, "Адрес электронной почты").pack(anchor="w", pady=(0, 3))
    self.email_entry = StyledEntry(self.main_frame, placeholder="example@mail.ru")
    self.email_entry.pack(fill="x", ipady=6, pady=(0, 10))
    
    # Пароль
    StyledLabel(self.main_frame, "Пароль").pack(anchor="w", pady=(0, 3))
    self.password_entry = StyledEntry(self.main_frame, show="•")
    self.password_entry.pack(fill="x", ipady=6, pady=(0, 5))
    
    # Подсказка
    StyledLabel(
      self.main_frame, 
      "Для Gmail/Yandex используйте пароль приложения",
      style="muted"
    ).pack(anchor="w", pady=(0, 10))
    
    # === Ручные настройки (скрыты по умолчанию) ===
    self.manual_frame = tk.Frame(self.container, bg=COLORS["bg_dark"])
    
    # Разделитель
    self.separator = tk.Frame(self.manual_frame, bg=COLORS["border"], height=1)
    self.separator.pack(fill="x", pady=(5, 15))
    
    # Заголовок ручных настроек
    manual_title = tk.Label(
      self.manual_frame,
      text="Настройки сервера входящей почты (IMAP)",
      bg=COLORS["bg_dark"],
      fg=COLORS["text_secondary"],
      font=FONTS["small"]
    )
    manual_title.pack(anchor="w", pady=(0, 10))
    
    # Строка: Сервер + Порт
    server_row = tk.Frame(self.manual_frame, bg=COLORS["bg_dark"])
    server_row.pack(fill="x", pady=(0, 10))
    
    # Сервер
    server_frame = tk.Frame(server_row, bg=COLORS["bg_dark"])
    server_frame.pack(side="left", fill="x", expand=True, padx=(0, 10))
    
    StyledLabel(server_frame, "Имя сервера:", style="small").pack(anchor="w")
    self.host_entry = StyledEntry(server_frame)
    self.host_entry.pack(fill="x", ipady=4)
    
    # Порт
    port_frame = tk.Frame(server_row, bg=COLORS["bg_dark"])
    port_frame.pack(side="right")
    
    StyledLabel(port_frame, "Порт:", style="small").pack(anchor="w")
    self.port_entry = StyledEntry(port_frame, width=10)
    self.port_entry.insert(0, "993")
    self.port_entry.pack(ipady=4, fill="x")
    
    # Защита соединения
    security_frame = tk.Frame(self.manual_frame, bg=COLORS["bg_dark"])
    security_frame.pack(fill="x", pady=(0, 10))
    
    StyledLabel(security_frame, "Защита соединения:", style="small").pack(anchor="w")
    self.security_var = tk.StringVar(value="SSL/TLS")
    self.security_combo = ttk.Combobox(
      security_frame,
      textvariable=self.security_var,
      values=SECURITY_TYPES,
      state="readonly",
      width=15
    )
    self.security_combo.pack(anchor="w", pady=(3, 0))
    self.security_combo.bind("<<ComboboxSelected>>", self._on_security_change)
    
    # === Статус ===
    self.status_label = StatusLabel(self.container)
    self.status_label.pack(fill="x", pady=(10, 0))
    
    # === Кнопки ===
    self.btn_frame = tk.Frame(self.container, bg=COLORS["bg_dark"])
    self.btn_frame.pack(fill="x", pady=(15, 0))
    
    # Ссылка "Настроить вручную"
    self.manual_link = tk.Label(
      self.btn_frame,
      text="Настроить вручную",
      bg=COLORS["bg_dark"],
      fg=COLORS["accent"],
      font=FONTS["small"],
      cursor="hand2"
    )
    self.manual_link.pack(side="left")
    self.manual_link.bind("<Button-1>", lambda e: self._toggle_manual())
    self.manual_link.bind("<Enter>", lambda e: self.manual_link.config(fg=COLORS["accent_hover"]))
    self.manual_link.bind("<Leave>", lambda e: self.manual_link.config(fg=COLORS["accent"]))
    
    # Кнопка отмены
    self.cancel_btn = StyledButton(
      self.btn_frame,
      text="Отмена",
      command=self.destroy,
      style="secondary",
    )
    self.cancel_btn.pack(side="right", padx=(10, 0))
    
    # Кнопка продолжить
    self.continue_btn = StyledButton(
      self.btn_frame,
      text="Продолжить",
      command=self._on_continue,
      style="primary"
    )
    self.continue_btn.pack(side="right")
    
    # Кнопка остановить (скрыта)
    self.stop_btn = StyledButton(
      self.btn_frame,
      text="Остановить",
      command=self._stop_check,
      style="secondary"
    )
  
  def _toggle_manual(self):
    """Показать/скрыть ручные настройки"""
    self.show_manual = not self.show_manual
    
    if self.show_manual:
      self.manual_frame.pack(fill="x", after=self.main_frame)
      self.manual_link.config(text="Скрыть настройки")
      self.geometry(f"{WINDOW_SIZE[0]}x{WINDOW_SIZE[2]}")
      self._auto_fill_host()
    else:
      self.manual_frame.pack_forget()
      self.manual_link.config(text="Настроить вручную")
      self.geometry(f"{WINDOW_SIZE[0]}x{WINDOW_SIZE[1]}")
  
  def _auto_fill_host(self):
    """Автозаполнение хоста по email"""
    email = self.email_entry.get_value()
    if "@" in email:
      domain = email.split("@")[-1].lower()
      host = IMAP_HOSTS.get(domain, f"imap.{domain}")
      self.host_entry.delete(0, "end")
      self.host_entry.insert(0, host)
  
  def _on_security_change(self, event=None):
    """Изменение типа защиты - обновить порт"""
    security = self.security_var.get()
    sec_key = {"SSL/TLS": "ssl", "STARTTLS": "starttls", "Нет": "none"}.get(security, "ssl")
    port = DEFAULT_PORTS.get(sec_key, 993)
    self.port_entry.delete(0, "end")
    self.port_entry.insert(0, str(port))
  
  def _on_continue(self):
    """Нажатие кнопки Продолжить"""
    email = self.email_entry.get_value()
    password = self.password_entry.get()
    
    # Валидация
    if not email:
      self.status_label.set_error("Введите email")
      return
    
    if "@" not in email:
      self.status_label.set_error("Некорректный email")
      return
    
    if not password:
      self.status_label.set_error("Введите пароль")
      return
    
    if self.show_manual:
      # Ручной режим - сразу пробуем подключиться
      self._try_connect_manual()
    else:
      # Автоматический режим - пробуем определить настройки
      self._try_auto_detect()
  
  def _try_auto_detect(self):
    """Попытка автоматического определения настроек"""
    self.is_checking = True
    self._set_loading_state(True)
    self.status_label.set_loading("Поиск конфигурации...")
    
    # Запускаем в отдельном потоке
    thread = threading.Thread(target=self._auto_detect_worker)
    thread.daemon = True
    thread.start()
  
  def _auto_detect_worker(self):
    """Рабочий поток автоопределения"""
    email = self.email_entry.get_value()
    password = self.password_entry.get()
    domain = email.split("@")[-1].lower()
    
    configs_to_try = []
    mx_domain = None  # Домен из MX записи
    
    # 1. Сначала проверяем известные хосты из базы (быстро, без DNS)
    if domain in IMAP_HOSTS:
      self.after(0, lambda: self.status_label.set_loading("Найден известный хост..."))
      configs_to_try.append({
        "host": IMAP_HOSTS[domain],
        "port": 993,
        "security": "SSL/TLS"
      })
    else:
      # 2. Домен не в базе - ищем MX запись
      self.after(0, lambda: self.status_label.set_loading("Поиск MX записи..."))
      mx_domain = get_mx_domain(domain)
      
      if mx_domain:
        # MX найден - пробуем варианты с MX
        configs_to_try = [
          {"host": f"imap.{mx_domain}", "port": 993, "security": "SSL/TLS"},
          {"host": f"mail.{mx_domain}", "port": 993, "security": "SSL/TLS"},
          {"host": mx_domain, "port": 993, "security": "SSL/TLS"},
          {"host": mx_domain, "port": 143, "security": "STARTTLS"},
        ]
      else:
        # 3. MX не найден - пробуем стандартные варианты
        configs_to_try = [
          {"host": f"imap.{domain}", "port": 993, "security": "SSL/TLS"},
          {"host": f"mail.{domain}", "port": 993, "security": "SSL/TLS"},
          {"host": f"imap.{domain}", "port": 143, "security": "STARTTLS"},
          {"host": domain, "port": 993, "security": "SSL/TLS"},
        ]
    
    # Убираем дубликаты
    seen = set()
    unique_configs = []
    for cfg in configs_to_try:
      key = (cfg["host"], cfg["port"])
      if key not in seen:
        seen.add(key)
        unique_configs.append(cfg)
    
    # Пробуем каждый вариант
    for cfg in unique_configs:
      if not self.is_checking:
        return
      
      self.after(0, lambda c=cfg: self.status_label.set_loading(
        f"Проверка {c['host']}:{c['port']}..."
      ))
      
      account = EmailAccount(
        email=email,
        password=password,
        host=cfg["host"],
        port=cfg["port"],
        security=cfg["security"]
      )
      
      client = IMAPClient(account)
      connected, error = client.connect()
      if connected:
        client.disconnect()
        # Успех!
        self.after(0, lambda a=account: self._on_connect_success(a))
        return
      
      # Если ошибка авторизации - сервер найден, но пароль неверный
      error_str = str(error).lower() if error else ""
      if "authenticationfailed" in error_str or "authentication failed" in error_str:
        self.after(0, lambda e=error, h=cfg["host"]: self._on_auth_failed(e, h))
        return
    
    # Не удалось - открываем ручные настройки с MX доменом (если был найден)
    self.after(0, lambda h=mx_domain: self._on_auto_detect_failed(h))
  
  def _on_connect_success(self, account: EmailAccount):
    """Успешное подключение"""
    self.is_checking = False
    self._set_loading_state(False)
    self.status_label.set_success(f"Подключено к {account.host}")
    
    self.result = account
    
    # Закрываем через секунду
    self.after(800, self._finish_success)
  
  def _finish_success(self):
    """Завершение с успехом"""
    if self.on_success and self.result:
      self.on_success(self.result)
    self.destroy()
  
  def _on_auto_detect_failed(self, detected_host: str = None):
    """Автоопределение не удалось"""
    self.is_checking = False
    self._set_loading_state(False)
    self.status_label.set_warning("Не удалось найти настройки автоматически")
    
    # Показываем ручные настройки с предзаполненным хостом
    if not self.show_manual:
      self._toggle_manual()
    
    # Заполняем найденный хост
    if detected_host:
      self.host_entry.delete(0, "end")
      self.host_entry.insert(0, detected_host)
  
  def _on_auth_failed(self, error, detected_host: str):
    """Ошибка авторизации - сервер найден, но пароль неверный"""
    self.is_checking = False
    self._set_loading_state(False)
    
    message = self._parse_error(error)
    self.status_label.set_error(message)
    
    # Показываем ручные настройки с найденным хостом
    if not self.show_manual:
      self._toggle_manual()
    
    # Заполняем найденный хост
    self.host_entry.delete(0, "end")
    self.host_entry.insert(0, detected_host)
  
  def _try_connect_manual(self):
    """Попытка подключения с ручными настройками"""
    email = self.email_entry.get_value()
    password = self.password_entry.get()
    host = self.host_entry.get().strip()
    
    try:
      port = int(self.port_entry.get())
    except ValueError:
      self.status_label.set_error("Некорректный порт")
      return
    
    if not host:
      self.status_label.set_error("Введите адрес сервера")
      return
    
    security = self.security_var.get()
    
    self.is_checking = True
    self._set_loading_state(True)
    self.status_label.set_loading(f"Подключение к {host}...")
    
    # В отдельном потоке
    def worker():
      account = EmailAccount(
        email=email,
        password=password,
        host=host,
        port=port,
        security=security
      )
      
      client = IMAPClient(account)
      connected, error = client.connect()
      if connected:
        client.disconnect()
        self.after(0, lambda: self._on_connect_success(account))
      else:
        self.after(0, lambda: self._on_connect_failed(error))
    
    thread = threading.Thread(target=worker)
    thread.daemon = True
    thread.start()
  
  def _parse_error(self, error) -> str:
    """Преобразовать ошибку IMAP в понятное сообщение"""
    if error is None:
      return ERROR_MESSAGES.get("default_error", "Ошибка подключения")
    
    error_str = str(error).lower()
    
    for key, message in ERROR_MESSAGES.get("imap_errors", {}).items():
      if key in error_str:
        return message
    
    return f"{ERROR_MESSAGES.get('unknown_error', 'Ошибка')}: {error}"
  
  def _on_connect_failed(self, error):
    """Ошибка подключения"""
    self.is_checking = False
    self._set_loading_state(False)
    message = self._parse_error(error)
    self.status_label.set_error(message)
  
  def _stop_check(self):
    """Остановить проверку"""
    self.is_checking = False
    self._set_loading_state(False)
    self.status_label.clear()
  
  def _set_loading_state(self, loading: bool):
    """Установить состояние загрузки"""
    if loading:
      self.continue_btn.pack_forget()
      self.stop_btn.pack(side="right")
      self.email_entry.config(state="disabled")
      self.password_entry.config(state="disabled")
    else:
      self.stop_btn.pack_forget()
      self.continue_btn.pack(side="right")
      self.email_entry.config(state="normal")
      self.password_entry.config(state="normal")

