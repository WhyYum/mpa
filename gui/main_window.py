# -*- coding: utf-8 -*-
"""
Главное окно приложения
"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import List, Dict, Any
import threading
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from .styles import COLORS, FONTS
from .widgets import StyledButton, AccountCard, ScrollableFrame
from .add_account_dialog import AddAccountDialog
from .log_viewer import LogViewer
from core import AccountManager, EmailAccount, DATA_DIR, LOGS_DIR
from analyzer import EmailAnalyzer
from imap import IMAPClient


# Количество параллельных воркеров для анализа
MAX_WORKERS = 10


class MainWindow:
  """Главное окно приложения"""
  
  def __init__(self):
    self.root = tk.Tk()
    self.root.title("Фильтр фишинговых писем")
    self.root.geometry("1000x650")
    self.root.configure(bg=COLORS["bg_dark"])
    self.root.minsize(800, 550)
    
    # Менеджер аккаунтов
    self.account_manager = AccountManager()
    self.account_manager.load()
    
    # Анализатор писем
    os.makedirs(LOGS_DIR, exist_ok=True)
    self.analyzer = EmailAnalyzer(DATA_DIR, LOGS_DIR)
    
    # Флаг проверки
    self.is_checking = False
    
    # Создаём интерфейс
    self._create_layout()
    
    # Обновляем список аккаунтов
    self._refresh_accounts()
    
    # Загружаем логи
    self._load_logs()
  
  def _create_layout(self):
    """Создать основной layout"""
    # === Статусная строка (создаём ПЕРВОЙ, pack bottom) ===
    self.status_bar = tk.Label(
      self.root,
      text="Готов к работе",
      bg=COLORS["bg_light"],
      fg=COLORS["text_secondary"],
      font=FONTS["small"],
      anchor="w",
      padx=10,
      pady=5
    )
    self.status_bar.pack(side="bottom", fill="x")
    
    # === Левая панель (аккаунты) ===
    self.left_panel = tk.Frame(
      self.root,
      bg=COLORS["bg_medium"],
      width=300
    )
    self.left_panel.pack(side="left", fill="y")
    self.left_panel.pack_propagate(False)
    
    self._create_accounts_panel()
    
    # === Правая панель (контент) ===
    self.right_panel = tk.Frame(
      self.root,
      bg=COLORS["bg_dark"]
    )
    self.right_panel.pack(side="left", fill="both", expand=True)
    
    self._create_content_panel()
  
  def _create_accounts_panel(self):
    """Создать панель аккаунтов"""
    # Заголовок
    header = tk.Frame(self.left_panel, bg=COLORS["bg_medium"])
    header.pack(fill="x", padx=15, pady=15)
    
    title = tk.Label(
      header,
      text="Почтовые ящики",
      bg=COLORS["bg_medium"],
      fg=COLORS["text_white"],
      font=FONTS["subtitle"]
    )
    title.pack(side="left")
    
    # Кнопка добавить
    add_btn = tk.Button(
      header,
      text="+",
      command=self._add_account,
      bg=COLORS["accent"],
      fg=COLORS["text_white"],
      font=("Segoe UI", 12, "bold"),
      relief="flat",
      cursor="hand2",
      width=3,
      height=1
    )
    add_btn.pack(side="right")
    
    # Разделитель
    separator = tk.Frame(self.left_panel, bg=COLORS["border"], height=1)
    separator.pack(fill="x", padx=15)
    
    # Список аккаунтов
    self.accounts_frame = ScrollableFrame(self.left_panel)
    self.accounts_frame.pack(fill="both", expand=True, padx=10, pady=10)
  
  def _create_content_panel(self):
    """Создать панель контента"""
    # Заголовок с кнопками
    header = tk.Frame(self.right_panel, bg=COLORS["bg_dark"])
    header.pack(fill="x", padx=20, pady=15)
    
    title = tk.Label(
      header,
      text="Журнал проверки писем",
      bg=COLORS["bg_dark"],
      fg=COLORS["text_white"],
      font=FONTS["subtitle"]
    )
    title.pack(side="left")
    
    # Кнопки справа
    btns_frame = tk.Frame(header, bg=COLORS["bg_dark"])
    btns_frame.pack(side="right")
    
    # Кнопка запустить проверку
    self.check_btn = StyledButton(
      btns_frame,
      text="Проверить письма",
      command=self._start_check,
      style="primary"
    )
    self.check_btn.pack(side="left", padx=(0, 10))
    
    # Кнопка обновить логи
    refresh_btn = StyledButton(
      btns_frame,
      text="Обновить логи",
      command=self._load_logs,
      style="secondary"
    )
    refresh_btn.pack(side="left", padx=(0, 5))
    
    # Кнопка очистить
    clear_btn = StyledButton(
      btns_frame,
      text="Очистить логи",
      command=self._clear_logs,
      style="secondary"
    )
    clear_btn.pack(side="left")
    
    # Разделитель
    separator = tk.Frame(self.right_panel, bg=COLORS["border"], height=1)
    separator.pack(fill="x", padx=20)
    
    # LogViewer
    self.log_viewer = LogViewer(self.right_panel)
    self.log_viewer.pack(fill="both", expand=True)
  
  def _load_logs(self):
    """Загрузить логи из файлов"""
    logs = self.analyzer.get_logs(limit=100)
    self.log_viewer.set_logs(logs)
    self._set_status(f"Загружено {len(logs)} записей")
  
  def _start_check(self):
    """Запустить проверку писем"""
    enabled_accounts = self.account_manager.get_enabled_accounts()
    
    if not enabled_accounts:
      messagebox.showwarning(
        "Нет активных аккаунтов",
        "Добавьте почтовый ящик и включите фильтрацию"
      )
      return
    
    if self.is_checking:
      return
    
    self.is_checking = True
    self.check_btn.config(text="Проверка...", state="disabled")
    self._set_status("Начинаем проверку писем...")
    
    # Запускаем в отдельном потоке
    thread = threading.Thread(target=self._check_worker, args=(enabled_accounts,))
    thread.daemon = True
    thread.start()
  
  def _check_worker(self, accounts: List[EmailAccount]):
    """Рабочий поток проверки с полностью параллельной обработкой"""
    # Счётчики (thread-safe через Lock)
    stats_lock = threading.Lock()
    stats = {"checked": 0, "spam": 0, "total": 0}
    
    # Получаем уже проверенные message_id из логов
    existing_logs = self.analyzer.get_logs(limit=1000)
    checked_ids = set(log.message_id for log in existing_logs)
    checked_ids_lock = threading.Lock()
    
    for account in accounts:
      try:
        self.root.after(0, lambda a=account: self._set_status(f"Подключение к {a.email}..."))
        
        client = IMAPClient(account)
        connected, error = client.connect()
        
        if not connected:
          self.root.after(0, lambda a=account: self._set_status(f"Ошибка подключения к {a.email}"))
          continue
        
        # Получаем ВСЕ непрочитанные письма (без лимита)
        uids = client.get_message_uids("INBOX", "UNSEEN", limit=0)
        
        if not uids:
          client.disconnect()
          continue
        
        self.root.after(0, lambda n=len(uids), a=account: 
                        self._set_status(f"{a.email}: найдено {n} непрочитанных писем"))
        
        stats["total"] = len(uids)
        
        # Lock для IMAP операций (соединение не thread-safe)
        imap_lock = threading.Lock()
        
        def process_email(uid: str):
          """Обработать одно письмо: fetch -> analyze -> display -> spam"""
          nonlocal client, account, checked_ids
          
          try:
            # 1. Fetch email (с блокировкой)
            with imap_lock:
              email_data = client.fetch_email(uid)
            
            if not email_data:
              return
            
            message_id = email_data.get("message_id", "")
            
            # Проверяем дубликат (с блокировкой)
            with checked_ids_lock:
              if message_id in checked_ids:
                return
              checked_ids.add(message_id)
            
            # 2. Analyze (параллельно, без блокировки - это CPU)
            result = self.analyzer.analyze(email_data, account.email)
            
            if not result:
              return
            
            # 3. Display result (UI update)
            with stats_lock:
              stats["checked"] += 1
              current = stats["checked"]
            
            self.root.after(0, lambda r=result: self.log_viewer.add_log(r))
            self.root.after(0, lambda c=current, t=stats["total"]: 
                            self._set_status(f"Проверено {c}/{t} писем..."))
            
            # 4. Move to spam if needed (с блокировкой)
            if result.is_spam or result.is_phishing or result.risk_level == "critical":
              with imap_lock:
                moved = client.move_to_spam(uid)
              
              if moved:
                with stats_lock:
                  stats["spam"] += 1
                  spam_count = stats["spam"]
                
                subj = result.subject[:25] if result.subject else "(без темы)"
                self.root.after(0, lambda s=subj, n=spam_count: 
                                self._set_status(f"В спам ({n}): {s}"))
          
          except Exception as e:
            print(f"Ошибка обработки письма {uid}: {e}")
        
        # Запускаем параллельную обработку всех писем
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
          # Submit все задачи
          futures = [executor.submit(process_email, uid) for uid in uids]
          
          # Ждём завершения всех
          for future in as_completed(futures):
            try:
              future.result()  # Проверяем на исключения
            except Exception as e:
              print(f"Ошибка в worker: {e}")
        
        client.disconnect()
        
      except Exception as e:
        print(f"Ошибка проверки {account.email}: {e}")
    
    # Завершаем
    self.root.after(0, lambda: self._finish_check(stats["checked"], stats["spam"]))
  
  def _analyze_email(self, email_data: Dict[str, Any], account_email: str):
    """Анализ одного письма (для параллельного выполнения)"""
    return self.analyzer.analyze(email_data, account_email)
  
  def _finish_check(self, count: int, spam_count: int = 0):
    """Завершение проверки"""
    self.is_checking = False
    self.check_btn.config(text="Проверить письма", state="normal")
    
    if count == 0:
      self._set_status("Новых писем нет")
    elif spam_count > 0:
      self._set_status(f"Проверено {count} писем, {spam_count} перемещено в спам")
    else:
      self._set_status(f"Проверено {count} писем")
  
  def _refresh_accounts(self):
    """Обновить список аккаунтов"""
    self.accounts_frame.clear()
    
    if not self.account_manager.accounts:
      # Пустое состояние
      empty_label = tk.Label(
        self.accounts_frame.get_frame(),
        text="Нет аккаунтов\n\nНажмите + чтобы\nдобавить почтовый ящик",
        bg=COLORS["bg_dark"],
        fg=COLORS["text_muted"],
        font=FONTS["body"],
        justify="center"
      )
      empty_label.pack(pady=50)
      return
    
    # Карточки аккаунтов
    for account in self.account_manager.accounts:
      card = AccountCard(
        self.accounts_frame.get_frame(),
        account,
        on_toggle=self._on_account_toggle,
        on_remove=self._on_account_remove
      )
      card.pack(fill="x", pady=5)
  
  def _add_account(self):
    """Открыть диалог добавления аккаунта"""
    def on_success(account: EmailAccount):
      self.account_manager.accounts.append(account)
      self.account_manager.save()
      self._refresh_accounts()
      self._set_status(f"Аккаунт {account.email} добавлен")
    
    dialog = AddAccountDialog(self.root, on_success=on_success)
  
  def _on_account_toggle(self, account: EmailAccount):
    """Переключение аккаунта"""
    self.account_manager.save()
    status = "включена" if account.enabled else "выключена"
    self._set_status(f"Фильтрация для {account.email} {status}")
  
  def _on_account_remove(self, account: EmailAccount):
    """Удаление аккаунта"""
    if messagebox.askyesno("Подтверждение", f"Удалить аккаунт {account.email}?"):
      self.account_manager.accounts.remove(account)
      self.account_manager.save()
      self._refresh_accounts()
      self._set_status(f"Аккаунт {account.email} удалён")
  
  def _clear_logs(self):
    """Очистить логи"""
    self.log_viewer.clear()
  
  def _set_status(self, text: str):
    """Установить статус"""
    self.status_bar.config(text=text)
  
  def run(self):
    """Запустить приложение"""
    self.root.protocol("WM_DELETE_WINDOW", self._on_close)
    self.root.mainloop()
  
  def _on_close(self):
    """Закрытие приложения"""
    self.account_manager.save()
    self.root.destroy()
