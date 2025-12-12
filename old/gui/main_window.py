# -*- coding: utf-8 -*-
"""
Главное окно приложения
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from typing import List, Optional
import threading
import queue
import time

from .styles import COLORS, FONTS
from .widgets import (
    EmailLogItem, AccountCard, ScrollableFrame, 
    CollapsibleFrame, ToolTip
)
from config import AppConfig, EmailAccount, SECURITY_TYPES, DEFAULT_PORTS
from core.email_client import EmailClient, ParsedEmail
from core.risk_engine import RiskEngine, EmailAnalysisResult


def bind_clipboard_hotkeys(entry_widget):
    """Привязать горячие клавиши буфера обмена (работает с любой раскладкой)"""
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
        # Проверяем Ctrl через state (бит 4 = Control)
        if event.state & 4:
            # keycode: V=86, C=67, X=88, A=65 (одинаковы для любой раскладки)
            if event.keycode == 86:  # V
                return paste(event)
            elif event.keycode == 67:  # C
                return copy(event)
            elif event.keycode == 88:  # X
                return cut(event)
            elif event.keycode == 65:  # A
                return select_all(event)
        return None
    
    # Универсальный обработчик клавиш
    entry_widget.bind("<Key>", on_key)


class AddAccountDialog(tk.Toplevel):
    """Диалог добавления аккаунта"""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Добавить почтовый аккаунт")
        self.geometry("450x500")
        self.configure(bg=COLORS["bg_dark"])
        self.resizable(False, False)
        
        # Центрируем окно
        self.transient(parent)
        self.grab_set()
        
        self.result: Optional[EmailAccount] = None
        
        self._create_widgets()
        
        # Позиционируем по центру родителя
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")
    
    def _create_widgets(self):
        # Заголовок
        title = tk.Label(
            self,
            text="📧 Добавить почтовый ящик",
            bg=COLORS["bg_dark"],
            fg=COLORS["text_primary"],
            font=FONTS["title"]
        )
        title.pack(pady=(15, 10))
        
        # Форма с прокруткой
        form_frame = tk.Frame(self, bg=COLORS["bg_dark"])
        form_frame.pack(fill="both", expand=True, padx=30)
        
        # Email
        tk.Label(
            form_frame,
            text="Email:",
            bg=COLORS["bg_dark"],
            fg=COLORS["text_primary"],
            font=FONTS["body"]
        ).pack(anchor="w", pady=(5, 2))
        
        self.email_entry = tk.Entry(
            form_frame,
            bg=COLORS["input_bg"],
            fg=COLORS["text_primary"],
            insertbackground=COLORS["text_primary"],
            font=FONTS["body"],
            relief="flat"
        )
        self.email_entry.pack(fill="x", ipady=6)
        bind_clipboard_hotkeys(self.email_entry)
        
        # Пароль
        tk.Label(
            form_frame,
            text="Пароль приложения:",
            bg=COLORS["bg_dark"],
            fg=COLORS["text_primary"],
            font=FONTS["body"]
        ).pack(anchor="w", pady=(10, 2))
        
        self.password_entry = tk.Entry(
            form_frame,
            bg=COLORS["input_bg"],
            fg=COLORS["text_primary"],
            insertbackground=COLORS["text_primary"],
            font=FONTS["body"],
            relief="flat",
            show="•"
        )
        self.password_entry.pack(fill="x", ipady=6)
        bind_clipboard_hotkeys(self.password_entry)
        
        # Подсказка
        tk.Label(
            form_frame,
            text="Для Gmail используйте пароль приложения",
            bg=COLORS["bg_dark"],
            fg=COLORS["text_muted"],
            font=FONTS["small"]
        ).pack(anchor="w", pady=(2, 0))
        
        # Защита соединения
        tk.Label(
            form_frame,
            text="Защита соединения:",
            bg=COLORS["bg_dark"],
            fg=COLORS["text_primary"],
            font=FONTS["body"]
        ).pack(anchor="w", pady=(15, 2))
        
        self.security_var = tk.StringVar(value="SSL/TLS")
        self.security_combo = ttk.Combobox(
            form_frame,
            textvariable=self.security_var,
            values=SECURITY_TYPES,
            state="readonly",
            width=15
        )
        self.security_combo.pack(anchor="w")
        self.security_combo.bind("<<ComboboxSelected>>", self._on_settings_change)
        
        # IMAP сервер и порт в одну строку
        server_frame = tk.Frame(form_frame, bg=COLORS["bg_dark"])
        server_frame.pack(fill="x", pady=(15, 0))
        
        # Сервер
        host_frame = tk.Frame(server_frame, bg=COLORS["bg_dark"])
        host_frame.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        tk.Label(
            host_frame,
            text="IMAP сервер (пусто = авто):",
            bg=COLORS["bg_dark"],
            fg=COLORS["text_primary"],
            font=FONTS["body"]
        ).pack(anchor="w", pady=(0, 2))
        
        self.host_entry = tk.Entry(
            host_frame,
            bg=COLORS["input_bg"],
            fg=COLORS["text_primary"],
            insertbackground=COLORS["text_primary"],
            font=FONTS["body"],
            relief="flat"
        )
        self.host_entry.pack(fill="x", ipady=6)
        bind_clipboard_hotkeys(self.host_entry)
        
        # Порт
        port_frame = tk.Frame(server_frame, bg=COLORS["bg_dark"])
        port_frame.pack(side="left")
        
        tk.Label(
            port_frame,
            text="Порт:",
            bg=COLORS["bg_dark"],
            fg=COLORS["text_primary"],
            font=FONTS["body"]
        ).pack(anchor="w", pady=(0, 2))
        
        self.port_var = tk.StringVar(value="993")
        self.port_entry = tk.Entry(
            port_frame,
            textvariable=self.port_var,
            bg=COLORS["input_bg"],
            fg=COLORS["text_primary"],
            insertbackground=COLORS["text_primary"],
            font=FONTS["body"],
            relief="flat",
            width=7
        )
        self.port_entry.pack(ipady=6)
        bind_clipboard_hotkeys(self.port_entry)
        
        # Подсказка по порту
        self.port_hint = tk.Label(
            form_frame,
            text="Стандартный порт: 993 (SSL/TLS), 143 (STARTTLS/Нет)",
            bg=COLORS["bg_dark"],
            fg=COLORS["text_muted"],
            font=FONTS["small"]
        )
        self.port_hint.pack(anchor="w", pady=(2, 0))
        
        # Кнопки
        btn_frame = tk.Frame(self, bg=COLORS["bg_dark"])
        btn_frame.pack(pady=20)
        
        cancel_btn = tk.Button(
            btn_frame,
            text="Отмена",
            command=self.destroy,
            bg=COLORS["bg_medium"],
            fg=COLORS["text_primary"],
            font=FONTS["body"],
            relief="flat",
            padx=20,
            pady=8,
            cursor="hand2"
        )
        cancel_btn.pack(side="left", padx=10)
        
        add_btn = tk.Button(
            btn_frame,
            text="Добавить",
            command=self._on_add,
            bg=COLORS["accent"],
            fg=COLORS["text_primary"],
            font=FONTS["body_bold"],
            relief="flat",
            padx=20,
            pady=8,
            cursor="hand2"
        )
        add_btn.pack(side="left", padx=10)
    
    def _on_settings_change(self, event=None):
        """Обновить порт по умолчанию при изменении настроек"""
        security = self.security_var.get()
        sec_key = {"SSL/TLS": "ssl", "STARTTLS": "starttls", "Нет": "none"}.get(security, "ssl")
        
        default_port = DEFAULT_PORTS.get(sec_key, 993)
        self.port_var.set(str(default_port))
    
    def _on_add(self):
        email = self.email_entry.get().strip()
        password = self.password_entry.get()
        host = self.host_entry.get().strip()
        security = self.security_var.get()
        
        try:
            port = int(self.port_var.get())
        except ValueError:
            messagebox.showerror("Ошибка", "Некорректный порт")
            return
        
        if not email or not password:
            messagebox.showerror("Ошибка", "Заполните email и пароль")
            return
        
        if "@" not in email:
            messagebox.showerror("Ошибка", "Некорректный email")
            return
        
        self.result = EmailAccount(
            email=email,
            password=password,
            host=host,
            port=port,
            security=security
        )
        self.destroy()


class MainWindow:
    """Главное окно приложения"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("📧 Фильтр фишинговых писем")
        self.root.geometry("1200x800")
        self.root.configure(bg=COLORS["bg_dark"])
        self.root.minsize(900, 600)
        
        # Конфигурация
        self.config = AppConfig.load()
        self.risk_engine = RiskEngine()
        
        # Клиенты и потоки
        self.email_clients: dict = {}  # email -> EmailClient
        self.check_threads: dict = {}  # email -> Thread
        self.stop_events: dict = {}    # email -> Event
        
        # Очередь для обновления GUI из потоков
        self.gui_queue = queue.Queue()
        
        # Логи анализа
        self.analysis_logs: List[EmailAnalysisResult] = []
        
        # Создаём интерфейс
        self._create_menu()
        self._create_widgets()
        
        # Запускаем обработку очереди
        self._process_gui_queue()
        
        # Автозапуск для активных аккаунтов
        self._auto_start_monitoring()
    
    def _create_menu(self):
        """Создать меню"""
        menubar = tk.Menu(self.root, bg=COLORS["bg_medium"], fg=COLORS["text_primary"])
        
        # Меню Файл
        file_menu = tk.Menu(menubar, tearoff=0, bg=COLORS["bg_medium"], fg=COLORS["text_primary"])
        file_menu.add_command(label="Сохранить конфигурацию", command=self._save_config)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self._on_close)
        menubar.add_cascade(label="Файл", menu=file_menu)
        
        # Меню Настройки
        settings_menu = tk.Menu(menubar, tearoff=0, bg=COLORS["bg_medium"], fg=COLORS["text_primary"])
        settings_menu.add_command(label="Интервал проверки...", command=self._change_interval)
        menubar.add_cascade(label="Настройки", menu=settings_menu)
        
        self.root.config(menu=menubar)
    
    def _create_widgets(self):
        """Создать виджеты"""
        # Главный контейнер с разделением
        paned = tk.PanedWindow(
            self.root,
            orient="horizontal",
            bg=COLORS["bg_dark"],
            sashwidth=4,
            sashrelief="flat"
        )
        paned.pack(fill="both", expand=True)
        
        # Левая панель - аккаунты
        left_frame = tk.Frame(paned, bg=COLORS["bg_dark"], width=300)
        paned.add(left_frame, minsize=250)
        
        self._create_accounts_panel(left_frame)
        
        # Правая панель - логи
        right_frame = tk.Frame(paned, bg=COLORS["bg_dark"])
        paned.add(right_frame, minsize=600)
        
        self._create_logs_panel(right_frame)
        
        # Статусная строка
        self.status_bar = tk.Label(
            self.root,
            text="Готов к работе",
            bg=COLORS["bg_medium"],
            fg=COLORS["text_secondary"],
            font=FONTS["small"],
            anchor="w",
            padx=10,
            pady=5
        )
        self.status_bar.pack(fill="x", side="bottom")
    
    def _create_accounts_panel(self, parent):
        """Создать панель аккаунтов"""
        # Заголовок
        header = tk.Frame(parent, bg=COLORS["bg_dark"])
        header.pack(fill="x", padx=10, pady=10)
        
        tk.Label(
            header,
            text="📬 Почтовые ящики",
            bg=COLORS["bg_dark"],
            fg=COLORS["text_primary"],
            font=FONTS["title"]
        ).pack(side="left")
        
        add_btn = tk.Button(
            header,
            text="+ Добавить",
            command=self._add_account,
            bg=COLORS["accent"],
            fg=COLORS["text_primary"],
            font=FONTS["body"],
            relief="flat",
            padx=15,
            pady=5,
            cursor="hand2"
        )
        add_btn.pack(side="right")
        
        # Список аккаунтов
        self.accounts_frame = ScrollableFrame(parent, bg=COLORS["bg_dark"])
        self.accounts_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self._refresh_accounts_list()
    
    def _create_logs_panel(self, parent):
        """Создать панель логов"""
        # Заголовок
        header = tk.Frame(parent, bg=COLORS["bg_dark"])
        header.pack(fill="x", padx=10, pady=10)
        
        tk.Label(
            header,
            text="📋 Журнал проверки писем",
            bg=COLORS["bg_dark"],
            fg=COLORS["text_primary"],
            font=FONTS["title"]
        ).pack(side="left")
        
        # Кнопка очистки
        clear_btn = tk.Button(
            header,
            text="🗑️ Очистить",
            command=self._clear_logs,
            bg=COLORS["bg_medium"],
            fg=COLORS["text_primary"],
            font=FONTS["body"],
            relief="flat",
            padx=10,
            pady=5,
            cursor="hand2"
        )
        clear_btn.pack(side="right")
        
        # Фильтр статуса
        filter_frame = tk.Frame(header, bg=COLORS["bg_dark"])
        filter_frame.pack(side="right", padx=20)
        
        tk.Label(
            filter_frame,
            text="Фильтр:",
            bg=COLORS["bg_dark"],
            fg=COLORS["text_secondary"],
            font=FONTS["body"]
        ).pack(side="left", padx=5)
        
        self.filter_var = tk.StringVar(value="Все")
        filter_options = ["Все", "Безопасные", "Подозрительные", "Спам/Фишинг"]
        
        self.filter_combo = ttk.Combobox(
            filter_frame,
            values=filter_options,
            textvariable=self.filter_var,
            state="readonly",
            width=15
        )
        self.filter_combo.pack(side="left")
        self.filter_combo.bind("<<ComboboxSelected>>", self._on_filter_change)
        
        # Статистика
        self.stats_label = tk.Label(
            header,
            text="",
            bg=COLORS["bg_dark"],
            fg=COLORS["text_secondary"],
            font=FONTS["small"]
        )
        self.stats_label.pack(side="right", padx=20)
        
        # Список логов
        self.logs_frame = ScrollableFrame(parent, bg=COLORS["bg_dark"])
        self.logs_frame.pack(fill="both", expand=True, padx=10, pady=5)
    
    def _refresh_accounts_list(self):
        """Обновить список аккаунтов"""
        # Очищаем
        for widget in self.accounts_frame.get_frame().winfo_children():
            widget.destroy()
        
        if not self.config.accounts:
            empty_label = tk.Label(
                self.accounts_frame.get_frame(),
                text="Нет добавленных аккаунтов\n\nНажмите '+ Добавить' чтобы\nдобавить почтовый ящик",
                bg=COLORS["bg_dark"],
                fg=COLORS["text_muted"],
                font=FONTS["body"],
                justify="center"
            )
            empty_label.pack(pady=50)
            return
        
        for account in self.config.accounts:
            card = AccountCard(
                self.accounts_frame.get_frame(),
                account,
                on_toggle=self._on_account_toggle,
                on_remove=self._on_account_remove
            )
            card.pack(fill="x", pady=5)
    
    def _refresh_logs_list(self):
        """Обновить список логов"""
        # Очищаем
        for widget in self.logs_frame.get_frame().winfo_children():
            widget.destroy()
        
        # Фильтруем
        filter_value = self.filter_var.get()
        filtered_logs = self.analysis_logs
        
        if filter_value == "Безопасные":
            filtered_logs = [l for l in self.analysis_logs if l.classification == "Безопасное"]
        elif filter_value == "Подозрительные":
            filtered_logs = [l for l in self.analysis_logs if l.classification == "Подозрительное"]
        elif filter_value == "Спам/Фишинг":
            filtered_logs = [l for l in self.analysis_logs if l.classification in ["Спам", "Фишинг", "Фишинг (опасное вложение)"]]
        
        if not filtered_logs:
            empty_label = tk.Label(
                self.logs_frame.get_frame(),
                text="Нет записей для отображения",
                bg=COLORS["bg_dark"],
                fg=COLORS["text_muted"],
                font=FONTS["body"]
            )
            empty_label.pack(pady=50)
            return
        
        # Показываем в обратном порядке (новые сверху)
        for result in reversed(filtered_logs[-100:]):  # Ограничиваем 100 записями
            log_item = EmailLogItem(
                self.logs_frame.get_frame(),
                result
            )
            log_item.pack(fill="x", pady=1)
        
        # Обновляем статистику
        self._update_stats()
    
    def _update_stats(self):
        """Обновить статистику"""
        total = len(self.analysis_logs)
        safe = len([l for l in self.analysis_logs if l.classification == "Безопасное"])
        suspicious = len([l for l in self.analysis_logs if l.classification == "Подозрительное"])
        spam = len([l for l in self.analysis_logs if l.classification in ["Спам", "Фишинг", "Фишинг (опасное вложение)"]])
        
        self.stats_label.config(
            text=f"Всего: {total} | ✅ {safe} | ⚠️ {suspicious} | 🚫 {spam}"
        )
    
    def _add_account(self):
        """Добавить аккаунт"""
        dialog = AddAccountDialog(self.root)
        self.root.wait_window(dialog)
        
        if dialog.result:
            # Проверяем подключение
            self._set_status(f"Проверка подключения к {dialog.result.email}...")
            
            client = EmailClient.from_account(dialog.result)
            if client.connect(dialog.result.email, dialog.result.password):
                client.disconnect()
                
                self.config.accounts.append(dialog.result)
                self.config.save()
                self._refresh_accounts_list()
                
                self._set_status(f"Аккаунт {dialog.result.email} добавлен")
                
                # Автоматически запускаем мониторинг
                if dialog.result.enabled:
                    self._start_monitoring(dialog.result)
            else:
                messagebox.showerror(
                    "Ошибка",
                    f"Не удалось подключиться к {dialog.result.email}\n\n"
                    "Проверьте:\n"
                    "- Правильность email и пароля\n"
                    "- Включён ли IMAP в настройках почты\n"
                    "- Используете ли вы пароль приложения (для Gmail)"
                )
                self._set_status("Ошибка подключения")
    
    def _on_account_toggle(self, account: EmailAccount):
        """Переключение фильтрации аккаунта"""
        self.config.save()
        
        if account.enabled:
            self._start_monitoring(account)
            self._set_status(f"Фильтрация для {account.email} включена")
        else:
            self._stop_monitoring(account)
            self._set_status(f"Фильтрация для {account.email} выключена")
    
    def _on_account_remove(self, account: EmailAccount):
        """Удалить аккаунт"""
        if messagebox.askyesno("Подтверждение", f"Удалить аккаунт {account.email}?"):
            self._stop_monitoring(account)
            self.config.accounts.remove(account)
            self.config.save()
            self._refresh_accounts_list()
            self._set_status(f"Аккаунт {account.email} удалён")
    
    def _start_monitoring(self, account: EmailAccount):
        """Запустить мониторинг аккаунта"""
        if account.email in self.check_threads:
            return
        
        stop_event = threading.Event()
        self.stop_events[account.email] = stop_event
        
        thread = threading.Thread(
            target=self._monitoring_worker,
            args=(account, stop_event),
            daemon=True
        )
        self.check_threads[account.email] = thread
        thread.start()
    
    def _stop_monitoring(self, account: EmailAccount):
        """Остановить мониторинг аккаунта"""
        if account.email in self.stop_events:
            self.stop_events[account.email].set()
        
        if account.email in self.email_clients:
            try:
                self.email_clients[account.email].disconnect()
            except:
                pass
            del self.email_clients[account.email]
        
        if account.email in self.check_threads:
            del self.check_threads[account.email]
        
        if account.email in self.stop_events:
            del self.stop_events[account.email]
    
    def _monitoring_worker(self, account: EmailAccount, stop_event: threading.Event):
        """Рабочий поток мониторинга"""
        client = EmailClient.from_account(account)
        
        if not client.connect(account.email, account.password):
            self.gui_queue.put(("status", f"Ошибка подключения к {account.email}"))
            return
        
        self.email_clients[account.email] = client
        processed_uids = set()
        
        # Первоначальная загрузка (последние 50 писем)
        client.select_folder("INBOX")
        initial_uids = client.get_all_uids(limit=50)
        processed_uids.update(initial_uids)
        
        self.gui_queue.put(("status", f"Мониторинг {account.email} запущен"))
        
        while not stop_event.is_set():
            try:
                # Проверяем новые письма
                client.select_folder("INBOX")
                current_uids = set(client.get_all_uids(limit=100))
                new_uids = current_uids - processed_uids
                
                for uid in new_uids:
                    if stop_event.is_set():
                        break
                    
                    email = client.fetch_email(uid)
                    if email:
                        # Анализируем письмо
                        result = self.risk_engine.analyze_email(email)
                        
                        # Добавляем в GUI
                        self.gui_queue.put(("log", result))
                        
                        # Перемещаем в спам если нужно
                        if result.should_move_to_spam and self.config.auto_move_spam:
                            client.move_to_spam(uid, account.spam_folder)
                            self.gui_queue.put(("status", f"Письмо перемещено в спам: {email.subject[:30]}"))
                    
                    processed_uids.add(uid)
                
                # Ждём перед следующей проверкой
                for _ in range(self.config.check_interval):
                    if stop_event.is_set():
                        break
                    time.sleep(1)
                    
            except Exception as e:
                self.gui_queue.put(("status", f"Ошибка: {str(e)[:50]}"))
                time.sleep(10)  # Пауза при ошибке
        
        client.disconnect()
    
    def _process_gui_queue(self):
        """Обработка очереди GUI"""
        try:
            while True:
                msg_type, data = self.gui_queue.get_nowait()
                
                if msg_type == "log":
                    self.analysis_logs.append(data)
                    self._refresh_logs_list()
                elif msg_type == "status":
                    self._set_status(data)
                    
        except queue.Empty:
            pass
        
        self.root.after(100, self._process_gui_queue)
    
    def _auto_start_monitoring(self):
        """Автозапуск мониторинга для активных аккаунтов"""
        for account in self.config.accounts:
            if account.enabled:
                self._start_monitoring(account)
    
    def _on_filter_change(self, event=None):
        """Изменение фильтра"""
        self._refresh_logs_list()
    
    def _clear_logs(self):
        """Очистить логи"""
        if messagebox.askyesno("Подтверждение", "Очистить журнал проверки?"):
            self.analysis_logs.clear()
            self._refresh_logs_list()
    
    def _save_config(self):
        """Сохранить конфигурацию"""
        self.config.save()
        self._set_status("Конфигурация сохранена")
    
    def _change_interval(self):
        """Изменить интервал проверки"""
        result = simpledialog.askinteger(
            "Интервал проверки",
            "Введите интервал проверки в секундах:",
            initialvalue=self.config.check_interval,
            minvalue=10,
            maxvalue=3600
        )
        if result:
            self.config.check_interval = result
            self.config.save()
            self._set_status(f"Интервал проверки: {result} сек.")
    
    def _set_status(self, text: str):
        """Установить текст статусной строки"""
        self.status_bar.config(text=text)
    
    def _on_close(self):
        """Закрытие приложения"""
        # Останавливаем все потоки
        for email in list(self.stop_events.keys()):
            self.stop_events[email].set()
        
        # Закрываем подключения
        for email, client in list(self.email_clients.items()):
            try:
                client.disconnect()
            except:
                pass
        
        self.config.save()
        self.root.destroy()
    
    def run(self):
        """Запустить приложение"""
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

