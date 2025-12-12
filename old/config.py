# -*- coding: utf-8 -*-
"""
Конфигурация приложения для анализа почты на фишинг
"""

import os
import json
import base64
from dataclasses import dataclass, field
from typing import Dict, List, Optional


def encode_password(password: str) -> str:
    """Кодировать пароль в Base64"""
    return base64.b64encode(password.encode('utf-8')).decode('utf-8')


def decode_password(encoded: str) -> str:
    """Декодировать пароль из Base64"""
    try:
        return base64.b64decode(encoded.encode('utf-8')).decode('utf-8')
    except Exception:
        # Если не удалось декодировать - возможно пароль в старом формате (не закодирован)
        return encoded

# Путь к директории приложения
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(APP_DIR, "data")
CONFIG_FILE = os.path.join(APP_DIR, "accounts.json")

# IMAP хосты для популярных почтовых сервисов
IMAP_HOSTS: Dict[str, str] = {
    "gmail.com": "imap.gmail.com",
    "googlemail.com": "imap.gmail.com",
    "mail.ru": "imap.mail.ru",
    "inbox.ru": "imap.mail.ru",
    "list.ru": "imap.mail.ru",
    "bk.ru": "imap.mail.ru",
    "yandex.ru": "imap.yandex.ru",
    "yandex.com": "imap.yandex.com",
    "ya.ru": "imap.yandex.ru",
    "outlook.com": "imap-mail.outlook.com",
    "hotmail.com": "imap-mail.outlook.com",
    "live.com": "imap-mail.outlook.com",
    "yahoo.com": "imap.mail.yahoo.com",
    "rambler.ru": "imap.rambler.ru",
}

# Порты по умолчанию для IMAP
DEFAULT_PORTS = {
    "ssl": 993,
    "starttls": 143,
    "none": 143
}

# Типы защиты соединения
SECURITY_TYPES = ["SSL/TLS", "STARTTLS", "Нет"]

# Интервал проверки новых писем (в секундах)
CHECK_INTERVAL = 30


@dataclass
class EmailAccount:
    """Класс для хранения данных почтового аккаунта (IMAP)"""
    email: str
    password: str
    host: str = ""
    port: int = 0  # 0 = авто
    security: str = "SSL/TLS"  # SSL/TLS, STARTTLS, Нет
    enabled: bool = True
    spam_folder: str = "Spam"
    
    def __post_init__(self):
        if not self.host:
            domain = self.email.split("@")[-1].lower()
            self.host = IMAP_HOSTS.get(domain, f"imap.{domain}")
        
        if self.port == 0:
            self.port = self.get_default_port()
    
    def get_default_port(self) -> int:
        """Получить порт по умолчанию для типа защиты"""
        sec_key = {"SSL/TLS": "ssl", "STARTTLS": "starttls", "Нет": "none"}.get(self.security, "ssl")
        return DEFAULT_PORTS.get(sec_key, 993)
    
    @property
    def use_ssl(self) -> bool:
        """Использовать SSL при подключении"""
        return self.security == "SSL/TLS"
    
    @property
    def use_starttls(self) -> bool:
        """Использовать STARTTLS"""
        return self.security == "STARTTLS"


@dataclass
class RiskThresholds:
    """Пороговые значения для классификации писем"""
    safe: int = 20          # 0-20: безопасное
    suspicious: int = 50    # 20-50: подозрительное  
    phishing: int = 100     # 50+: вероятный фишинг


@dataclass
class AppConfig:
    """Основная конфигурация приложения"""
    accounts: List[EmailAccount] = field(default_factory=list)
    check_interval: int = CHECK_INTERVAL
    auto_move_spam: bool = True
    thresholds: RiskThresholds = field(default_factory=RiskThresholds)
    
    def save(self):
        """Сохранить конфигурацию в файл"""
        data = {
            "check_interval": self.check_interval,
            "auto_move_spam": self.auto_move_spam,
            "thresholds": {
                "safe": self.thresholds.safe,
                "suspicious": self.thresholds.suspicious,
                "phishing": self.thresholds.phishing
            },
            "accounts": [
                {
                    "email": acc.email,
                    "password": encode_password(acc.password),
                    "host": acc.host,
                    "port": acc.port,
                    "security": acc.security,
                    "enabled": acc.enabled,
                    "spam_folder": acc.spam_folder
                }
                for acc in self.accounts
            ]
        }
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    @classmethod
    def load(cls) -> "AppConfig":
        """Загрузить конфигурацию из файла"""
        if not os.path.exists(CONFIG_FILE):
            return cls()
        
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            config = cls(
                check_interval=data.get("check_interval", CHECK_INTERVAL),
                auto_move_spam=data.get("auto_move_spam", True),
                thresholds=RiskThresholds(
                    safe=data.get("thresholds", {}).get("safe", 20),
                    suspicious=data.get("thresholds", {}).get("suspicious", 50),
                    phishing=data.get("thresholds", {}).get("phishing", 100)
                )
            )
            
            for acc_data in data.get("accounts", []):
                config.accounts.append(EmailAccount(
                    email=acc_data["email"],
                    password=decode_password(acc_data["password"]),
                    host=acc_data.get("host", acc_data.get("imap_host", "")),  # совместимость со старым форматом
                    port=acc_data.get("port", acc_data.get("imap_port", 0)),
                    security=acc_data.get("security", "SSL/TLS"),
                    enabled=acc_data.get("enabled", True),
                    spam_folder=acc_data.get("spam_folder", "Spam")
                ))
            
            return config
        except Exception as e:
            print(f"Ошибка загрузки конфигурации: {e}")
            return cls()

