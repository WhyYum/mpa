# -*- coding: utf-8 -*-
"""
Конфигурация и загрузка аккаунтов
"""

import os
import json
import base64
from dataclasses import dataclass
from typing import List, Dict


# Пути
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(APP_DIR, "data")
CONFIG_FILE = os.path.join(APP_DIR, "accounts.json")


def load_imap_hosts() -> Dict[str, str]:
  """Загрузить IMAP хосты из JSON файла"""
  path = os.path.join(DATA_DIR, "imap_hosts.json")
  try:
    with open(path, "r", encoding="utf-8") as f:
      return json.load(f)
  except Exception as e:
    print(f"Ошибка загрузки imap_hosts.json: {e}")
    return {}


# IMAP хосты для популярных почтовых сервисов
IMAP_HOSTS: Dict[str, str] = load_imap_hosts()

# Порты по умолчанию
DEFAULT_PORTS = {"ssl": 993, "starttls": 143, "none": 25}

# Типы защиты соединения
SECURITY_TYPES = ["SSL/TLS", "STARTTLS", "Нет"]


def encode_password(password: str) -> str:
  """Кодировать пароль в Base64"""
  return base64.b64encode(password.encode('utf-8')).decode('utf-8')


def decode_password(encoded: str) -> str:
  """Декодировать пароль из Base64"""
  try:
    return base64.b64decode(encoded.encode('utf-8')).decode('utf-8')
  except Exception:
    return encoded  # Если не удалось - возвращаем как есть


@dataclass
class EmailAccount:
  """Почтовый аккаунт"""
  email: str
  password: str
  host: str = ""
  port: int = 993
  security: str = "SSL/TLS"  # SSL/TLS, STARTTLS, Нет
  enabled: bool = True
  
  def __post_init__(self):
    # Автоопределение хоста
    if not self.host:
      domain = self.email.split("@")[-1].lower()
      self.host = IMAP_HOSTS.get(domain, f"imap.{domain}")
    
    # Автоопределение порта
    if self.port == 0:
      sec_key = {"SSL/TLS": "ssl", "STARTTLS": "starttls", "Нет": "none"}.get(self.security, "ssl")
      self.port = DEFAULT_PORTS.get(sec_key, 993)
  
  @property
  def use_ssl(self) -> bool:
    return self.security == "SSL/TLS"
  
  @property
  def use_starttls(self) -> bool:
    return self.security == "STARTTLS"
  
  def __str__(self):
    return f"{self.email} -> {self.host}:{self.port} ({self.security})"


class AccountManager:
  """Менеджер аккаунтов"""
  
  def __init__(self):
    self.accounts: List[EmailAccount] = []
  
  def load(self) -> bool:
    """Загрузить аккаунты из файла"""
    if not os.path.exists(CONFIG_FILE):
      print(f"Файл конфигурации не найден: {CONFIG_FILE}")
      return False
    
    try:
      with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
        
      self.accounts.clear()
      
      for acc_data in data.get("accounts", []):
        account = EmailAccount(
          email=acc_data["email"],
          password=decode_password(acc_data["password"]),
          host=acc_data.get("host", ""),
          port=acc_data.get("port", 0),
          security=acc_data.get("security", "SSL/TLS"),
          enabled=acc_data.get("enabled", True)
        )
        self.accounts.append(account)
      
      print(f"Загружено аккаунтов: {len(self.accounts)}")
      return True
        
    except Exception as e:
      print(f"Ошибка загрузки: {e}")
      return False
  
  def save(self) -> bool:
    """Сохранить аккаунты в файл"""
    try:
      data = {
        "accounts": [
          {
            "email": acc.email,
            "password": encode_password(acc.password),
            "host": acc.host,
            "port": acc.port,
            "security": acc.security,
            "enabled": acc.enabled
          }
          for acc in self.accounts
        ]
      }
      
      with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
      
      print(f"Сохранено аккаунтов: {len(self.accounts)}")
      return True
        
    except Exception as e:
      print(f"Ошибка сохранения: {e}")
      return False
  
  def add_account(self, email: str, password: str, **kwargs) -> EmailAccount:
    """Добавить новый аккаунт"""
    account = EmailAccount(email=email, password=password, **kwargs)
    self.accounts.append(account)
    return account
  
  def get_enabled_accounts(self) -> List[EmailAccount]:
    """Получить активные аккаунты"""
    return [acc for acc in self.accounts if acc.enabled]
  
  def print_accounts(self):
    """Вывести аккаунты в консоль"""
    if not self.accounts:
      print("Нет аккаунтов")
      return
      
    print("\n" + "=" * 60)
    print("📧 ЗАГРУЖЕННЫЕ АККАУНТЫ")
    print("=" * 60)
    
    for i, acc in enumerate(self.accounts, 1):
      status = "✅" if acc.enabled else "❌"
      print(f"\n{status} Аккаунт #{i}")
      print(f"   Email:    {acc.email}")
      print(f"   Пароль:   {acc.password}")
      print(f"   Сервер:   {acc.host}:{acc.port}")
      print(f"   Защита:   {acc.security}")
    
    print("\n" + "=" * 60)

