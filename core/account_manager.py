# -*- coding: utf-8 -*-
"""
Менеджер почтовых аккаунтов
"""

import os
import json
from typing import List

from .config import CONFIG_FILE
from .models import EmailAccount
from utils.crypto import encode_password, decode_password


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
          enabled=acc_data.get("enabled", True),
          auto_check=acc_data.get("auto_check", False),
          check_interval=acc_data.get("check_interval", 30)
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
            "enabled": acc.enabled,
            "auto_check": acc.auto_check,
            "check_interval": acc.check_interval
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
  
  def get_auto_check_accounts(self) -> List[EmailAccount]:
    """Получить аккаунты с включённой автопроверкой"""
    return [acc for acc in self.accounts if acc.enabled and acc.auto_check]
  
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

