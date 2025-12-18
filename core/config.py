# -*- coding: utf-8 -*-
"""
Конфигурация приложения: пути и константы
"""

import os

# Пути
APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(APP_DIR, "data")
LOGS_DIR = os.path.join(APP_DIR, "logs")
CONFIG_FILE = os.path.join(APP_DIR, "accounts.json")


def _load_imap_hosts() -> dict:
  """Загрузить IMAP хосты из JSON файла"""
  import json
  path = os.path.join(DATA_DIR, "imap_hosts.json")
  try:
    with open(path, "r", encoding="utf-8") as f:
      return json.load(f)
  except Exception as e:
    print(f"Ошибка загрузки imap_hosts.json: {e}")
    return {}


# IMAP хосты для популярных почтовых сервисов
IMAP_HOSTS: dict = _load_imap_hosts()

# Порты по умолчанию
DEFAULT_PORTS = {"ssl": 993, "starttls": 143, "none": 25}

# Типы защиты соединения
SECURITY_TYPES = ["SSL/TLS", "STARTTLS", "Нет"]

