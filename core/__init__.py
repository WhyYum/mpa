# -*- coding: utf-8 -*-
"""
Ядро приложения: модели, конфигурация, менеджер аккаунтов
"""

from .config import (
  APP_DIR, DATA_DIR, LOGS_DIR, CONFIG_FILE, 
  IMAP_HOSTS, DEFAULT_PORTS, SECURITY_TYPES, DNS_SERVERS
)
from .models import EmailAccount
from .account_manager import AccountManager

__all__ = [
  'APP_DIR',
  'DATA_DIR', 
  'LOGS_DIR',
  'CONFIG_FILE',
  'IMAP_HOSTS',
  'DEFAULT_PORTS',
  'SECURITY_TYPES',
  'DNS_SERVERS',
  'EmailAccount',
  'AccountManager'
]

