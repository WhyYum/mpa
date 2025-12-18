# -*- coding: utf-8 -*-
"""
Модели данных
"""

from dataclasses import dataclass
from .config import IMAP_HOSTS, DEFAULT_PORTS


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

