# -*- coding: utf-8 -*-
"""
DNS утилиты
"""

from typing import Optional

try:
  import dns.resolver
  HAS_DNS = True
except ImportError:
  HAS_DNS = False


def get_mx_domain(domain: str) -> Optional[str]:
  """
  Получить домен почтового сервера из MX записи.
  
  Args:
    domain: Домен для проверки (например, "gmail.com")
    
  Returns:
    Базовый домен MX сервера (например, "google.com") или None
  """
  if not HAS_DNS:
    return None
  
  try:
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']  # Публичные DNS
    mx_records = resolver.resolve(domain, 'MX')
    
    # Берём MX с наивысшим приоритетом (наименьшее число)
    best_mx = min(mx_records, key=lambda x: x.preference)
    mx_host = str(best_mx.exchange).rstrip('.')
    
    # Извлекаем базовый домен (mx1.mail.ru -> mail.ru)
    parts = mx_host.split('.')
    if len(parts) >= 2:
      return '.'.join(parts[-2:])
    return mx_host
  except Exception as e:
    print(f"MX lookup error: {e}")
    return None

