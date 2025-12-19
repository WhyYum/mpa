# -*- coding: utf-8 -*-
"""
Проверка DNS записей: SPF, DKIM, DMARC
"""

import re
import time
import threading
from typing import Dict, Optional, Tuple, List
from .analysis_result import CheckResult, CheckStatus
from core.config import DNS_SERVERS

try:
  import dns.resolver
  HAS_DNS = True
except ImportError:
  HAS_DNS = False


def get_resolver() -> "dns.resolver.Resolver":
  """Создать DNS резолвер с публичными DNS серверами"""
  resolver = dns.resolver.Resolver()
  resolver.nameservers = DNS_SERVERS
  return resolver


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
    resolver = get_resolver()
    mx_records = resolver.resolve(domain, 'MX', lifetime=3)
    
    # Берём MX с наивысшим приоритетом (наименьшее число)
    best_mx = min(mx_records, key=lambda x: x.preference)
    mx_host = str(best_mx.exchange).rstrip('.')
    
    # Извлекаем базовый домен (mx1.mail.ru -> mail.ru)
    parts = mx_host.split('.')
    if len(parts) >= 2:
      return '.'.join(parts[-2:])
    return mx_host
  except Exception:
    return None


class DNSCache:
  """Кеш DNS запросов с TTL"""
  
  def __init__(self, ttl: int = 300):
    self.cache: Dict[str, Tuple[any, float]] = {}
    self.ttl = ttl
    self.lock = threading.Lock()
  
  def get(self, key: str) -> Optional[any]:
    """Получить из кеша"""
    with self.lock:
      if key in self.cache:
        value, timestamp = self.cache[key]
        if time.time() - timestamp < self.ttl:
          return value
        del self.cache[key]
    return None
  
  def set(self, key: str, value: any):
    """Сохранить в кеш"""
    with self.lock:
      self.cache[key] = (value, time.time())
  
  def clear(self):
    """Очистить кеш"""
    with self.lock:
      self.cache.clear()


class DNSChecker:
  """Проверка DNS записей для аутентификации email"""
  
  # Глобальный кеш (общий для всех инстансов)
  _cache = DNSCache(ttl=300)  # 5 минут
  
  def __init__(self):
    self.timeout = 3  # Уменьшили с 5 до 3 секунд
    self.resolver = get_resolver()
  
  def check_spf(self, domain: str, sender_ip: str = None) -> CheckResult:
    """Проверить SPF запись"""
    if not HAS_DNS:
      return CheckResult(
        name="spf",
        status=CheckStatus.ERROR,
        title="SPF проверка недоступна",
        description="Библиотека dnspython не установлена"
      )
    
    # Проверяем кеш
    cache_key = f"spf:{domain}"
    cached = self._cache.get(cache_key)
    if cached is not None:
      return cached
    
    try:
      # Получаем TXT записи
      answers = self.resolver.resolve(domain, 'TXT', lifetime=self.timeout)
      spf_record = None
      
      for rdata in answers:
        txt = str(rdata).strip('"')
        if txt.startswith('v=spf1'):
          spf_record = txt
          break
      
      if not spf_record:
        return CheckResult(
          name="spf",
          status=CheckStatus.WARN,
          score=-0.5,
          title="SPF запись не найдена",
          description=f"Домен {domain} не имеет SPF записи",
          details={"domain": domain}
        )
      
      # Анализируем SPF
      details = {
        "domain": domain,
        "spf_record": spf_record,
        "mechanisms": []
      }
      
      # Парсим механизмы
      parts = spf_record.split()
      policy = "neutral"
      
      for part in parts:
        if part.startswith('ip4:') or part.startswith('ip6:'):
          details["mechanisms"].append(part)
        elif part.startswith('include:'):
          details["mechanisms"].append(part)
        elif part in ['-all', '~all', '?all', '+all']:
          policy = part
          details["policy"] = policy
      
      # Оцениваем политику
      if policy == '-all':
        result = CheckResult(
          name="spf",
          status=CheckStatus.PASS,
          score=0.5,
          title="SPF настроен корректно",
          description=f"Строгая политика SPF (-all)",
          details=details
        )
      elif policy == '~all':
        result = CheckResult(
          name="spf",
          status=CheckStatus.PASS,
          score=0.3,
          title="SPF настроен",
          description=f"Мягкая политика SPF (~all)",
          details=details
        )
      else:
        result = CheckResult(
          name="spf",
          status=CheckStatus.WARN,
          score=0.0,
          title="SPF настроен слабо",
          description=f"Нестрогая политика SPF ({policy})",
          details=details
        )
      
      self._cache.set(cache_key, result)
      return result
        
    except dns.resolver.NXDOMAIN:
      result = CheckResult(
        name="spf",
        status=CheckStatus.FAIL,
        score=-1.0,
        title="Домен не существует",
        description=f"Домен {domain} не найден в DNS"
      )
      self._cache.set(cache_key, result)
      return result
    except dns.resolver.NoAnswer:
      result = CheckResult(
        name="spf",
        status=CheckStatus.WARN,
        score=-0.5,
        title="SPF запись отсутствует",
        description=f"Нет TXT записей для {domain}"
      )
      self._cache.set(cache_key, result)
      return result
    except Exception as e:
      return CheckResult(
        name="spf",
        status=CheckStatus.ERROR,
        title="Ошибка проверки SPF",
        description=str(e)
      )
  
  def check_dkim(self, domain: str, selector: str = None) -> CheckResult:
    """Проверить DKIM запись"""
    if not HAS_DNS:
      return CheckResult(
        name="dkim",
        status=CheckStatus.ERROR,
        title="DKIM проверка недоступна",
        description="Библиотека dnspython не установлена"
      )
    
    # Проверяем кеш
    cache_key = f"dkim:{domain}:{selector or 'auto'}"
    cached = self._cache.get(cache_key)
    if cached is not None:
      return cached
    
    # Типичные селекторы (уменьшил количество для скорости)
    selectors = [selector] if selector else [
      'default', 'google', 'selector1', 'selector2', 'dkim'
    ]
    
    for sel in selectors:
      dkim_domain = f"{sel}._domainkey.{domain}"
      try:
        answers = self.resolver.resolve(dkim_domain, 'TXT', lifetime=self.timeout)
        
        for rdata in answers:
          txt = str(rdata).strip('"').replace('" "', '')
          if 'v=DKIM1' in txt or 'k=rsa' in txt:
            # Парсим ключ
            details = {
              "domain": domain,
              "selector": sel,
              "dkim_domain": dkim_domain,
              "record": txt[:200] + "..." if len(txt) > 200 else txt
            }
            
            # Проверяем длину ключа
            if 'p=' in txt:
              key_match = re.search(r'p=([A-Za-z0-9+/=]+)', txt)
              if key_match:
                key_len = len(key_match.group(1)) * 6 // 8 * 8  # Примерная длина в битах
                details["key_length_approx"] = key_len
                
                if key_len >= 2048:
                  result = CheckResult(
                    name="dkim",
                    status=CheckStatus.PASS,
                    score=0.5,
                    title="DKIM настроен корректно",
                    description=f"Найден DKIM ключ (селектор: {sel})",
                    details=details
                  )
                  self._cache.set(cache_key, result)
                  return result
                elif key_len >= 1024:
                  result = CheckResult(
                    name="dkim",
                    status=CheckStatus.PASS,
                    score=0.3,
                    title="DKIM настроен",
                    description=f"DKIM ключ найден, но рекомендуется 2048 бит",
                    details=details
                  )
                  self._cache.set(cache_key, result)
                  return result
            
            result = CheckResult(
              name="dkim",
              status=CheckStatus.PASS,
              score=0.3,
              title="DKIM настроен",
              description=f"Найден DKIM ключ (селектор: {sel})",
              details=details
            )
            self._cache.set(cache_key, result)
            return result
            
      except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        continue
      except Exception:
        continue
    
    result = CheckResult(
      name="dkim",
      status=CheckStatus.WARN,
      score=-0.3,
      title="DKIM не найден",
      description=f"Не удалось найти DKIM запись для {domain}",
      details={"domain": domain, "checked_selectors": selectors}
    )
    self._cache.set(cache_key, result)
    return result
  
  def check_dmarc(self, domain: str) -> CheckResult:
    """Проверить DMARC запись"""
    if not HAS_DNS:
      return CheckResult(
        name="dmarc",
        status=CheckStatus.ERROR,
        title="DMARC проверка недоступна",
        description="Библиотека dnspython не установлена"
      )
    
    # Проверяем кеш
    cache_key = f"dmarc:{domain}"
    cached = self._cache.get(cache_key)
    if cached is not None:
      return cached
    
    dmarc_domain = f"_dmarc.{domain}"
    
    try:
      answers = self.resolver.resolve(dmarc_domain, 'TXT', lifetime=self.timeout)
      
      for rdata in answers:
        txt = str(rdata).strip('"')
        if txt.startswith('v=DMARC1'):
          # Парсим политику
          details = {
            "domain": domain,
            "dmarc_record": txt
          }
          
          policy = "none"
          if 'p=reject' in txt:
            policy = "reject"
          elif 'p=quarantine' in txt:
            policy = "quarantine"
          elif 'p=none' in txt:
            policy = "none"
          
          details["policy"] = policy
          
          # Проверяем процент
          pct_match = re.search(r'pct=(\d+)', txt)
          if pct_match:
            details["pct"] = int(pct_match.group(1))
          
          if policy == "reject":
            result = CheckResult(
              name="dmarc",
              status=CheckStatus.PASS,
              score=0.5,
              title="DMARC настроен строго",
              description="Политика отклонения (reject)",
              details=details
            )
          elif policy == "quarantine":
            result = CheckResult(
              name="dmarc",
              status=CheckStatus.PASS,
              score=0.4,
              title="DMARC настроен",
              description="Политика карантина (quarantine)",
              details=details
            )
          else:
            result = CheckResult(
              name="dmarc",
              status=CheckStatus.WARN,
              score=0.1,
              title="DMARC в режиме мониторинга",
              description="Политика none - только мониторинг",
              details=details
            )
          
          self._cache.set(cache_key, result)
          return result
      
      result = CheckResult(
        name="dmarc",
        status=CheckStatus.WARN,
        score=-0.3,
        title="DMARC не настроен",
        description=f"DMARC запись не найдена для {domain}"
      )
      self._cache.set(cache_key, result)
      return result
      
    except dns.resolver.NXDOMAIN:
      result = CheckResult(
        name="dmarc",
        status=CheckStatus.WARN,
        score=-0.3,
        title="DMARC не настроен",
        description=f"DMARC запись отсутствует"
      )
      self._cache.set(cache_key, result)
      return result
    except dns.resolver.NoAnswer:
      result = CheckResult(
        name="dmarc",
        status=CheckStatus.WARN,
        score=-0.3,
        title="DMARC не настроен",
        description=f"Нет DMARC записи для {domain}"
      )
      self._cache.set(cache_key, result)
      return result
    except Exception as e:
      return CheckResult(
        name="dmarc",
        status=CheckStatus.ERROR,
        title="Ошибка проверки DMARC",
        description=str(e)
      )
  
  def check_reverse_dns(self, ip: str) -> CheckResult:
    """Проверить обратную DNS запись (PTR)"""
    if not HAS_DNS:
      return CheckResult(
        name="reverse_dns",
        status=CheckStatus.ERROR,
        title="rDNS проверка недоступна",
        description="Библиотека dnspython не установлена"
      )
    
    try:
      # Формируем PTR запрос
      parts = ip.split('.')
      if len(parts) != 4:
        return CheckResult(
          name="reverse_dns",
          status=CheckStatus.ERROR,
          title="Некорректный IP",
          description=f"Невалидный IPv4 адрес: {ip}"
        )
      
      ptr_domain = f"{'.'.join(reversed(parts))}.in-addr.arpa"
      answers = self.resolver.resolve(ptr_domain, 'PTR', lifetime=self.timeout)
      
      hostnames = [str(rdata).rstrip('.') for rdata in answers]
      
      if hostnames:
        return CheckResult(
          name="reverse_dns",
          status=CheckStatus.PASS,
          score=0.3,
          title="rDNS настроен",
          description=f"IP {ip} связан с {hostnames[0]}",
          details={"ip": ip, "hostnames": hostnames}
        )
      
      return CheckResult(
        name="reverse_dns",
        status=CheckStatus.WARN,
        score=-0.2,
        title="rDNS не настроен",
        description=f"Нет PTR записи для {ip}"
      )
      
    except Exception as e:
      return CheckResult(
        name="reverse_dns",
        status=CheckStatus.WARN,
        score=-0.2,
        title="rDNS не найден",
        description=f"Не удалось получить PTR для {ip}"
      )
  
  def check_mx(self, domain: str) -> CheckResult:
    """Проверить MX записи домена"""
    if not HAS_DNS:
      return CheckResult(
        name="mx",
        status=CheckStatus.ERROR,
        title="MX проверка недоступна",
        description="Библиотека dnspython не установлена"
      )
    
    # Проверяем кеш
    cache_key = f"mx:{domain}"
    cached = self._cache.get(cache_key)
    if cached is not None:
      return cached
    
    try:
      answers = self.resolver.resolve(domain, 'MX', lifetime=self.timeout)
      
      mx_records = []
      for rdata in answers:
        mx_records.append({
          "priority": rdata.preference,
          "host": str(rdata.exchange).rstrip('.')
        })
      
      mx_records.sort(key=lambda x: x["priority"])
      
      if mx_records:
        result = CheckResult(
          name="mx",
          status=CheckStatus.PASS,
          score=0.2,
          title="MX записи настроены",
          description=f"Найдено {len(mx_records)} MX записей",
          details={"domain": domain, "mx_records": mx_records}
        )
        self._cache.set(cache_key, result)
        return result
      
      result = CheckResult(
        name="mx",
        status=CheckStatus.WARN,
        score=-0.5,
        title="MX записи отсутствуют",
        description=f"Домен {domain} не имеет MX записей"
      )
      self._cache.set(cache_key, result)
      return result
      
    except Exception as e:
      result = CheckResult(
        name="mx",
        status=CheckStatus.WARN,
        score=-0.3,
        title="Ошибка проверки MX",
        description=str(e)
      )
      self._cache.set(cache_key, result)
      return result

