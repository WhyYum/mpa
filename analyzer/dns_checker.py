# -*- coding: utf-8 -*-
"""
Проверка DNS записей: SPF, DKIM, DMARC
"""

import re
from typing import Dict, Optional, Tuple, List
from .analysis_result import CheckResult, CheckStatus

try:
  import dns.resolver
  HAS_DNS = True
except ImportError:
  HAS_DNS = False


class DNSChecker:
  """Проверка DNS записей для аутентификации email"""
  
  def __init__(self):
    self.timeout = 5
  
  def check_spf(self, domain: str, sender_ip: str = None) -> CheckResult:
    """Проверить SPF запись"""
    if not HAS_DNS:
      return CheckResult(
        name="spf",
        status=CheckStatus.ERROR,
        title="SPF проверка недоступна",
        description="Библиотека dnspython не установлена"
      )
    
    try:
      # Получаем TXT записи
      answers = dns.resolver.resolve(domain, 'TXT', lifetime=self.timeout)
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
        return CheckResult(
          name="spf",
          status=CheckStatus.PASS,
          score=0.5,
          title="SPF настроен корректно",
          description=f"Строгая политика SPF (-all)",
          details=details
        )
      elif policy == '~all':
        return CheckResult(
          name="spf",
          status=CheckStatus.PASS,
          score=0.3,
          title="SPF настроен",
          description=f"Мягкая политика SPF (~all)",
          details=details
        )
      else:
        return CheckResult(
          name="spf",
          status=CheckStatus.WARN,
          score=0.0,
          title="SPF настроен слабо",
          description=f"Нестрогая политика SPF ({policy})",
          details=details
        )
        
    except dns.resolver.NXDOMAIN:
      return CheckResult(
        name="spf",
        status=CheckStatus.FAIL,
        score=-1.0,
        title="Домен не существует",
        description=f"Домен {domain} не найден в DNS"
      )
    except dns.resolver.NoAnswer:
      return CheckResult(
        name="spf",
        status=CheckStatus.WARN,
        score=-0.5,
        title="SPF запись отсутствует",
        description=f"Нет TXT записей для {domain}"
      )
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
    
    # Типичные селекторы
    selectors = [selector] if selector else [
      'default', 'google', 'selector1', 'selector2', 'k1', 'dkim', 'mail', 's1', 's2'
    ]
    
    for sel in selectors:
      dkim_domain = f"{sel}._domainkey.{domain}"
      try:
        answers = dns.resolver.resolve(dkim_domain, 'TXT', lifetime=self.timeout)
        
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
                  return CheckResult(
                    name="dkim",
                    status=CheckStatus.PASS,
                    score=0.5,
                    title="DKIM настроен корректно",
                    description=f"Найден DKIM ключ (селектор: {sel})",
                    details=details
                  )
                elif key_len >= 1024:
                  return CheckResult(
                    name="dkim",
                    status=CheckStatus.PASS,
                    score=0.3,
                    title="DKIM настроен",
                    description=f"DKIM ключ найден, но рекомендуется 2048 бит",
                    details=details
                  )
            
            return CheckResult(
              name="dkim",
              status=CheckStatus.PASS,
              score=0.3,
              title="DKIM настроен",
              description=f"Найден DKIM ключ (селектор: {sel})",
              details=details
            )
            
      except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        continue
      except Exception:
        continue
    
    return CheckResult(
      name="dkim",
      status=CheckStatus.WARN,
      score=-0.3,
      title="DKIM не найден",
      description=f"Не удалось найти DKIM запись для {domain}",
      details={"domain": domain, "checked_selectors": selectors[:5]}
    )
  
  def check_dmarc(self, domain: str) -> CheckResult:
    """Проверить DMARC запись"""
    if not HAS_DNS:
      return CheckResult(
        name="dmarc",
        status=CheckStatus.ERROR,
        title="DMARC проверка недоступна",
        description="Библиотека dnspython не установлена"
      )
    
    dmarc_domain = f"_dmarc.{domain}"
    
    try:
      answers = dns.resolver.resolve(dmarc_domain, 'TXT', lifetime=self.timeout)
      
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
            return CheckResult(
              name="dmarc",
              status=CheckStatus.PASS,
              score=0.5,
              title="DMARC настроен строго",
              description="Политика отклонения (reject)",
              details=details
            )
          elif policy == "quarantine":
            return CheckResult(
              name="dmarc",
              status=CheckStatus.PASS,
              score=0.4,
              title="DMARC настроен",
              description="Политика карантина (quarantine)",
              details=details
            )
          else:
            return CheckResult(
              name="dmarc",
              status=CheckStatus.WARN,
              score=0.1,
              title="DMARC в режиме мониторинга",
              description="Политика none - только мониторинг",
              details=details
            )
      
      return CheckResult(
        name="dmarc",
        status=CheckStatus.WARN,
        score=-0.3,
        title="DMARC не настроен",
        description=f"DMARC запись не найдена для {domain}"
      )
      
    except dns.resolver.NXDOMAIN:
      return CheckResult(
        name="dmarc",
        status=CheckStatus.WARN,
        score=-0.3,
        title="DMARC не настроен",
        description=f"DMARC запись отсутствует"
      )
    except dns.resolver.NoAnswer:
      return CheckResult(
        name="dmarc",
        status=CheckStatus.WARN,
        score=-0.3,
        title="DMARC не настроен",
        description=f"Нет DMARC записи для {domain}"
      )
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
      answers = dns.resolver.resolve(ptr_domain, 'PTR', lifetime=self.timeout)
      
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
    
    try:
      answers = dns.resolver.resolve(domain, 'MX', lifetime=self.timeout)
      
      mx_records = []
      for rdata in answers:
        mx_records.append({
          "priority": rdata.preference,
          "host": str(rdata.exchange).rstrip('.')
        })
      
      mx_records.sort(key=lambda x: x["priority"])
      
      if mx_records:
        return CheckResult(
          name="mx",
          status=CheckStatus.PASS,
          score=0.2,
          title="MX записи настроены",
          description=f"Найдено {len(mx_records)} MX записей",
          details={"domain": domain, "mx_records": mx_records}
        )
      
      return CheckResult(
        name="mx",
        status=CheckStatus.WARN,
        score=-0.5,
        title="MX записи отсутствуют",
        description=f"Домен {domain} не имеет MX записей"
      )
      
    except Exception as e:
      return CheckResult(
        name="mx",
        status=CheckStatus.WARN,
        score=-0.3,
        title="Ошибка проверки MX",
        description=str(e)
      )

