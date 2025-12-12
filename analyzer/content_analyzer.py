# -*- coding: utf-8 -*-
"""
Анализ контента письма: текст, ссылки, вложения
"""

import re
from typing import List, Dict, Set, Tuple
from urllib.parse import urlparse
from .analysis_result import CheckResult, CheckStatus
from .data_loader import AnalysisData


class ContentAnalyzer:
  """Анализатор контента письма"""
  
  # URL shorteners
  URL_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 
    'buff.ly', 'j.mp', 'su.pr', 'tr.im', 'cli.gs', 'short.to',
    'cutt.ly', 'rb.gy', 'shorturl.at', 'tiny.cc', 'yourls.org'
  }
  
  # Опасные HTML теги
  DANGEROUS_TAGS = ['script', 'iframe', 'embed', 'object', 'applet', 'form']
  
  def __init__(self, data: AnalysisData):
    self.data = data
  
  def check_trigger_words(self, text: str, subject: str = "") -> CheckResult:
    """Проверить триггерные слова в тексте"""
    full_text = f"{subject} {text}".lower()
    
    found_words = {
      "urgent": [],
      "threat": [],
      "action": [],
      "money": [],
      "credential": []
    }
    
    categories = {
      "urgent_words": "urgent",
      "threat_words": "threat",
      "action_words": "action",
      "money_words": "money",
      "credential_words": "credential"
    }
    
    total_found = 0
    
    for json_key, cat_key in categories.items():
      words = self.data.get_trigger_words_by_category(json_key)
      for word in words:
        if word in full_text:
          found_words[cat_key].append(word)
          total_found += 1
    
    # Рассчитываем штраф
    score = 0.0
    
    if found_words["urgent"]:
      score -= 0.3 * min(len(found_words["urgent"]), 3)
    if found_words["threat"]:
      score -= 0.5 * min(len(found_words["threat"]), 3)
    if found_words["action"]:
      score -= 0.2 * min(len(found_words["action"]), 3)
    if found_words["money"]:
      score -= 0.4 * min(len(found_words["money"]), 3)
    if found_words["credential"]:
      score -= 0.6 * min(len(found_words["credential"]), 3)
    
    if total_found == 0:
      return CheckResult(
        name="trigger_words",
        status=CheckStatus.PASS,
        score=0.2,
        title="Подозрительные слова не найдены",
        description="Текст не содержит типичных фишинговых фраз"
      )
    elif total_found <= 2:
      return CheckResult(
        name="trigger_words",
        status=CheckStatus.WARN,
        score=score,
        title="Найдены подозрительные слова",
        description=f"Обнаружено {total_found} триггерных слов",
        details={"found": {k: v for k, v in found_words.items() if v}}
      )
    else:
      return CheckResult(
        name="trigger_words",
        status=CheckStatus.FAIL,
        score=score,
        title="Много подозрительных слов",
        description=f"Обнаружено {total_found} триггерных слов - признак фишинга",
        details={"found": {k: v for k, v in found_words.items() if v}}
      )
  
  def check_links(self, text: str, html: str = "") -> CheckResult:
    """Проверить ссылки в письме"""
    # Извлекаем ссылки
    url_pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+'
    
    text_urls = set(re.findall(url_pattern, text))
    html_urls = set(re.findall(url_pattern, html))
    all_urls = text_urls | html_urls
    
    if not all_urls:
      return CheckResult(
        name="links",
        status=CheckStatus.INFO,
        score=0.0,
        title="Ссылки отсутствуют",
        description="В письме нет ссылок"
      )
    
    issues = []
    suspicious_count = 0
    details = {"total_links": len(all_urls), "issues": []}
    
    for url in all_urls:
      try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # 1. Проверка URL shorteners (точное совпадение домена или поддомена)
        is_shortener = False
        for shortener in self.URL_SHORTENERS:
          # domain == shortener ИЛИ domain заканчивается на .shortener
          if domain == shortener or domain.endswith('.' + shortener):
            is_shortener = True
            break
        if is_shortener:
          issues.append(f"Сокращённая ссылка: {domain}")
          suspicious_count += 1
          continue
        
        # 2. Проверка подозрительного TLD
        is_suspicious, reasons = self.data.is_suspicious_domain(domain)
        if is_suspicious:
          issues.extend(reasons)
          suspicious_count += 1
          continue
        
        # 3. Проверка IP вместо домена
        if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
          issues.append(f"IP-адрес вместо домена: {domain}")
          suspicious_count += 1
          continue
        
        # 4. Проверка длинного домена (homograph attack)
        if len(domain) > 50:
          issues.append(f"Подозрительно длинный домен")
          suspicious_count += 1
        
        # 5. Проверка Unicode в домене (IDN homograph)
        try:
          domain.encode('ascii')
        except UnicodeEncodeError:
          issues.append(f"Unicode символы в домене (возможная подмена)")
          suspicious_count += 1
          
      except Exception:
        continue
    
    details["issues"] = issues[:10]  # Ограничиваем количество
    
    if suspicious_count == 0:
      return CheckResult(
        name="links",
        status=CheckStatus.PASS,
        score=0.1,
        title="Ссылки безопасны",
        description=f"Проверено {len(all_urls)} ссылок, проблем не найдено",
        details=details
      )
    elif suspicious_count <= 2:
      return CheckResult(
        name="links",
        status=CheckStatus.WARN,
        score=-0.5 * suspicious_count,
        title="Подозрительные ссылки",
        description=f"Найдено {suspicious_count} подозрительных ссылок",
        details=details
      )
    else:
      return CheckResult(
        name="links",
        status=CheckStatus.FAIL,
        score=-1.5,
        title="Опасные ссылки",
        description=f"Много подозрительных ссылок ({suspicious_count})",
        details=details
      )
  
  def check_attachments(self, attachments: List[Dict]) -> CheckResult:
    """Проверить вложения"""
    if not attachments:
      return CheckResult(
        name="attachments",
        status=CheckStatus.INFO,
        score=0.0,
        title="Нет вложений",
        description="Письмо не содержит вложений"
      )
    
    dangerous = []
    warnings = []
    details = {"total": len(attachments), "files": []}
    
    for att in attachments:
      filename = att.get("filename", "unknown")
      size = att.get("size", 0)
      
      is_dangerous, level, reason = self.data.is_dangerous_extension(filename)
      
      file_info = {
        "name": filename,
        "size": size,
        "level": level
      }
      details["files"].append(file_info)
      
      if is_dangerous:
        if level == "critical":
          dangerous.append(f"{filename}: {reason}")
        else:
          warnings.append(f"{filename}: {reason}")
    
    if dangerous:
      return CheckResult(
        name="attachments",
        status=CheckStatus.FAIL,
        score=-3.0,
        title="ОПАСНЫЕ ВЛОЖЕНИЯ!",
        description=f"Обнаружены критически опасные файлы",
        details={"dangerous": dangerous, "warnings": warnings, **details}
      )
    elif warnings:
      return CheckResult(
        name="attachments",
        status=CheckStatus.WARN,
        score=-0.5 * len(warnings),
        title="Потенциально опасные вложения",
        description=f"Найдено {len(warnings)} подозрительных файлов",
        details={"warnings": warnings, **details}
      )
    else:
      return CheckResult(
        name="attachments",
        status=CheckStatus.PASS,
        score=0.0,
        title="Вложения безопасны",
        description=f"Проверено {len(attachments)} вложений",
        details=details
      )
  
  def check_html_content(self, html: str) -> CheckResult:
    """Проверить HTML на опасные элементы"""
    if not html:
      return CheckResult(
        name="html_content",
        status=CheckStatus.INFO,
        score=0.0,
        title="HTML отсутствует",
        description="Письмо в текстовом формате"
      )
    
    html_lower = html.lower()
    found_dangerous = []
    
    for tag in self.DANGEROUS_TAGS:
      if f'<{tag}' in html_lower:
        found_dangerous.append(tag)
    
    # Проверка скрытых элементов
    hidden_patterns = [
      r'display\s*:\s*none',
      r'visibility\s*:\s*hidden',
      r'opacity\s*:\s*0',
      r'font-size\s*:\s*0'
    ]
    
    hidden_found = []
    for pattern in hidden_patterns:
      if re.search(pattern, html_lower):
        hidden_found.append(pattern.replace(r'\s*', ' ').replace(':', ''))
    
    # Проверка форм
    forms_count = len(re.findall(r'<form', html_lower))
    password_inputs = len(re.findall(r'type\s*=\s*["\']?password', html_lower))
    
    issues = []
    score = 0.0
    
    if found_dangerous:
      issues.append(f"Опасные теги: {', '.join(found_dangerous)}")
      score -= 1.0 * len(found_dangerous)
    
    if hidden_found:
      issues.append(f"Скрытый контент: {len(hidden_found)} элементов")
      score -= 0.5
    
    if forms_count > 0:
      issues.append(f"Формы в письме: {forms_count}")
      score -= 0.5 * forms_count
    
    if password_inputs > 0:
      issues.append(f"Поля ввода пароля: {password_inputs}")
      score -= 1.5
    
    if not issues:
      return CheckResult(
        name="html_content",
        status=CheckStatus.PASS,
        score=0.1,
        title="HTML контент безопасен",
        description="Опасные элементы не найдены"
      )
    
    status = CheckStatus.FAIL if score < -1.5 else CheckStatus.WARN
    return CheckResult(
      name="html_content",
      status=status,
      score=score,
      title="Подозрительный HTML",
      description="; ".join(issues),
      details={"issues": issues, "forms": forms_count, "password_fields": password_inputs}
    )
  
  def _is_domain_official(self, sender_domain: str, official_domains: list) -> bool:
    """Проверить, является ли домен официальным (включая поддомены)"""
    sender_lower = sender_domain.lower()
    
    for official in official_domains:
      official_lower = official.lower()
      # Точное совпадение
      if sender_lower == official_lower:
        return True
      # Поддомен (accounts.google.com -> google.com)
      if sender_lower.endswith('.' + official_lower):
        return True
    
    return False
  
  def _get_brand_for_domain(self, domain: str) -> str:
    """Получить бренд для домена (с учётом поддоменов)"""
    for brand_id, brand_data in self.data.brands.items():
      official_domains = brand_data.get("domains", [])
      if self._is_domain_official(domain, official_domains):
        return brand_data.get("name", brand_id)
    return None
  
  def check_brand_impersonation(self, from_email: str, from_name: str, 
                                 subject: str, text: str) -> CheckResult:
    """Проверить подмену бренда"""
    brand_keywords = self.data.get_brand_keywords()
    
    # Извлекаем домен отправителя
    sender_domain = from_email.split('@')[-1].lower() if '@' in from_email else ""
    
    # Проверяем упоминания брендов в теме и тексте
    full_text = f"{from_name} {subject} {text}".lower()
    
    mentioned_brands = set()
    for keyword, brand_name in brand_keywords.items():
      if keyword in full_text:
        mentioned_brands.add(brand_name)
    
    if not mentioned_brands:
      return CheckResult(
        name="brand_impersonation",
        status=CheckStatus.INFO,
        score=0.0,
        title="Бренды не упоминаются",
        description="В письме не обнаружены упоминания известных брендов"
      )
    
    # КРИТИЧЕСКАЯ ПРОВЕРКА: "официальное" имя + бесплатная почта = ФИШИНГ
    official_words = ['support', 'admin', 'security', 'team', 'service', 'help', 
                      'account', 'billing', 'verify', 'notification', 'alert',
                      'поддержка', 'служба', 'безопасность', 'команда']
    from_name_lower = from_name.lower()
    
    has_official_name = any(word in from_name_lower for word in official_words)
    is_free_email = sender_domain in self.data.free_email_domains
    
    if has_official_name and is_free_email:
      # Это явный фишинг - "Google Support" с gmail.com и т.п.
      return CheckResult(
        name="brand_impersonation",
        status=CheckStatus.FAIL,
        score=-3.0,
        title="ФИШИНГ: официальное имя с бесплатной почты!",
        description=f'"{from_name}" отправлено с бесплатной почты {sender_domain}',
        details={
          "from_name": from_name,
          "sender_domain": sender_domain,
          "mentioned_brands": list(mentioned_brands),
          "reason": "Официальные службы не используют бесплатную почту"
        }
      )
    
    # Определяем бренд отправителя (с учётом поддоменов)
    # НО исключаем бесплатные почтовые домены!
    sender_brand = None
    if not is_free_email:
      sender_brand = self._get_brand_for_domain(sender_domain)
    
    for brand in mentioned_brands:
      # Если упоминается бренд, но домен не принадлежит этому бренду
      if brand != sender_brand:
        # Проверяем, не является ли домен официальным для этого бренда
        # (исключая бесплатные почтовые домены)
        is_official = False
        if not is_free_email:
          for brand_id, brand_data in self.data.brands.items():
            if brand_data.get("name") == brand:
              official_domains = brand_data.get("domains", [])
              # Фильтруем бесплатные домены из списка официальных
              corporate_domains = [d for d in official_domains 
                                   if d not in self.data.free_email_domains]
              if self._is_domain_official(sender_domain, corporate_domains):
                is_official = True
                break
        
        if not is_official:
          return CheckResult(
            name="brand_impersonation",
            status=CheckStatus.FAIL,
            score=-2.5,
            title="Возможная подмена бренда!",
            description=f"Упоминается {brand}, но письмо с домена {sender_domain}",
            details={
              "mentioned_brands": list(mentioned_brands),
              "sender_domain": sender_domain,
              "expected_domains": self.data.brands.get(brand.lower(), {}).get("domains", [])
            }
          )
    
    # Если домен соответствует бренду (и это НЕ бесплатная почта)
    if sender_brand and sender_brand in mentioned_brands and not is_free_email:
      return CheckResult(
        name="brand_impersonation",
        status=CheckStatus.PASS,
        score=0.5,
        title="Бренд подтверждён",
        description=f"Письмо от {sender_brand} с официального домена",
        details={"brand": sender_brand, "domain": sender_domain}
      )
    
    return CheckResult(
      name="brand_impersonation",
      status=CheckStatus.INFO,
      score=0.0,
      title="Упоминаются бренды",
      description=f"Упомянуты: {', '.join(mentioned_brands)}",
      details={"mentioned_brands": list(mentioned_brands)}
    )

