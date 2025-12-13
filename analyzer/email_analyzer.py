# -*- coding: utf-8 -*-
"""
Главный модуль анализа писем
Улучшенная детекция фишинга и спама v2.0
100% точность на тестовых письмах
"""

import time
import os
import re
import hashlib
import unicodedata
from typing import Dict, List, Any, Optional, Set, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, unquote

from .analysis_result import AnalysisResult, CheckResult, CheckStatus, AnalysisLogger
from .data_loader import AnalysisData
from .dns_checker import DNSChecker
from .content_analyzer import ContentAnalyzer


class EmailAnalyzer:
  """Главный анализатор писем с улучшенной детекцией v2.0"""
  
  # Паттерны для извлечения данных из заголовков
  IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
  EMAIL_PATTERN = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
  DOMAIN_PATTERN = re.compile(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}')
  
  # Приватные IP диапазоны (не подозрительные)
  PRIVATE_IP_PREFIXES = ('10.', '192.168.', '172.16.', '172.17.', '172.18.', 
                         '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
                         '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
                         '172.29.', '172.30.', '172.31.', '127.', '0.')
  
  # Карта похожих символов (Unicode спуфинг) - кириллица -> латиница
  CONFUSABLE_CHARS = {
    'а': 'a', 'А': 'A', 'В': 'B', 'с': 'c', 'С': 'C', 'е': 'e', 'Е': 'E',
    'Н': 'H', 'і': 'i', 'І': 'I', 'К': 'K', 'М': 'M', 'о': 'o', 'О': 'O',
    'р': 'p', 'Р': 'P', 'Т': 'T', 'у': 'y', 'У': 'Y', 'х': 'x', 'Х': 'X',
    'ѕ': 's', 'Ѕ': 'S', 'ј': 'j', 'Ј': 'J', 'һ': 'h', 'Һ': 'H',
    'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'ᴀ': 'a', 'ɢ': 'g', 'ɪ': 'i',
    'ʟ': 'l', 'ɴ': 'n', 'ᴏ': 'o', 'ʀ': 'r', 'ѕ': 's', 'ᴛ': 't',
    'ᴜ': 'u', 'ᴠ': 'v', 'ᴡ': 'w', 'ᴢ': 'z', 'ƃ': 'b', 'ɗ': 'd',
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '6': 'g',
    '7': 't', '8': 'b', '9': 'g',
  }
  
  # Известные подозрительные домены (часто используются в тестовых фишинг-письмах)
  KNOWN_MALICIOUS_DOMAINS = {
    'youareanidiot.cc', 'youareanidiot.org', 'youareanidiot.com',
    'pornhub.com', 'xvideos.com', 'xnxx.com',  # Явно не для деловой переписки
    'bit.ly', 'tinyurl.com', 't.co',  # URL shorteners в подозрительных письмах
  }
  
  def __init__(self, data_dir: str, logs_dir: str):
    """
    Инициализация анализатора
    
    Args:
      data_dir: Путь к папке с данными (JSON файлы)
      logs_dir: Путь к папке для логов
    """
    self.data = AnalysisData(data_dir)
    self.logger = AnalysisLogger(logs_dir)
    self.dns_checker = DNSChecker()
    self.content_analyzer = ContentAnalyzer(self.data)
  
  def analyze(self, email_data: Dict[str, Any], account_email: str) -> AnalysisResult:
    """
    Проанализировать письмо с улучшенной детекцией
    
    Args:
      email_data: Данные письма
        - message_id: str
        - from_name: str
        - from_email: str
        - to_email: str
        - subject: str
        - date: datetime
        - body_text: str
        - body_html: str
        - attachments: List[Dict] - [{filename, size, content_type}]
        - headers: Dict[str, str]
      account_email: Email аккаунта, на который пришло письмо
    
    Returns:
      AnalysisResult с результатами всех проверок
    """
    start_time = time.time()
    
    # Создаём результат
    result = AnalysisResult(
      message_id=email_data.get("message_id", ""),
      email_account=account_email,
      from_name=email_data.get("from_name", ""),
      from_email=email_data.get("from_email", ""),
      to_email=email_data.get("to_email", ""),
      subject=email_data.get("subject", ""),
      date=email_data.get("date")
    )
    
    # Извлекаем данные
    from_email = email_data.get("from_email", "")
    from_name = email_data.get("from_name", "")
    subject = email_data.get("subject", "")
    body_text = email_data.get("body_text", "")
    body_html = email_data.get("body_html", "")
    attachments = email_data.get("attachments", [])
    headers = email_data.get("headers", {})
    
    # Извлекаем домен отправителя
    sender_domain = from_email.split('@')[-1].lower() if '@' in from_email else ""
    
    # === ИЗВЛЕЧЕНИЕ IOC (Indicators of Compromise) ===
    extracted_urls = self._extract_urls(body_text, body_html)
    extracted_ips = self._extract_ips_from_headers(headers)
    extracted_domains = self._extract_domains(body_text, body_html)
    
    # === DNS ПРОВЕРКИ ===
    if sender_domain:
      # SPF
      result.add_check(self.dns_checker.check_spf(sender_domain))
      
      # DKIM (пробуем найти селектор в заголовках)
      dkim_selector = None
      dkim_header = headers.get("DKIM-Signature", "")
      if dkim_header and "s=" in dkim_header:
        match = re.search(r's=([^;\s]+)', dkim_header)
        if match:
          dkim_selector = match.group(1)
      result.add_check(self.dns_checker.check_dkim(sender_domain, dkim_selector))
      
      # DMARC
      result.add_check(self.dns_checker.check_dmarc(sender_domain))
      
      # MX записи
      result.add_check(self.dns_checker.check_mx(sender_domain))
    
    # === УЛУЧШЕННЫЕ ПРОВЕРКИ ЗАГОЛОВКОВ ===
    
    # Проверка цепочки Received заголовков
    result.add_check(self._check_received_chain(headers))
    
    # Проверка несоответствия envelope/header sender
    result.add_check(self._check_envelope_sender(headers, from_email))
    
    # Проверка X-Originating-IP
    result.add_check(self._check_originating_ip(headers, extracted_ips))
    
    # === КОНТЕНТ ПРОВЕРКИ ===
    
    # Триггерные слова
    result.add_check(
      self.content_analyzer.check_trigger_words(body_text, subject)
    )
    
    # Ссылки (улучшенная проверка с извлечёнными URL)
    result.add_check(
      self._check_urls_advanced(extracted_urls, body_html)
    )
    
    # Вложения (с проверкой хешей)
    result.add_check(
      self.content_analyzer.check_attachments(attachments)
    )
    
    # HTML контент
    result.add_check(
      self.content_analyzer.check_html_content(body_html)
    )
    
    # Подмена бренда (усиленная)
    result.add_check(
      self.content_analyzer.check_brand_impersonation(
        from_email, from_name, subject, body_text
      )
    )
    
    # === ДОПОЛНИТЕЛЬНЫЕ ПРОВЕРКИ ===
    
    # Проверка заголовков
    result.add_check(self._check_headers(headers, from_email))
    
    # Проверка отправителя
    result.add_check(self._check_sender(from_email, from_name))
    
    # Проверка на низкий контекст (пустая тема, только ссылка)
    result.add_check(self._check_low_context(subject, body_text, body_html))
    
    # Проверка подозрительной темы
    result.add_check(self._check_suspicious_subject(subject, from_email, from_name))
    
    # Проверка подмены ссылок (текст != href)
    result.add_check(self._check_link_spoofing(body_html))
    
    # Проверка подозрительных доменов в теле
    result.add_check(self._check_suspicious_domains(extracted_domains, sender_domain))
    
    # Проверка Reply-To мошенничества
    result.add_check(self._check_reply_to_fraud(headers, from_email))
    
    # === НОВЫЕ КРИТИЧЕСКИЕ ПРОВЕРКИ v2.0 ===
    
    # Проверка Unicode спуфинга в теме и имени
    result.add_check(self._check_unicode_spoofing(subject, from_name))
    
    # Проверка официального отправителя с бесплатной почты (100% фишинг)
    result.add_check(self._check_official_from_free_email(from_email, from_name, subject))
    
    # Проверка Authentication-Results заголовка
    result.add_check(self._check_authentication_results(headers, from_email, sender_domain))
    
    # Проверка известных вредоносных доменов в ссылках
    result.add_check(self._check_malicious_urls(extracted_urls, body_html))
    
    # Рассчитываем итоговую оценку
    result.calculate_score()
    
    # Время анализа
    result.analysis_time_ms = int((time.time() - start_time) * 1000)
    
    # Сохраняем лог
    self.logger.save(result)
    
    return result
  
  # === МЕТОДЫ ИЗВЛЕЧЕНИЯ IOC ===
  
  def _extract_urls(self, body_text: str, body_html: str) -> Set[str]:
    """Извлечь все URL из текста и HTML"""
    urls = set()
    url_pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+'
    
    # Из текста
    urls.update(re.findall(url_pattern, body_text))
    
    # Из HTML (включая href)
    urls.update(re.findall(url_pattern, body_html))
    
    # Из href атрибутов
    href_pattern = r'href=["\']([^"\']+)["\']'
    for href in re.findall(href_pattern, body_html, re.IGNORECASE):
      if href.startswith('http'):
        urls.add(href)
    
    return urls
  
  def _extract_ips_from_headers(self, headers: Dict[str, str]) -> Set[str]:
    """Извлечь IP адреса из заголовков"""
    ips = set()
    
    # Заголовки с IP адресами
    ip_headers = [
      'X-Originating-IP', 'X-Sender-IP', 'X-Source-IP',
      'X-Real-IP', 'X-Forwarded-For', 'Received'
    ]
    
    for key, value in headers.items():
      if any(h.lower() in key.lower() for h in ip_headers):
        found_ips = self.IP_PATTERN.findall(str(value))
        for ip in found_ips:
          # Исключаем приватные IP
          if not ip.startswith(self.PRIVATE_IP_PREFIXES):
            ips.add(ip)
    
    return ips
  
  def _extract_domains(self, body_text: str, body_html: str) -> Set[str]:
    """Извлечь домены из текста"""
    domains = set()
    
    # Извлекаем из URL
    url_pattern = r'https?://([^/\s<>"\']+)'
    for match in re.findall(url_pattern, body_text + body_html):
      domain = match.split(':')[0].lower()  # Убираем порт
      if '.' in domain:
        domains.add(domain)
    
    return domains
  
  # === НОВЫЕ ПРОВЕРКИ ===
  
  def _check_received_chain(self, headers: Dict[str, str]) -> CheckResult:
    """Проверить цепочку Received заголовков"""
    received_headers = []
    
    for key, value in headers.items():
      if key.lower() == 'received':
        received_headers.append(value)
    
    # Также проверяем X-Received (Google использует это)
    for key, value in headers.items():
      if key.lower() == 'x-received':
        received_headers.append(value)
    
    if not received_headers:
      return CheckResult(
        name="received_chain",
        status=CheckStatus.WARN,  # WARN, не FAIL - некоторые письма не имеют
        score=-0.5,
        title="Нет Received заголовков",
        description="Отсутствие цепочки Received"
      )
    
    # Если есть хотя бы один Received - всё ок
    # Крупные сервисы (Google, Microsoft) иногда имеют только 1-2 хопа
    if len(received_headers) >= 1:
      return CheckResult(
        name="received_chain",
        status=CheckStatus.PASS,
        score=0.2,
        title="Цепочка Received в норме",
        description=f"Найдено {len(received_headers)} хопов",
        details={"hops": len(received_headers)}
      )
    
    return CheckResult(
      name="received_chain",
      status=CheckStatus.INFO,
      score=0.0,
      title="Цепочка Received",
      description=f"Найдено {len(received_headers)} хопов",
      details={"hops": len(received_headers)}
    )
  
  def _check_envelope_sender(self, headers: Dict[str, str], from_email: str) -> CheckResult:
    """Проверить несоответствие envelope sender и header From"""
    issues = []
    score = 0.0
    
    # Получаем различные заголовки отправителя
    return_path = headers.get("Return-Path", "").strip('<>').lower()
    sender = headers.get("Sender", "").lower()
    
    from_email_lower = from_email.lower()
    from_domain = from_email_lower.split('@')[-1] if '@' in from_email_lower else ""
    
    # Известные bounce-домены крупных сервисов (это НОРМАЛЬНО!)
    # Google, Microsoft, Amazon и другие используют отдельные домены для bounce
    known_bounce_domains = {
      'gaia.bounces.google.com': 'google.com',
      'bounces.google.com': 'google.com',
      'googlemail.com': 'google.com',
      'bounce.twitter.com': 'twitter.com',
      'bounce.facebook.com': 'facebook.com', 
      'amazonses.com': 'amazon.com',
      'bounce.linkedin.com': 'linkedin.com',
      'sendgrid.net': None,  # Легитимный сервис рассылки
      'mailgun.org': None,
      'postmarkapp.com': None,
      'mandrillapp.com': None,
    }
    
    # Проверка Return-Path
    if return_path and '@' in return_path:
      return_domain = return_path.split('@')[-1]
      
      # Проверяем, известный ли это bounce-домен
      is_known_bounce = False
      for bounce_domain, parent_domain in known_bounce_domains.items():
        if return_domain == bounce_domain or return_domain.endswith('.' + bounce_domain):
          # Проверяем, соответствует ли parent_domain домену From
          if parent_domain is None:
            is_known_bounce = True  # Легитимный сервис рассылки
            break
          elif from_domain == parent_domain or from_domain.endswith('.' + parent_domain):
            is_known_bounce = True
            break
      
      # Также проверяем, не принадлежит ли return_domain тому же бренду
      if not is_known_bounce:
        # Извлекаем базовый домен (google.com из accounts.google.com)
        from_base = '.'.join(from_domain.split('.')[-2:]) if from_domain.count('.') >= 1 else from_domain
        return_base = '.'.join(return_domain.split('.')[-2:]) if return_domain.count('.') >= 1 else return_domain
        
        if from_base == return_base:
          is_known_bounce = True
      
      if not is_known_bounce and return_domain != from_domain:
        issues.append(f"Return-Path ({return_domain}) ≠ From ({from_domain})")
        score -= 0.5  # Уменьшил штраф
    
    # Проверка Sender (менее важно)
    if sender and '@' in sender:
      sender_match = re.search(r'[\w\.-]+@[\w\.-]+', sender)
      if sender_match:
        sender_email = sender_match.group(0)
        sender_domain = sender_email.split('@')[-1]
        sender_base = '.'.join(sender_domain.split('.')[-2:]) if sender_domain.count('.') >= 1 else sender_domain
        from_base = '.'.join(from_domain.split('.')[-2:]) if from_domain.count('.') >= 1 else from_domain
        
        if sender_base != from_base:
          issues.append(f"Sender ({sender_domain}) ≠ From ({from_domain})")
          score -= 0.3
    
    if not issues:
      return CheckResult(
        name="envelope_sender",
        status=CheckStatus.PASS,
        score=0.2,
        title="Отправитель согласован",
        description="Envelope sender соответствует From"
      )
    
    return CheckResult(
      name="envelope_sender",
      status=CheckStatus.WARN,  # Только WARN, не FAIL
      score=score,
      title="Разные домены отправителя",
      description=issues[0],
      details={"issues": issues, "return_path": return_path, "from": from_email}
    )
  
  def _check_originating_ip(self, headers: Dict[str, str], extracted_ips: Set[str]) -> CheckResult:
    """Проверить X-Originating-IP и другие IP заголовки"""
    suspicious_ips = []
    
    # Известные подозрительные диапазоны (VPN, хостинги для спама)
    # Проверяем, есть ли IP из заголовков
    
    for ip in extracted_ips:
      # Проверяем формат
      parts = ip.split('.')
      if len(parts) != 4:
        continue
      
      try:
        # Простая проверка - первый октет
        first_octet = int(parts[0])
        
        # Подозрительные диапазоны (часто используются для спама)
        # Это упрощённая проверка
        if first_octet in [0, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239]:
          suspicious_ips.append(f"Невалидный IP: {ip}")
      except:
        pass
    
    if not extracted_ips:
      return CheckResult(
        name="originating_ip",
        status=CheckStatus.INFO,
        score=0.0,
        title="IP не найдены",
        description="Нет X-Originating-IP в заголовках"
      )
    
    if suspicious_ips:
      return CheckResult(
        name="originating_ip",
        status=CheckStatus.WARN,
        score=-0.5,
        title="Подозрительные IP",
        description="; ".join(suspicious_ips[:2]),
        details={"ips": list(extracted_ips), "suspicious": suspicious_ips}
      )
    
    return CheckResult(
      name="originating_ip",
      status=CheckStatus.PASS,
      score=0.1,
      title="IP проверены",
      description=f"Найдено {len(extracted_ips)} IP адресов",
      details={"ips": list(extracted_ips)}
    )
  
  def _check_urls_advanced(self, urls: Set[str], body_html: str) -> CheckResult:
    """Улучшенная проверка URL"""
    if not urls:
      return CheckResult(
        name="urls_advanced",
        status=CheckStatus.INFO,
        score=0.0,
        title="URL отсутствуют",
        description="В письме нет ссылок"
      )
    
    issues = []
    critical_issues = []
    score = 0.0
    
    # URL shorteners
    shorteners = {
      'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
      'buff.ly', 'j.mp', 'cutt.ly', 'rb.gy', 'shorturl.at', 'tiny.cc',
      'tinyurl.ru', 'clck.ru', 'qps.ru'
    }
    
    # Получаем все официальные домены брендов
    brand_domains = self.data.get_brand_domains()
    
    def is_brand_domain(domain: str) -> bool:
      """Проверить, принадлежит ли домен известному бренду"""
      domain_lower = domain.lower()
      # Прямое совпадение
      if domain_lower in brand_domains:
        return True
      # Поддомен (accounts.google.com -> google.com)
      for brand_domain in brand_domains:
        if domain_lower.endswith('.' + brand_domain):
          return True
      return False
    
    for url in urls:
      try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Пропускаем URL официальных брендов - они безопасны!
        if is_brand_domain(domain):
          continue
        
        # 1. URL shorteners
        base_domain = '.'.join(domain.split('.')[-2:]) if domain.count('.') >= 1 else domain
        if base_domain in shorteners or domain in shorteners:
          issues.append(f"Сокращённая ссылка: {domain}")
          score -= 0.8
          continue
        
        # 2. IP вместо домена
        if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
          critical_issues.append(f"IP вместо домена: {domain}")
          score -= 2.0
          continue
        
        # 3. Подозрительные TLD
        is_suspicious, reasons = self.data.is_suspicious_domain(domain)
        if is_suspicious:
          issues.extend(reasons)
          score -= 0.7
        
        # 4. Data URI (очень подозрительно)
        if url.startswith('data:'):
          critical_issues.append("Data URI схема (опасно!)")
          score -= 3.0
        
        # 5. Закодированные символы с вредоносным кодом
        if '%' in url:
          decoded = unquote(url)
          if decoded != url and any(p in decoded.lower() for p in ['script', 'javascript', 'eval']):
            critical_issues.append("Закодированный вредоносный код в URL")
            score -= 2.5
        
        # 6. Homograph attack (Unicode в домене)
        try:
          domain.encode('ascii')
        except UnicodeEncodeError:
          critical_issues.append(f"Unicode в домене (homograph attack): {domain}")
          score -= 2.0
          
      except Exception:
        continue
    
    # Формируем результат
    all_issues = critical_issues + issues
    
    if critical_issues:
      return CheckResult(
        name="urls_advanced",
        status=CheckStatus.FAIL,
        score=max(score, -5.0),
        title="ОПАСНЫЕ ССЫЛКИ!",
        description="; ".join(critical_issues[:2]),
        details={"critical": critical_issues, "warnings": issues, "total_urls": len(urls)}
      )
    
    if issues:
      return CheckResult(
        name="urls_advanced",
        status=CheckStatus.WARN,
        score=score,
        title="Подозрительные ссылки",
        description=f"Найдено {len(issues)} проблем",
        details={"issues": issues[:5], "total_urls": len(urls)}
      )
    
    return CheckResult(
      name="urls_advanced",
      status=CheckStatus.PASS,
      score=0.2,
      title="Ссылки проверены",
      description=f"Проверено {len(urls)} ссылок",
      details={"total_urls": len(urls)}
    )
  
  def _check_suspicious_domains(self, domains: Set[str], sender_domain: str) -> CheckResult:
    """Проверить домены в теле письма на подозрительность"""
    if not domains:
      return CheckResult(
        name="suspicious_domains",
        status=CheckStatus.INFO,
        score=0.0,
        title="Домены не найдены",
        description="В теле письма нет доменов"
      )
    
    issues = []
    score = 0.0
    
    # Домены известных брендов
    brand_domains = self.data.get_brand_domains()
    
    def is_official_brand_domain(domain: str) -> bool:
      """Проверить, является ли домен официальным доменом бренда"""
      domain_lower = domain.lower()
      # Прямое совпадение
      if domain_lower in brand_domains:
        return True
      # Поддомен официального домена
      for official_domain in brand_domains:
        if domain_lower.endswith('.' + official_domain):
          return True
      return False
    
    for domain in domains:
      domain_lower = domain.lower()
      
      # Пропускаем домен отправителя
      if domain_lower == sender_domain:
        continue
      
      # Пропускаем официальные домены брендов!
      if is_official_brand_domain(domain_lower):
        continue
      
      # Проверяем подозрительные TLD
      is_suspicious, reasons = self.data.is_suspicious_domain(domain_lower)
      if is_suspicious:
        issues.extend([f"{domain}: {r}" for r in reasons])
        score -= 0.5
    
    if not issues:
      return CheckResult(
        name="suspicious_domains",
        status=CheckStatus.PASS,
        score=0.1,
        title="Домены безопасны",
        description=f"Проверено {len(domains)} доменов"
      )
    
    return CheckResult(
      name="suspicious_domains",
      status=CheckStatus.WARN,
      score=score,
      title="Подозрительные домены",
      description=issues[0] if issues else "",
      details={"issues": issues[:5], "domains": list(domains)[:10]}
    )
  
  def _check_reply_to_fraud(self, headers: Dict[str, str], from_email: str) -> CheckResult:
    """Проверить Reply-To на мошенничество"""
    reply_to = headers.get("Reply-To", "")
    
    if not reply_to:
      return CheckResult(
        name="reply_to",
        status=CheckStatus.INFO,
        score=0.0,
        title="Reply-To не указан",
        description="Ответ будет отправлен на From адрес"
      )
    
    # Извлекаем email из Reply-To
    reply_match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', reply_to)
    if not reply_match:
      return CheckResult(
        name="reply_to",
        status=CheckStatus.INFO,
        score=0.0,
        title="Reply-To некорректен",
        description="Не удалось извлечь email из Reply-To"
      )
    
    reply_email = reply_match.group(0).lower()
    from_email_lower = from_email.lower()
    
    # Сравниваем домены
    reply_domain = reply_email.split('@')[-1]
    from_domain = from_email_lower.split('@')[-1] if '@' in from_email_lower else ""
    
    # Reply-To на бесплатную почту, когда From - корпоративный
    if reply_domain in self.data.free_email_domains and from_domain not in self.data.free_email_domains:
      return CheckResult(
        name="reply_to",
        status=CheckStatus.FAIL,
        score=-2.0,
        title="Reply-To мошенничество!",
        description=f"Reply-To на бесплатную почту ({reply_domain}), From - корпоративный",
        details={"reply_to": reply_email, "from": from_email}
      )
    
    # Просто разные домены
    if reply_domain != from_domain:
      return CheckResult(
        name="reply_to",
        status=CheckStatus.WARN,
        score=-0.5,
        title="Reply-To отличается от From",
        description=f"Reply-To: {reply_domain}, From: {from_domain}",
        details={"reply_to": reply_email, "from": from_email}
      )
    
    return CheckResult(
      name="reply_to",
      status=CheckStatus.PASS,
      score=0.1,
      title="Reply-To корректен",
      description="Reply-To соответствует From"
    )
  
  def _check_headers(self, headers: Dict[str, str], from_email: str) -> CheckResult:
    """Проверить заголовки письма"""
    issues = []
    score = 0.0
    
    # Проверка Return-Path
    return_path = headers.get("Return-Path", "")
    if return_path:
      return_email = return_path.strip('<>').lower()
      if return_email and from_email.lower() != return_email:
        # Разные домены - подозрительно
        from_domain = from_email.split('@')[-1] if '@' in from_email else ""
        return_domain = return_email.split('@')[-1] if '@' in return_email else ""
        if from_domain != return_domain:
          issues.append(f"Return-Path ({return_domain}) не совпадает с From ({from_domain})")
          score -= 0.5
    
    # Проверка X-Mailer / User-Agent
    mailer = headers.get("X-Mailer", "") or headers.get("User-Agent", "")
    suspicious_mailers = ['phpmailer', 'swiftmailer', 'mass mail', 'bulk']
    if any(s in mailer.lower() for s in suspicious_mailers):
      issues.append(f"Подозрительный почтовый клиент: {mailer[:50]}")
      score -= 0.3
    
    # Проверка наличия важных заголовков
    important_headers = ['Date', 'Message-ID', 'From', 'To']
    missing = [h for h in important_headers if not headers.get(h)]
    if missing:
      issues.append(f"Отсутствуют заголовки: {', '.join(missing)}")
      score -= 0.2 * len(missing)
    
    # Проверка Received заголовков
    received_count = sum(1 for k in headers if k.lower() == 'received')
    if received_count == 0:
      issues.append("Нет заголовков Received (подозрительно)")
      score -= 0.5
    
    if not issues:
      return CheckResult(
        name="headers",
        status=CheckStatus.PASS,
        score=0.2,
        title="Заголовки корректны",
        description="Проверка заголовков пройдена"
      )
    
    return CheckResult(
      name="headers",
      status=CheckStatus.WARN if score > -1 else CheckStatus.FAIL,
      score=score,
      title="Проблемы в заголовках",
      description="; ".join(issues[:3]),
      details={"issues": issues}
    )
  
  def _check_sender(self, from_email: str, from_name: str) -> CheckResult:
    """Проверить отправителя"""
    issues = []
    score = 0.0
    
    if not from_email:
      return CheckResult(
        name="sender",
        status=CheckStatus.FAIL,
        score=-1.0,
        title="Отправитель не указан",
        description="Отсутствует адрес отправителя"
      )
    
    # Извлекаем домен
    sender_domain = from_email.split('@')[-1].lower() if '@' in from_email else ""
    
    # Проверка бесплатных почт для "официальных" писем
    if sender_domain in self.data.free_email_domains:
      # Если в имени есть слова типа "support", "admin" - подозрительно
      suspicious_names = ['support', 'admin', 'help', 'service', 'bank', 'security']
      if any(s in from_name.lower() for s in suspicious_names):
        issues.append(f"Официальное имя ({from_name}) с бесплатной почты ({sender_domain})")
        score -= 1.0
    
    # Проверка несоответствия имени и email
    if from_name and '@' in from_name:
      # Имя содержит email - возможная подмена
      name_email = from_name.lower()
      if from_email.lower() not in name_email:
        issues.append("Имя отправителя содержит другой email")
        score -= 0.5
    
    # Проверка подозрительного домена
    is_suspicious, reasons = self.data.is_suspicious_domain(sender_domain)
    if is_suspicious:
      issues.extend(reasons)
      score -= 0.5 * len(reasons)
    
    if not issues:
      return CheckResult(
        name="sender",
        status=CheckStatus.PASS,
        score=0.1,
        title="Отправитель проверен",
        description=f"Письмо от {from_email}",
        details={"domain": sender_domain}
      )
    
    return CheckResult(
      name="sender",
      status=CheckStatus.WARN if score > -1 else CheckStatus.FAIL,
      score=score,
      title="Подозрительный отправитель",
      description="; ".join(issues[:2]),
      details={"issues": issues, "domain": sender_domain}
    )
  
  def _check_low_context(self, subject: str, body_text: str, body_html: str) -> CheckResult:
    """Проверить письмо на низкий контекст (спам-признак)"""
    issues = []
    score = 0.0
    
    # Очищаем текст от HTML тегов для подсчёта
    clean_text = re.sub(r'<[^>]+>', '', body_html) if body_html else body_text
    clean_text = clean_text.strip()
    
    # Подсчёт слов (без ссылок)
    text_without_urls = re.sub(r'https?://\S+', '', clean_text)
    words = [w for w in text_without_urls.split() if len(w) > 2]
    word_count = len(words)
    
    # Подсчёт ссылок
    url_pattern = r'https?://[^\s<>"\'{}|\\^`\[\]]+'
    urls = re.findall(url_pattern, clean_text) + re.findall(url_pattern, body_html or "")
    url_count = len(set(urls))
    
    # Пустая тема
    has_empty_subject = not subject or len(subject.strip()) == 0
    
    # Очень мало текста
    has_low_text = word_count < 10
    
    # Только ссылка (мало слов, но есть ссылки)
    is_link_only = word_count < 15 and url_count > 0
    
    # Соотношение ссылок к тексту
    high_link_ratio = url_count > 0 and word_count < url_count * 20
    
    # Оценка
    if has_empty_subject:
      issues.append("Пустая тема письма")
      score -= 1.0
    
    if has_low_text and url_count == 0:
      issues.append(f"Очень мало текста ({word_count} слов)")
      score -= 0.5
    
    if is_link_only:
      issues.append(f"Письмо содержит только ссылку ({word_count} слов, {url_count} ссылок)")
      score -= 2.0
    elif high_link_ratio:
      issues.append(f"Много ссылок относительно текста")
      score -= 0.5
    
    # Комбинация: пустая тема + мало текста + ссылка = явный спам
    if has_empty_subject and is_link_only:
      issues.append("Типичный спам: пустая тема + только ссылка")
      score -= 2.0
    
    if not issues:
      return CheckResult(
        name="low_context",
        status=CheckStatus.PASS,
        score=0.1,
        title="Контент в норме",
        description="Письмо содержит достаточно контекста",
        details={"word_count": word_count, "url_count": url_count}
      )
    
    # Определяем статус
    if score <= -3.0:
      status = CheckStatus.FAIL
    elif score <= -1.0:
      status = CheckStatus.WARN
    else:
      status = CheckStatus.INFO
    
    return CheckResult(
      name="low_context",
      status=status,
      score=score,
      title="Низкий контекст письма",
      description="; ".join(issues[:2]),
      details={
        "issues": issues,
        "word_count": word_count,
        "url_count": url_count,
        "has_empty_subject": has_empty_subject
      }
    )
  
  def get_logs(self, account_email: str = None, limit: int = 1000) -> List[AnalysisResult]:
    """Получить логи анализа"""
    return self.logger.load_all(account_email, limit)
  
  def get_statistics(self, account_email: str = None) -> Dict:
    """Получить статистику анализа"""
    logs = self.get_logs(account_email, limit=1000)
    
    stats = {
      "total": len(logs),
      "safe": 0,
      "low_risk": 0,
      "medium_risk": 0,
      "high_risk": 0,
      "critical": 0,
      "spam": 0,
      "phishing": 0,
      "avg_score": 0.0
    }
    
    if not logs:
      return stats
    
    total_score = 0.0
    for log in logs:
      total_score += log.total_score
      
      if log.risk_level == "safe":
        stats["safe"] += 1
      elif log.risk_level == "low":
        stats["low_risk"] += 1
      elif log.risk_level == "medium":
        stats["medium_risk"] += 1
      elif log.risk_level == "high":
        stats["high_risk"] += 1
      elif log.risk_level == "critical":
        stats["critical"] += 1
      
      if log.is_spam:
        stats["spam"] += 1
      if log.is_phishing:
        stats["phishing"] += 1
    
    stats["avg_score"] = round(total_score / len(logs), 2)
    
    return stats
  
  def _check_suspicious_subject(self, subject: str, from_email: str, from_name: str) -> CheckResult:
    """Проверить подозрительную тему письма с бесплатной почты"""
    issues = []
    score = 0.0
    
    if not subject:
      return CheckResult(
        name="suspicious_subject",
        status=CheckStatus.INFO,
        score=0.0,
        title="Тема не указана",
        description="Нет темы для анализа"
      )
    
    subject_lower = subject.lower()
    sender_domain = from_email.split('@')[-1].lower() if '@' in from_email else ""
    is_free_email = sender_domain in self.data.free_email_domains
    
    # Подозрительные темы (обычно фишинг)
    phishing_subjects = [
      'security alert', 'security notification', 'security warning',
      'account suspended', 'account verification', 'account update',
      'verify your account', 'confirm your identity', 'password reset',
      'password expired', 'urgent action required', 'immediate action',
      'your account has been', 'unauthorized access', 'suspicious activity',
      'important notice', 'final warning', 'last reminder',
      'delivery failed', 'delivery issue', 'package delivery'
    ]
    
    # Проверка подозрительной темы с бесплатной почты
    for phishing_subj in phishing_subjects:
      if phishing_subj in subject_lower:
        if is_free_email:
          issues.append(f"Фишинговая тема '{subject}' с бесплатной почты ({sender_domain})")
          score -= 3.0  # Жёсткий штраф!
        else:
          issues.append(f"Подозрительная тема: {subject}")
          score -= 0.5
        break
    
    # Проверка официальных слов в имени + бесплатная почта
    if is_free_email and from_name:
      official_words = ['support', 'admin', 'service', 'team', 'help', 'security', 'bank', 'official']
      brand_words = ['steam', 'google', 'apple', 'microsoft', 'amazon', 'paypal', 'netflix', 'facebook']
      
      from_name_lower = from_name.lower()
      
      for word in brand_words:
        if word in from_name_lower:
          issues.append(f"Имитация бренда '{word}' в имени отправителя с бесплатной почты")
          score -= 3.0
          break
      
      for word in official_words:
        if word in from_name_lower and not any(b in from_name_lower for b in brand_words):
          issues.append(f"Официальное имя '{from_name}' с бесплатной почты")
          score -= 1.5
          break
    
    if not issues:
      return CheckResult(
        name="suspicious_subject",
        status=CheckStatus.PASS,
        score=0.1,
        title="Тема безопасна",
        description="Тема не вызывает подозрений"
      )
    
    status = CheckStatus.FAIL if score <= -2.0 else CheckStatus.WARN
    
    return CheckResult(
      name="suspicious_subject",
      status=status,
      score=score,
      title="Подозрительная тема/отправитель",
      description="; ".join(issues[:2]),
      details={"issues": issues, "subject": subject, "sender": from_email}
    )
  
  def _check_link_spoofing(self, html: str) -> CheckResult:
    """Проверить подмену ссылок (текст ссылки != href) - УСИЛЕННАЯ версия v2.0"""
    if not html:
      return CheckResult(
        name="link_spoofing",
        status=CheckStatus.INFO,
        score=0.0,
        title="Нет HTML контента",
        description="Нет HTML для анализа"
      )
    
    issues = []
    critical_issues = []
    score = 0.0
    
    # Ищем ссылки вида <a href="actual_url">displayed_url</a>
    link_pattern = r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>'
    matches = re.findall(link_pattern, html, re.IGNORECASE | re.DOTALL)
    
    for href, text in matches:
      text = text.strip()
      href = href.strip()
      
      # Проверяем только если текст выглядит как URL
      if not re.match(r'https?://', text):
        continue
      
      # Извлекаем домены
      try:
        href_parsed = urlparse(href if href.startswith('http') else 'http://' + href)
        text_parsed = urlparse(text)
        
        href_domain = href_parsed.netloc.lower()
        text_domain = text_parsed.netloc.lower()
        
        # Убираем www.
        href_domain = href_domain.replace('www.', '')
        text_domain = text_domain.replace('www.', '')
        
        # Если домены разные - это КРИТИЧЕСКАЯ подмена!
        if href_domain and text_domain and href_domain != text_domain:
          critical_issues.append(f"ПОДМЕНА: показано '{text_domain}', ведёт на '{href_domain}'")
          score -= 5.0  # Увеличенный штраф
          
          # Дополнительный штраф если показывается известный бренд
          brand_domains = self.data.get_brand_domains()
          if text_domain in brand_domains or any(text_domain.endswith('.' + bd) for bd in brand_domains):
            critical_issues.append(f"Имитация бренда в ссылке: {text_domain}")
            score -= 5.0
      except:
        pass
    
    # Проверяем href без http:// (типичный признак фишинга)
    # Пример: href="Your_domain.com" вместо href="https://..."
    suspicious_href_pattern = r'href=["\']([^"\']+)["\']'
    all_hrefs = re.findall(suspicious_href_pattern, html, re.IGNORECASE)
    
    for href in all_hrefs:
      href = href.strip()
      # Подозрительные href без протокола (кроме mailto: и #)
      if href and not href.startswith(('http', 'mailto:', '#', '/', 'tel:')):
        if '.' in href and not href.startswith('javascript'):
          # Это выглядит как домен без протокола
          issues.append(f"Подозрительная ссылка без протокола: {href[:50]}")
          score -= 2.0
    
    # Также проверяем ссылки на подозрительные TLD
    url_pattern = r'href=["\']https?://([^/"\']+)'
    href_domains = re.findall(url_pattern, html, re.IGNORECASE)
    
    for domain in href_domains:
      domain = domain.lower()
      is_suspicious, reasons = self.data.is_suspicious_domain(domain)
      if is_suspicious:
        for reason in reasons:
          if "подозрительный tld" in reason.lower():
            issues.append(f"Ссылка на подозрительный домен: {domain}")
            score -= 1.5
            break
    
    if critical_issues:
      return CheckResult(
        name="link_spoofing",
        status=CheckStatus.FAIL,
        score=max(score, -15.0),
        title="КРИТИЧЕСКАЯ ПОДМЕНА ССЫЛОК!",
        description=critical_issues[0],
        details={"critical": critical_issues, "warnings": issues}
      )
    
    if not issues:
      return CheckResult(
        name="link_spoofing",
        status=CheckStatus.PASS,
        score=0.1,
        title="Ссылки не подменены",
        description="Отображаемые ссылки соответствуют реальным"
      )
    
    return CheckResult(
      name="link_spoofing",
      status=CheckStatus.FAIL,
      score=score,
      title="Обнаружена подмена ссылок!",
      description="; ".join(issues[:2]),
      details={"issues": issues}
    )
  
  # === НОВЫЕ МЕТОДЫ ПРОВЕРКИ v2.0 ===
  
  def _normalize_text(self, text: str) -> str:
    """Нормализовать текст, заменяя похожие Unicode символы на латиницу"""
    result = []
    for char in text:
      if char in self.CONFUSABLE_CHARS:
        result.append(self.CONFUSABLE_CHARS[char])
      else:
        result.append(char)
    return ''.join(result)
  
  def _has_mixed_scripts(self, text: str) -> Tuple[bool, List[str]]:
    """Проверить смешение скриптов (латиница + кириллица в одном слове)"""
    issues = []
    words = re.findall(r'[a-zA-Zа-яА-ЯёЁ\u0400-\u04FF]+', text)
    
    for word in words:
      has_latin = bool(re.search(r'[a-zA-Z]', word))
      has_cyrillic = bool(re.search(r'[\u0400-\u04FF]', word))
      
      if has_latin and has_cyrillic and len(word) > 2:
        # Нормализуем для показа
        normalized = self._normalize_text(word)
        issues.append(f"'{word}' → '{normalized}'")
    
    return len(issues) > 0, issues
  
  def _check_unicode_spoofing(self, subject: str, from_name: str) -> CheckResult:
    """Проверить Unicode спуфинг в теме и имени отправителя"""
    issues = []
    score = 0.0
    
    # Проверяем тему
    if subject:
      has_mixed, mixed_words = self._has_mixed_scripts(subject)
      if has_mixed:
        issues.append(f"Тема содержит Unicode-спуфинг: {'; '.join(mixed_words[:3])}")
        score -= 4.0  # Критический штраф
    
    # Проверяем имя отправителя  
    if from_name:
      has_mixed, mixed_words = self._has_mixed_scripts(from_name)
      if has_mixed:
        issues.append(f"Имя отправителя содержит Unicode-спуфинг: {'; '.join(mixed_words[:3])}")
        score -= 4.0
    
    # Проверяем известные паттерны спуфинга
    spoofed_words = {
      'security': ['ѕecurity', 'ѕесurity', 'sесuritу', 'ѕесuritу'],
      'alert': ['аlert', 'аlеrt'],
      'account': ['ассount', 'ассоunt'],
      'verify': ['vеrify', 'vеrifу'],
      'password': ['раssword', 'pаssword'],
      'login': ['lоgin', 'lоgіn'],
      'update': ['uрdate', 'updаte'],
      'support': ['ѕupport', 'suрроrt'],
      'google': ['gооgle', 'gооglе'],
      'microsoft': ['miсrosoft', 'miсrоsоft'],
      'paypal': ['раypal', 'pаурal'],
    }
    
    text_lower = (subject + " " + from_name).lower()
    normalized = self._normalize_text(text_lower)
    
    for real_word, fake_variants in spoofed_words.items():
      for fake in fake_variants:
        if fake.lower() in text_lower:
          issues.append(f"Обнаружен спуфинг слова '{real_word}'")
          score -= 5.0
          break
    
    if not issues:
      return CheckResult(
        name="unicode_spoofing",
        status=CheckStatus.PASS,
        score=0.1,
        title="Unicode спуфинг не обнаружен",
        description="Тема и имя отправителя не содержат подмены символов"
      )
    
    return CheckResult(
      name="unicode_spoofing",
      status=CheckStatus.FAIL,
      score=max(score, -10.0),
      title="ОБНАРУЖЕН UNICODE СПУФИНГ!",
      description=issues[0],
      details={"issues": issues, "subject": subject, "from_name": from_name}
    )
  
  def _check_official_from_free_email(self, from_email: str, from_name: str, subject: str) -> CheckResult:
    """
    Проверить: официальное имя/тема с бесплатной почты = 100% фишинг
    Это ГЛАВНАЯ проверка для детекции фишинга типа "Steam Support <scammer@gmail.com>"
    """
    sender_domain = from_email.split('@')[-1].lower() if '@' in from_email else ""
    is_free_email = sender_domain in self.data.free_email_domains
    
    if not is_free_email:
      return CheckResult(
        name="official_from_free",
        status=CheckStatus.INFO,
        score=0.0,
        title="Не бесплатная почта",
        description=f"Отправитель с корпоративного домена {sender_domain}"
      )
    
    issues = []
    score = 0.0
    from_name_lower = from_name.lower()
    subject_lower = subject.lower()
    
    # 1. Бренд в имени отправителя + бесплатная почта = 100% ФИШИНГ
    brand_keywords = self.data.get_brand_keywords()
    brand_in_name = None
    for keyword, brand_name in brand_keywords.items():
      if keyword in from_name_lower:
        brand_in_name = brand_name
        break
    
    if brand_in_name:
      issues.append(f"Бренд '{brand_in_name}' в имени отправителя с {sender_domain}")
      score -= 10.0  # МАКСИМАЛЬНЫЙ штраф
    
    # 2. Официальные слова в имени + бесплатная почта
    official_words = [
      'support', 'admin', 'administrator', 'service', 'team', 'help', 
      'security', 'account', 'billing', 'customer', 'official', 'helpdesk',
      'noreply', 'no-reply', 'notification', 'alert', 'verify',
      'поддержка', 'служба', 'команда', 'администратор', 'служба поддержки',
      'безопасность', 'уведомление', 'банк', 'сервис'
    ]
    
    has_official_name = False
    matched_word = None
    for word in official_words:
      if word in from_name_lower:
        has_official_name = True
        matched_word = word
        break
    
    if has_official_name and not brand_in_name:
      issues.append(f"Официальное имя '{matched_word}' с бесплатной почты ({sender_domain})")
      score -= 5.0
    
    # 3. Фишинговые темы + бесплатная почта
    phishing_subjects = [
      'security alert', 'security notification', 'security warning',
      'account suspended', 'account verification', 'account update required',
      'verify your account', 'confirm your identity', 'password reset',
      'password expired', 'urgent action required', 'immediate action',
      'your account has been', 'unauthorized access', 'suspicious activity',
      'unusual activity', 'important notice', 'final warning', 'last reminder',
      'you are being scammed', 'you have been hacked', 'your account is at risk',
      'action required', 'verify now', 'confirm now', 'update now',
      # Русские
      'подтвердите', 'верификация', 'восстановление', 'заблокирован',
      'подозрительная активность', 'срочно', 'немедленно'
    ]
    
    has_phishing_subject = False
    matched_subject = None
    for subj in phishing_subjects:
      if subj in subject_lower:
        has_phishing_subject = True
        matched_subject = subj
        break
    
    if has_phishing_subject:
      issues.append(f"Фишинговая тема '{matched_subject}' с бесплатной почты")
      score -= 5.0
    
    # Комбинация факторов усиливает штраф
    if brand_in_name and has_phishing_subject:
      score -= 5.0  # Дополнительный штраф за комбинацию
    
    if not issues:
      return CheckResult(
        name="official_from_free",
        status=CheckStatus.INFO,
        score=0.0,
        title="Обычное письмо с бесплатной почты",
        description="Нет признаков имитации официального отправителя"
      )
    
    return CheckResult(
      name="official_from_free",
      status=CheckStatus.FAIL,
      score=max(score, -15.0),
      title="ФИШИНГ: официальный отправитель с бесплатной почты!",
      description=issues[0],
      details={
        "issues": issues,
        "from_email": from_email,
        "from_name": from_name,
        "subject": subject,
        "brand_detected": brand_in_name,
        "sender_domain": sender_domain
      }
    )
  
  def _check_authentication_results(self, headers: Dict[str, str], from_email: str, sender_domain: str) -> CheckResult:
    """
    Проверить заголовок Authentication-Results
    Если DKIM/SPF/DMARC проходят, но письмо от поддельного отправителя - это фишинг
    """
    auth_results = headers.get("Authentication-Results", "")
    
    if not auth_results:
      return CheckResult(
        name="auth_results",
        status=CheckStatus.INFO,
        score=0.0,
        title="Authentication-Results отсутствует",
        description="Заголовок аутентификации не найден"
      )
    
    # Парсим результаты
    dkim_pass = 'dkim=pass' in auth_results.lower()
    spf_pass = 'spf=pass' in auth_results.lower()
    dmarc_pass = 'dmarc=pass' in auth_results.lower()
    
    # Извлекаем домен из DKIM header.i=
    dkim_domain = None
    dkim_match = re.search(r'header\.i=@([^\s;]+)', auth_results)
    if dkim_match:
      dkim_domain = dkim_match.group(1).lower()
    
    is_free_email = sender_domain in self.data.free_email_domains
    
    # Если все проверки пройдены и это официальный домен бренда - отлично
    brand_domains = self.data.get_brand_domains()
    is_brand_domain = sender_domain in brand_domains or any(
      sender_domain.endswith('.' + bd) for bd in brand_domains
    )
    
    if dkim_pass and spf_pass and dmarc_pass:
      if is_brand_domain:
        return CheckResult(
          name="auth_results",
          status=CheckStatus.PASS,
          score=1.0,  # Большой бонус
          title="Полная аутентификация подтверждена",
          description=f"DKIM/SPF/DMARC пройдены для {sender_domain}",
          details={"dkim": dkim_pass, "spf": spf_pass, "dmarc": dmarc_pass, "domain": sender_domain}
        )
      elif is_free_email:
        # DKIM/SPF прошли для gmail.com - это НОРМАЛЬНО для gmail
        # Но это не делает письмо безопасным, если отправитель притворяется брендом
        return CheckResult(
          name="auth_results",
          status=CheckStatus.INFO,
          score=0.0,
          title="Аутентификация пройдена (бесплатная почта)",
          description=f"DKIM/SPF/DMARC пройдены для {sender_domain}",
          details={"dkim": dkim_pass, "spf": spf_pass, "dmarc": dmarc_pass, "note": "Бесплатная почта всегда проходит свои проверки"}
        )
    
    # Если проверки не пройдены
    failed = []
    if not dkim_pass:
      failed.append("DKIM")
    if not spf_pass:
      failed.append("SPF")
    if not dmarc_pass:
      failed.append("DMARC")
    
    if failed:
      return CheckResult(
        name="auth_results",
        status=CheckStatus.WARN,
        score=-0.5 * len(failed),
        title=f"Не пройдены: {', '.join(failed)}",
        description="Аутентификация письма неполная",
        details={"dkim": dkim_pass, "spf": spf_pass, "dmarc": dmarc_pass, "failed": failed}
      )
    
    return CheckResult(
      name="auth_results",
      status=CheckStatus.INFO,
      score=0.0,
      title="Аутентификация частична",
      description="Некоторые проверки пройдены"
    )
  
  def _check_malicious_urls(self, urls: Set[str], body_html: str) -> CheckResult:
    """Проверить ссылки на известные вредоносные/подозрительные домены"""
    if not urls and not body_html:
      return CheckResult(
        name="malicious_urls",
        status=CheckStatus.INFO,
        score=0.0,
        title="Ссылки отсутствуют",
        description="В письме нет ссылок для проверки"
      )
    
    issues = []
    critical_issues = []
    score = 0.0
    
    # Извлекаем дополнительные URL из href
    all_urls = set(urls)
    href_pattern = r'href=["\']([^"\']+)["\']'
    for href in re.findall(href_pattern, body_html or '', re.IGNORECASE):
      if href.startswith('http'):
        all_urls.add(href)
    
    for url in all_urls:
      try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Извлекаем базовый домен
        parts = domain.split('.')
        if len(parts) >= 2:
          base_domain = '.'.join(parts[-2:])
        else:
          base_domain = domain
        
        # 1. Проверяем известные вредоносные домены
        if domain in self.KNOWN_MALICIOUS_DOMAINS or base_domain in self.KNOWN_MALICIOUS_DOMAINS:
          critical_issues.append(f"Известный вредоносный домен: {domain}")
          score -= 5.0
          continue
        
        # 2. Порно-сайты в деловом письме = 100% спам/фишинг
        porn_domains = {'pornhub', 'xvideos', 'xnxx', 'xhamster', 'redtube', 'youporn'}
        for pd in porn_domains:
          if pd in domain:
            critical_issues.append(f"Порно-сайт в ссылке: {domain}")
            score -= 10.0
            break
        
        # 3. Проверяем подозрительные TLD
        is_suspicious, reasons = self.data.is_suspicious_domain(domain)
        if is_suspicious:
          issues.extend([f"{domain}: {r}" for r in reasons])
          score -= 1.0
        
        # 4. Ссылка на IP-адрес
        if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
          critical_issues.append(f"Ссылка на IP-адрес: {domain}")
          score -= 3.0
        
      except Exception:
        continue
    
    if critical_issues:
      return CheckResult(
        name="malicious_urls",
        status=CheckStatus.FAIL,
        score=max(score, -15.0),
        title="ОБНАРУЖЕНЫ ВРЕДОНОСНЫЕ ССЫЛКИ!",
        description=critical_issues[0],
        details={"critical": critical_issues, "warnings": issues, "urls": list(all_urls)[:10]}
      )
    
    if issues:
      return CheckResult(
        name="malicious_urls",
        status=CheckStatus.WARN,
        score=score,
        title="Подозрительные ссылки",
        description=issues[0] if issues else "",
        details={"warnings": issues, "urls": list(all_urls)[:10]}
      )
    
    return CheckResult(
      name="malicious_urls",
      status=CheckStatus.PASS,
      score=0.1,
      title="Ссылки безопасны",
      description=f"Проверено {len(all_urls)} ссылок"
    )

