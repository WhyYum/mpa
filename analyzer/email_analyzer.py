# -*- coding: utf-8 -*-
"""
Главный модуль анализа писем
"""

import time
import os
import re
from typing import Dict, List, Any, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from .analysis_result import AnalysisResult, CheckResult, CheckStatus, AnalysisLogger
from .data_loader import AnalysisData
from .dns_checker import DNSChecker
from .content_analyzer import ContentAnalyzer


class EmailAnalyzer:
  """Главный анализатор писем"""
  
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
    Проанализировать письмо
    
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
    
    # === DNS ПРОВЕРКИ ===
    if sender_domain:
      # SPF
      result.add_check(self.dns_checker.check_spf(sender_domain))
      
      # DKIM (пробуем найти селектор в заголовках)
      dkim_selector = None
      dkim_header = headers.get("DKIM-Signature", "")
      if dkim_header and "s=" in dkim_header:
        import re
        match = re.search(r's=([^;\s]+)', dkim_header)
        if match:
          dkim_selector = match.group(1)
      result.add_check(self.dns_checker.check_dkim(sender_domain, dkim_selector))
      
      # DMARC
      result.add_check(self.dns_checker.check_dmarc(sender_domain))
      
      # MX записи
      result.add_check(self.dns_checker.check_mx(sender_domain))
    
    # === КОНТЕНТ ПРОВЕРКИ ===
    
    # Триггерные слова
    result.add_check(
      self.content_analyzer.check_trigger_words(body_text, subject)
    )
    
    # Ссылки
    result.add_check(
      self.content_analyzer.check_links(body_text, body_html)
    )
    
    # Вложения
    result.add_check(
      self.content_analyzer.check_attachments(attachments)
    )
    
    # HTML контент
    result.add_check(
      self.content_analyzer.check_html_content(body_html)
    )
    
    # Подмена бренда
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
    
    # Рассчитываем итоговую оценку
    result.calculate_score()
    
    # Время анализа
    result.analysis_time_ms = int((time.time() - start_time) * 1000)
    
    # Сохраняем лог
    self.logger.save(result)
    
    return result
  
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
  
  def get_logs(self, account_email: str = None, limit: int = 100) -> List[AnalysisResult]:
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

