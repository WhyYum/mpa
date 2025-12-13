# -*- coding: utf-8 -*-
"""
Классы для результатов анализа
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum
import json
import os


class CheckStatus(Enum):
  """Статус проверки"""
  PASS = "pass"       # Проверка пройдена
  WARN = "warning"    # Предупреждение
  FAIL = "fail"       # Провал
  INFO = "info"       # Информация
  ERROR = "error"     # Ошибка проверки


@dataclass
class CheckResult:
  """Результат одной проверки"""
  name: str                          # Название проверки
  status: CheckStatus                # Статус
  score: float = 0.0                 # Баллы (+ хорошо, - плохо)
  title: str = ""                    # Заголовок
  description: str = ""              # Описание
  details: Dict[str, Any] = field(default_factory=dict)  # Детали
  
  def to_dict(self) -> Dict:
    return {
      "name": self.name,
      "status": self.status.value,
      "score": self.score,
      "title": self.title,
      "description": self.description,
      "details": self.details
    }


@dataclass
class AnalysisResult:
  """Полный результат анализа письма"""
  # Идентификация
  message_id: str
  email_account: str
  
  # Информация о письме
  from_name: str = ""
  from_email: str = ""
  to_email: str = ""
  subject: str = ""
  date: Optional[datetime] = None
  
  # Результаты проверок
  checks: List[CheckResult] = field(default_factory=list)
  
  # Итоговая оценка
  total_score: float = 0.0      # Общий балл (макс 10)
  risk_level: str = "safe"      # safe, low, medium, high, critical
  is_spam: bool = False
  is_phishing: bool = False
  
  # Метаданные
  analyzed_at: datetime = field(default_factory=datetime.now)
  analysis_time_ms: int = 0
  
  def add_check(self, check: CheckResult):
    """Добавить результат проверки"""
    self.checks.append(check)
  
  def calculate_score(self):
    """Рассчитать итоговую оценку с улучшенной логикой v2.0"""
    # Начинаем с 10 баллов
    score = 10.0
    
    # Проверки на фишинг (критические) - ОДИН FAIL = фишинг
    phishing_checks = [
      "brand_impersonation",   # Имитация бренда
      "suspicious_links",      # Подозрительные ссылки
      "credential_harvesting", # Сбор учётных данных
      "link_spoofing",         # Подмена ссылок (текст != href)
      "suspicious_subject",    # Фишинговая тема + имитация бренда
      "urls_advanced",         # Улучшенная проверка URL
      "envelope_sender",       # Несоответствие отправителей
      "reply_to",              # Reply-To мошенничество
      "suspicious_domains",    # Подозрительные домены
      # Новые проверки v2.0
      "unicode_spoofing",      # Unicode спуфинг в теме/имени
      "official_from_free",    # Официальный отправитель с бесплатной почты
      "malicious_urls",        # Известные вредоносные ссылки
    ]
    
    # Критические угрозы - сразу помечаем как спам/фишинг
    critical_checks = ["attachments", "html_content"]
    
    # Проверки на спам
    spam_checks = ["low_context", "received_chain"]
    
    # Счётчики для комбинированной логики
    fail_count = 0
    warn_count = 0
    severe_penalty = 0.0
    
    for check in self.checks:
      # Подсчёт статусов
      if check.status == CheckStatus.FAIL:
        fail_count += 1
      elif check.status == CheckStatus.WARN:
        warn_count += 1
      
      # Фишинг - проверяем FAIL или жёсткий штраф
      if check.name in phishing_checks:
        if check.status == CheckStatus.FAIL:
          self.is_phishing = True
          severe_penalty += abs(check.score)
        elif check.score <= -2.0:
          self.is_phishing = True
          severe_penalty += abs(check.score)
      
      # НОВОЕ v2.0: Критические проверки - один FAIL = фишинг
      if check.name in ["unicode_spoofing", "official_from_free", "malicious_urls"]:
        if check.status == CheckStatus.FAIL:
          self.is_phishing = True
          self.is_spam = True
      
      # Критические угрозы (опасные вложения, формы с паролями)
      if check.name in critical_checks and check.status == CheckStatus.FAIL:
        if check.score <= -2.0:
          self.is_spam = True
          severe_penalty += abs(check.score)
      
      # Спам (низкий контекст, подозрительная цепочка Received)
      if check.name in spam_checks and check.status == CheckStatus.FAIL:
        self.is_spam = True
    
    # Комбинированная детекция: много предупреждений = спам
    if fail_count >= 3 or (fail_count >= 2 and warn_count >= 3):
      self.is_spam = True
    
    # Если много WARN без FAIL - тоже подозрительно
    if warn_count >= 5 and fail_count == 0:
      self.is_spam = True
    
    # Считаем баллы
    for check in self.checks:
      score += check.score
    
    # Если фишинг или спам - максимум 1 балл (критический уровень)
    if self.is_phishing or self.is_spam:
      score = min(score, 1.0)
    
    # Ограничиваем 0-10
    self.total_score = max(0.0, min(10.0, score))
    
    # Определяем уровень риска
    if self.is_phishing or self.is_spam:
      self.risk_level = "critical"
    elif self.total_score >= 8:
      self.risk_level = "safe"
    elif self.total_score >= 6:
      self.risk_level = "low"
    elif self.total_score >= 4:
      self.risk_level = "medium"
    elif self.total_score >= 2:
      self.risk_level = "high"
    else:
      self.risk_level = "critical"
  
  def to_dict(self) -> Dict:
    """Преобразовать в словарь для сохранения"""
    return {
      "message_id": self.message_id,
      "email_account": self.email_account,
      "from_name": self.from_name,
      "from_email": self.from_email,
      "to_email": self.to_email,
      "subject": self.subject,
      "date": self.date.isoformat() if self.date else None,
      "checks": [c.to_dict() for c in self.checks],
      "total_score": self.total_score,
      "risk_level": self.risk_level,
      "is_spam": self.is_spam,
      "is_phishing": self.is_phishing,
      "analyzed_at": self.analyzed_at.isoformat(),
      "analysis_time_ms": self.analysis_time_ms
    }
  
  @classmethod
  def from_dict(cls, data: Dict) -> 'AnalysisResult':
    """Создать из словаря"""
    result = cls(
      message_id=data.get("message_id", ""),
      email_account=data.get("email_account", ""),
      from_name=data.get("from_name", ""),
      from_email=data.get("from_email", ""),
      to_email=data.get("to_email", ""),
      subject=data.get("subject", ""),
      total_score=data.get("total_score", 0),
      risk_level=data.get("risk_level", "safe"),
      is_spam=data.get("is_spam", False),
      is_phishing=data.get("is_phishing", False),
      analysis_time_ms=data.get("analysis_time_ms", 0)
    )
    
    # Парсим дату
    if data.get("date"):
      try:
        result.date = datetime.fromisoformat(data["date"])
      except:
        pass
    
    if data.get("analyzed_at"):
      try:
        result.analyzed_at = datetime.fromisoformat(data["analyzed_at"])
      except:
        pass
    
    # Парсим проверки
    for check_data in data.get("checks", []):
      result.checks.append(CheckResult(
        name=check_data.get("name", ""),
        status=CheckStatus(check_data.get("status", "info")),
        score=check_data.get("score", 0),
        title=check_data.get("title", ""),
        description=check_data.get("description", ""),
        details=check_data.get("details", {})
      ))
    
    return result


class AnalysisLogger:
  """Логгер результатов анализа"""
  
  def __init__(self, logs_dir: str):
    self.logs_dir = logs_dir
    os.makedirs(logs_dir, exist_ok=True)
  
  def save(self, result: AnalysisResult) -> str:
    """Сохранить результат анализа"""
    # Создаём папку для аккаунта
    account_dir = os.path.join(self.logs_dir, self._safe_filename(result.email_account))
    os.makedirs(account_dir, exist_ok=True)
    
    # Имя файла: дата_message_id.json
    date_str = result.analyzed_at.strftime("%Y%m%d_%H%M%S")
    msg_id = self._safe_filename(result.message_id)[:50]
    filename = f"{date_str}_{msg_id}.json"
    filepath = os.path.join(account_dir, filename)
    
    with open(filepath, "w", encoding="utf-8") as f:
      json.dump(result.to_dict(), f, ensure_ascii=False, indent=2)
    
    return filepath
  
  def load_all(self, email_account: str = None, limit: int = 1000) -> List[AnalysisResult]:
    """Загрузить результаты анализа (с дедупликацией по message_id)"""
    results = []
    seen_message_ids = set()  # Для дедупликации
    
    if email_account:
      account_dirs = [os.path.join(self.logs_dir, self._safe_filename(email_account))]
    else:
      account_dirs = [
        os.path.join(self.logs_dir, d) 
        for d in os.listdir(self.logs_dir) 
        if os.path.isdir(os.path.join(self.logs_dir, d))
      ]
    
    files = []
    for account_dir in account_dirs:
      if not os.path.exists(account_dir):
        continue
      for filename in os.listdir(account_dir):
        if filename.endswith(".json"):
          filepath = os.path.join(account_dir, filename)
          files.append((os.path.getmtime(filepath), filepath))
    
    # Сортируем по дате (новые первые)
    files.sort(reverse=True)
    
    for _, filepath in files:
      if len(results) >= limit:
        break
      try:
        with open(filepath, "r", encoding="utf-8") as f:
          data = json.load(f)
          result = AnalysisResult.from_dict(data)
          
          # Дедупликация по message_id
          if result.message_id and result.message_id in seen_message_ids:
            continue  # Пропускаем дубликат
          
          seen_message_ids.add(result.message_id)
          results.append(result)
      except Exception as e:
        print(f"Ошибка загрузки лога {filepath}: {e}")
    
    return results
  
  def _safe_filename(self, name: str) -> str:
    """Безопасное имя файла"""
    return "".join(c if c.isalnum() or c in "._-@" else "_" for c in name)

