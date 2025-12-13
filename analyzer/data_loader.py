# -*- coding: utf-8 -*-
"""
Загрузчик данных для анализа
"""

import json
import os
from typing import Dict, List, Set, Any


class AnalysisData:
  """Данные для анализа писем"""
  
  def __init__(self, data_dir: str):
    self.data_dir = data_dir
    
    # Триггерные слова
    self.trigger_words: Dict[str, Dict[str, List[str]]] = {}
    
    # Опасные расширения
    self.critical_extensions: Set[str] = set()
    self.high_risk_extensions: Set[str] = set()
    self.macro_extensions: Set[str] = set()
    self.double_extension_patterns: List[str] = []
    
    # Подозрительные TLD
    self.high_risk_tlds: Set[str] = set()
    self.suspicious_substrings: List[str] = []
    self.free_email_domains: Set[str] = set()
    self.phishing_domain_patterns: List[str] = []
    
    # Известные бренды
    self.brands: Dict[str, Dict[str, Any]] = {}
    
    # Загружаем данные
    self._load_all()
  
  def _load_json(self, filename: str) -> Dict:
    """Загрузить JSON файл"""
    filepath = os.path.join(self.data_dir, filename)
    try:
      with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)
    except Exception as e:
      print(f"Ошибка загрузки {filename}: {e}")
      return {}
  
  def _load_all(self):
    """Загрузить все данные"""
    # Триггерные слова
    self.trigger_words = self._load_json("trigger_words.json")
    
    # Опасные расширения
    ext_data = self._load_json("dangerous_extensions.json")
    self.critical_extensions = set(ext_data.get("critical_extensions", []))
    self.high_risk_extensions = set(ext_data.get("high_risk_extensions", []))
    self.macro_extensions = set(ext_data.get("macro_extensions", []))
    self.double_extension_patterns = ext_data.get("double_extension_patterns", [])
    
    # Подозрительные TLD
    tld_data = self._load_json("suspicious_tlds.json")
    self.high_risk_tlds = set(tld_data.get("high_risk_tlds", []))
    self.suspicious_substrings = tld_data.get("suspicious_substrings", [])
    self.free_email_domains = set(tld_data.get("free_email_domains", []))
    self.phishing_domain_patterns = tld_data.get("phishing_domain_patterns", [])
    
    # Известные бренды
    brands_data = self._load_json("known_brands.json")
    self.brands = brands_data.get("brands", {})
  
  def get_all_trigger_words(self) -> Set[str]:
    """Получить все триггерные слова"""
    words = set()
    for category, lang_words in self.trigger_words.items():
      for lang, word_list in lang_words.items():
        words.update(w.lower() for w in word_list)
    return words
  
  def get_trigger_words_by_category(self, category: str) -> Set[str]:
    """Получить триггерные слова по категории"""
    words = set()
    if category in self.trigger_words:
      for lang, word_list in self.trigger_words[category].items():
        words.update(w.lower() for w in word_list)
    return words
  
  def get_brand_domains(self) -> Dict[str, str]:
    """Получить домены брендов: домен -> имя бренда"""
    domains = {}
    for brand_id, brand_data in self.brands.items():
      brand_name = brand_data.get("name", brand_id)
      for domain in brand_data.get("domains", []):
        domains[domain.lower()] = brand_name
    return domains
  
  def get_brand_keywords(self) -> Dict[str, str]:
    """Получить ключевые слова брендов: слово -> имя бренда"""
    keywords = {}
    for brand_id, brand_data in self.brands.items():
      brand_name = brand_data.get("name", brand_id)
      for keyword in brand_data.get("keywords", []):
        keywords[keyword.lower()] = brand_name
    return keywords
  
  def is_dangerous_extension(self, filename: str) -> tuple:
    """
    Проверить расширение файла
    Возвращает: (is_dangerous, level, reason)
    """
    filename_lower = filename.lower()
    
    # Проверка двойного расширения
    for pattern in self.double_extension_patterns:
      if filename_lower.endswith(pattern):
        return (True, "critical", f"Двойное расширение: {pattern}")
    
    # Получаем расширение
    ext = os.path.splitext(filename_lower)[1]
    
    if ext in self.critical_extensions:
      return (True, "critical", f"Критически опасное расширение: {ext}")
    
    if ext in self.macro_extensions:
      return (True, "high", f"Файл с макросами: {ext}")
    
    if ext in self.high_risk_extensions:
      return (True, "medium", f"Потенциально опасное расширение: {ext}")
    
    return (False, "safe", "")
  
  def is_suspicious_domain(self, domain: str) -> tuple:
    """
    Проверить домен на подозрительность
    Возвращает: (is_suspicious, reasons)
    """
    domain_lower = domain.lower()
    
    # СНАЧАЛА проверяем - не является ли это официальным доменом бренда
    # Если да - сразу возвращаем "безопасно"
    for brand_id, brand_data in self.brands.items():
      for official_domain in brand_data.get("domains", []):
        official_lower = official_domain.lower()
        # Точное совпадение или поддомен
        if domain_lower == official_lower or domain_lower.endswith('.' + official_lower):
          return (False, [])  # Официальный домен = безопасно
    
    reasons = []
    
    # Проверка TLD
    for tld in self.high_risk_tlds:
      if domain_lower.endswith(tld):
        reasons.append(f"Подозрительный TLD: {tld}")
        break
    
    # Проверка подозрительных подстрок (только если не бренд)
    for substring in self.suspicious_substrings:
      if substring in domain_lower:
        reasons.append(f"Подозрительная подстрока в домене: {substring}")
        break
    
    return (len(reasons) > 0, reasons)

