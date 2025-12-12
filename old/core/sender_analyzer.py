# -*- coding: utf-8 -*-
"""
Анализатор отправителя письма
Проверяет: имя отправителя, домен, соответствие бренду и т.д.
"""

import re
import json
import os
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from difflib import SequenceMatcher

# Путь к данным
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")


@dataclass
class SenderAnalysisResult:
    """Результат анализа отправителя"""
    score: int = 0  # Баллы риска (чем больше, тем подозрительнее)
    issues: List[Dict] = field(default_factory=list)
    
    # Детальные данные
    display_name: str = ""
    email_address: str = ""
    domain: str = ""
    domain_age: Optional[int] = None  # Возраст домена в днях (если доступно)
    
    # Флаги
    is_brand_spoofing: bool = False
    is_lookalike_domain: bool = False
    has_suspicious_tld: bool = False
    name_email_mismatch: bool = False


class SenderAnalyzer:
    """Анализатор отправителя письма"""
    
    def __init__(self):
        self.brands = self._load_brands()
        self.suspicious_data = self._load_suspicious_data()
        
        # Символы для подмены (homoglyph)
        self.homoglyphs = {
            'a': ['а', '@', '4'],  # латинская a -> кириллица а
            'e': ['е', '3'],
            'o': ['о', '0'],
            'p': ['р'],
            'c': ['с'],
            'x': ['х'],
            'y': ['у'],
            'i': ['і', '1', 'l', '|'],
            'l': ['1', 'I', '|'],
            's': ['$', '5'],
            'b': ['6'],
            'g': ['9'],
            't': ['+', '7'],
        }
    
    def _load_brands(self) -> Dict:
        """Загрузить данные о брендах"""
        try:
            path = os.path.join(DATA_DIR, "known_brands.json")
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f).get("brands", {})
        except:
            return {}
    
    def _load_suspicious_data(self) -> Dict:
        """Загрузить данные о подозрительных TLD"""
        try:
            path = os.path.join(DATA_DIR, "suspicious_tlds.json")
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            return {}
    
    def analyze(self, from_name: str, from_email: str) -> SenderAnalysisResult:
        """Провести полный анализ отправителя"""
        result = SenderAnalysisResult()
        result.display_name = from_name
        result.email_address = from_email
        
        # Извлекаем домен
        if "@" in from_email:
            result.domain = from_email.split("@")[-1].lower()
        
        # 1. Проверка на подозрительное имя
        self._check_suspicious_name(result, from_name)
        
        # 2. Проверка на подмену бренда
        self._check_brand_spoofing(result, from_name, result.domain)
        
        # 3. Проверка домена на look-alike
        self._check_lookalike_domain(result, result.domain)
        
        # 4. Проверка подозрительного TLD
        self._check_suspicious_tld(result, result.domain)
        
        # 5. Проверка несоответствия имени и email
        self._check_name_email_mismatch(result, from_name, from_email)
        
        # 6. Проверка на использование бесплатной почты для "корпоративных" писем
        self._check_free_email_for_corporate(result, from_name, result.domain)
        
        return result
    
    def _check_suspicious_name(self, result: SenderAnalysisResult, name: str):
        """Проверка на подозрительное имя отправителя"""
        name_lower = name.lower()
        
        # Слишком общие имена
        generic_names = [
            "customer service", "support team", "help desk", "customer support",
            "service team", "official notice", "important notice", "security team",
            "account team", "billing department", "verification team",
            "служба поддержки", "техподдержка", "служба безопасности",
            "отдел безопасности", "важное уведомление", "официальное уведомление"
        ]
        
        for generic in generic_names:
            if generic in name_lower:
                result.score += 15
                result.issues.append({
                    "type": "generic_name",
                    "severity": "medium",
                    "message": f"Слишком общее имя отправителя: '{name}'",
                    "details": f"Имя '{generic}' часто используется в фишинговых письмах"
                })
                break
        
        # Проверка на спецсимволы и странное форматирование
        special_chars_count = len(re.findall(r'[!@#$%^&*()+=\[\]{}|\\<>?/~`]', name))
        if special_chars_count > 2:
            result.score += 10
            result.issues.append({
                "type": "special_chars",
                "severity": "low",
                "message": f"Много спецсимволов в имени: '{name}'",
                "details": f"Найдено {special_chars_count} спецсимволов"
            })
        
        # Проверка на подмену символов (l -> 1, o -> 0)
        substitution_patterns = [
            (r'0', 'o'), (r'1', 'l/i'), (r'@', 'a'),
            (r'\$', 's'), (r'3', 'e'), (r'4', 'a')
        ]
        for pattern, replacement in substitution_patterns:
            if re.search(pattern, name_lower):
                # Проверяем контекст - это может быть легитимно
                pass  # Дополнительная логика при необходимости
    
    def _check_brand_spoofing(self, result: SenderAnalysisResult, name: str, domain: str):
        """Проверка на подмену бренда"""
        name_lower = name.lower()
        
        for brand_key, brand_data in self.brands.items():
            brand_name = brand_data["name"].lower()
            brand_domains = [d.lower() for d in brand_data["domains"]]
            brand_keywords = [k.lower() for k in brand_data["keywords"]]
            
            # Проверяем, упоминается ли бренд в имени
            brand_mentioned = False
            for keyword in brand_keywords:
                if keyword in name_lower:
                    brand_mentioned = True
                    break
            
            if brand_mentioned:
                # Проверяем, соответствует ли домен бренду
                domain_matches = domain in brand_domains
                
                if not domain_matches:
                    result.is_brand_spoofing = True
                    result.score += 40  # Высокий риск
                    result.issues.append({
                        "type": "brand_spoofing",
                        "severity": "critical",
                        "message": f"Подмена бренда '{brand_data['name']}'",
                        "details": f"Имя содержит '{brand_data['name']}', но домен '{domain}' не принадлежит этому бренду. Легитимные домены: {', '.join(brand_domains[:3])}"
                    })
                    return  # Достаточно одного обнаружения
    
    def _check_lookalike_domain(self, result: SenderAnalysisResult, domain: str):
        """Проверка на похожий домен (typosquatting)"""
        if not domain:
            return
        
        domain_name = domain.split('.')[0]  # Берем только имя без TLD
        
        for brand_key, brand_data in self.brands.items():
            for legit_domain in brand_data["domains"]:
                legit_name = legit_domain.split('.')[0]
                
                # Пропускаем точное совпадение
                if domain == legit_domain:
                    continue
                
                # Проверяем похожесть
                similarity = SequenceMatcher(None, domain_name, legit_name).ratio()
                
                # Высокая похожесть, но не точное совпадение
                if 0.7 < similarity < 1.0:
                    result.is_lookalike_domain = True
                    result.score += 35
                    result.issues.append({
                        "type": "lookalike_domain",
                        "severity": "high",
                        "message": f"Домен похож на '{legit_domain}'",
                        "details": f"Домен '{domain}' похож на легитимный домен '{legit_domain}' ({brand_data['name']}). Сходство: {similarity:.0%}"
                    })
                    return
        
        # Проверка на подозрительные суффиксы/префиксы
        suspicious_subs = self.suspicious_data.get("suspicious_substrings", [])
        for sub in suspicious_subs:
            if sub in domain:
                result.score += 20
                result.issues.append({
                    "type": "suspicious_domain_pattern",
                    "severity": "medium",
                    "message": f"Подозрительный паттерн в домене: '{sub}'",
                    "details": f"Домен '{domain}' содержит подозрительную подстроку '{sub}', часто используемую в фишинге"
                })
                break
    
    def _check_suspicious_tld(self, result: SenderAnalysisResult, domain: str):
        """Проверка на подозрительный TLD"""
        if not domain:
            return
        
        high_risk_tlds = self.suspicious_data.get("high_risk_tlds", [])
        
        for tld in high_risk_tlds:
            if domain.endswith(tld):
                result.has_suspicious_tld = True
                result.score += 15
                result.issues.append({
                    "type": "suspicious_tld",
                    "severity": "medium",
                    "message": f"Подозрительный домен верхнего уровня: '{tld}'",
                    "details": f"Домен '{domain}' использует TLD '{tld}', который часто используется для фишинга и спама"
                })
                break
    
    def _check_name_email_mismatch(self, result: SenderAnalysisResult, name: str, email_addr: str):
        """Проверка несоответствия имени и email"""
        if not name or not email_addr:
            return
        
        name_lower = name.lower()
        email_lower = email_addr.lower()
        local_part = email_lower.split("@")[0] if "@" in email_lower else ""
        
        # Извлекаем слова из имени
        name_words = re.findall(r'[a-zа-яё]+', name_lower)
        
        # Проверяем, есть ли хоть какое-то соответствие
        if name_words and local_part:
            has_match = False
            for word in name_words:
                if len(word) > 2 and word in local_part:
                    has_match = True
                    break
            
            # Если имя выглядит как "реальное" имя, но не совпадает с email
            if not has_match and len(name_words) >= 2:
                # Это может быть нормально для корпоративных писем
                # Но если используются noreply, support и т.д. - это флаг
                suspicious_locals = ["noreply", "no-reply", "donotreply", "mailer", "bounce", "auto"]
                if any(s in local_part for s in suspicious_locals):
                    result.name_email_mismatch = True
                    result.score += 5  # Низкий риск, но отмечаем
                    result.issues.append({
                        "type": "name_email_mismatch",
                        "severity": "low",
                        "message": "Имя отправителя не соответствует email",
                        "details": f"Отображаемое имя '{name}' не связано с адресом '{email_addr}'"
                    })
    
    def _check_free_email_for_corporate(self, result: SenderAnalysisResult, name: str, domain: str):
        """Проверка использования бесплатной почты для корпоративных писем"""
        if not domain:
            return
        
        free_domains = self.suspicious_data.get("free_email_domains", [])
        
        if domain.lower() not in free_domains:
            return
        
        # Проверяем, выглядит ли письмо как корпоративное
        corporate_keywords = [
            "bank", "банк", "support", "поддержка", "security", "безопасность",
            "official", "официальн", "service", "сервис", "billing", "payment",
            "account", "аккаунт", "verify", "verification", "подтвержд"
        ]
        
        name_lower = name.lower()
        for keyword in corporate_keywords:
            if keyword in name_lower:
                result.score += 25
                result.issues.append({
                    "type": "free_email_corporate",
                    "severity": "high",
                    "message": "Корпоративное письмо с бесплатной почты",
                    "details": f"Отправитель представляется как '{name}', но использует бесплатный почтовый сервис ({domain}). Настоящие организации используют корпоративные домены."
                })
                break
    
    def check_homoglyphs(self, text: str) -> List[Tuple[str, str, int]]:
        """Проверить текст на подмену символов (homoglyphs)"""
        findings = []
        for i, char in enumerate(text):
            for original, substitutes in self.homoglyphs.items():
                if char in substitutes:
                    findings.append((char, original, i))
        return findings

