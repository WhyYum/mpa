# -*- coding: utf-8 -*-
"""
Анализатор тела письма
Проверяет: слова-триггеры, ссылки, HTML-элементы и т.д.
"""

import re
import json
import os
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse, unquote
from html.parser import HTMLParser


DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")


@dataclass
class LinkInfo:
    """Информация о ссылке"""
    url: str
    display_text: str
    domain: str
    is_hidden: bool = False
    is_suspicious: bool = False
    issues: List[str] = field(default_factory=list)


@dataclass
class BodyAnalysisResult:
    """Результат анализа тела письма"""
    score: int = 0
    issues: List[Dict] = field(default_factory=list)
    
    # Найденные элементы
    trigger_words_found: List[Dict] = field(default_factory=list)
    links: List[LinkInfo] = field(default_factory=list)
    suspicious_links: List[LinkInfo] = field(default_factory=list)
    
    # Статистика
    total_links: int = 0
    hidden_links: int = 0
    external_links: int = 0


class HTMLLinkExtractor(HTMLParser):
    """Парсер HTML для извлечения ссылок"""
    
    def __init__(self):
        super().__init__()
        self.links = []
        self.current_link = None
        self.current_text = ""
    
    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            href = dict(attrs).get('href', '')
            style = dict(attrs).get('style', '')
            
            # Проверяем на скрытую ссылку
            is_hidden = False
            if style:
                style_lower = style.lower()
                if 'display:none' in style_lower or 'visibility:hidden' in style_lower:
                    is_hidden = True
                if 'font-size:0' in style_lower or 'font-size: 0' in style_lower:
                    is_hidden = True
            
            self.current_link = {'href': href, 'is_hidden': is_hidden}
            self.current_text = ""
    
    def handle_endtag(self, tag):
        if tag == 'a' and self.current_link:
            self.current_link['text'] = self.current_text.strip()
            self.links.append(self.current_link)
            self.current_link = None
            self.current_text = ""
    
    def handle_data(self, data):
        if self.current_link is not None:
            self.current_text += data


class BodyAnalyzer:
    """Анализатор тела письма"""
    
    def __init__(self):
        self.trigger_words = self._load_trigger_words()
        self.suspicious_data = self._load_suspicious_data()
        self.brands = self._load_brands()
        
        # Паттерны
        self.url_pattern = re.compile(
            r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',
            re.IGNORECASE
        )
        self.ip_url_pattern = re.compile(
            r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            re.IGNORECASE
        )
        self.short_url_domains = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 
            'is.gd', 'buff.ly', 'adf.ly', 'tiny.cc', 'lnkd.in',
            'db.tt', 'qr.ae', 'cutt.ly', 'rb.gy', 'shorturl.at'
        ]
    
    def _load_trigger_words(self) -> Dict:
        """Загрузить слова-триггеры"""
        try:
            path = os.path.join(DATA_DIR, "trigger_words.json")
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            return {}
    
    def _load_suspicious_data(self) -> Dict:
        """Загрузить подозрительные данные"""
        try:
            path = os.path.join(DATA_DIR, "suspicious_tlds.json")
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            return {}
    
    def _load_brands(self) -> Dict:
        """Загрузить данные о брендах"""
        try:
            path = os.path.join(DATA_DIR, "known_brands.json")
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f).get("brands", {})
        except:
            return {}
    
    def analyze(self, body_text: str, body_html: str, subject: str = "") -> BodyAnalysisResult:
        """Провести полный анализ тела письма"""
        result = BodyAnalysisResult()
        
        # Объединяем текст для анализа
        full_text = f"{subject}\n{body_text}".lower()
        
        # 1. Поиск слов-триггеров
        self._find_trigger_words(result, full_text)
        
        # 2. Анализ ссылок из текста
        self._analyze_text_links(result, body_text)
        
        # 3. Анализ HTML (если есть)
        if body_html:
            self._analyze_html_links(result, body_html)
        
        # 4. Проверка на признаки фишинга в тексте
        self._check_phishing_patterns(result, full_text)
        
        # 5. Подсчёт подозрительных ссылок
        result.suspicious_links = [l for l in result.links if l.is_suspicious]
        result.total_links = len(result.links)
        result.hidden_links = len([l for l in result.links if l.is_hidden])
        
        return result
    
    def _find_trigger_words(self, result: BodyAnalysisResult, text: str):
        """Поиск слов-триггеров"""
        categories = {
            "urgent_words": {"name": "Срочность/Давление", "base_score": 10},
            "threat_words": {"name": "Угрозы/Предупреждения", "base_score": 15},
            "action_words": {"name": "Призыв к действию", "base_score": 10},
            "money_words": {"name": "Деньги/Выигрыш", "base_score": 20},
            "credential_words": {"name": "Запрос данных", "base_score": 15}
        }
        
        found_categories = set()
        
        for category, info in categories.items():
            words_data = self.trigger_words.get(category, {})
            
            for lang, words in words_data.items():
                for word in words:
                    if word.lower() in text:
                        # Находим контекст
                        idx = text.find(word.lower())
                        start = max(0, idx - 30)
                        end = min(len(text), idx + len(word) + 30)
                        context = text[start:end]
                        
                        result.trigger_words_found.append({
                            "word": word,
                            "category": info["name"],
                            "context": f"...{context}..."
                        })
                        
                        if category not in found_categories:
                            found_categories.add(category)
                            result.score += info["base_score"]
        
        # Добавляем общую проблему если нашли триггеры
        if result.trigger_words_found:
            unique_categories = list(set(w["category"] for w in result.trigger_words_found))
            result.issues.append({
                "type": "trigger_words",
                "severity": "medium" if len(unique_categories) < 3 else "high",
                "message": f"Найдены подозрительные слова ({len(result.trigger_words_found)} шт.)",
                "details": f"Категории: {', '.join(unique_categories)}. Фишинговые письма часто используют слова, создающие срочность или страх."
            })
    
    def _analyze_text_links(self, result: BodyAnalysisResult, text: str):
        """Анализ ссылок из текста"""
        urls = self.url_pattern.findall(text)
        
        for url in urls:
            link_info = self._analyze_single_link(url, url)
            result.links.append(link_info)
            
            if link_info.is_suspicious:
                for issue in link_info.issues:
                    result.score += 15
                    result.issues.append({
                        "type": "suspicious_link",
                        "severity": "high",
                        "message": f"Подозрительная ссылка: {link_info.domain}",
                        "details": issue
                    })
    
    def _analyze_html_links(self, result: BodyAnalysisResult, html: str):
        """Анализ ссылок из HTML"""
        try:
            parser = HTMLLinkExtractor()
            parser.feed(html)
            
            for link_data in parser.links:
                href = link_data.get('href', '')
                text = link_data.get('text', '')
                is_hidden = link_data.get('is_hidden', False)
                
                if not href or href.startswith('mailto:'):
                    continue
                
                link_info = self._analyze_single_link(href, text, is_hidden)
                
                # Проверяем несоответствие текста ссылки и URL
                if text and href:
                    text_urls = self.url_pattern.findall(text)
                    if text_urls:
                        text_domain = self._extract_domain(text_urls[0])
                        href_domain = self._extract_domain(href)
                        
                        if text_domain and href_domain and text_domain != href_domain:
                            link_info.is_suspicious = True
                            link_info.issues.append(
                                f"Текст ссылки показывает '{text_domain}', но ведёт на '{href_domain}'"
                            )
                            result.score += 30
                            result.issues.append({
                                "type": "link_mismatch",
                                "severity": "critical",
                                "message": "Скрытая подмена ссылки",
                                "details": f"Отображается: {text_domain}, реальный адрес: {href_domain}. Это классический приём фишинга."
                            })
                
                # Скрытые ссылки
                if is_hidden:
                    result.score += 20
                    result.issues.append({
                        "type": "hidden_link",
                        "severity": "high",
                        "message": "Обнаружена скрытая ссылка",
                        "details": f"Ссылка на {link_info.domain} скрыта с помощью CSS стилей."
                    })
                
                result.links.append(link_info)
                
        except Exception as e:
            pass  # HTML парсинг не критичен
    
    def _analyze_single_link(self, url: str, display_text: str, is_hidden: bool = False) -> LinkInfo:
        """Анализ одной ссылки"""
        domain = self._extract_domain(url)
        
        link_info = LinkInfo(
            url=url,
            display_text=display_text,
            domain=domain,
            is_hidden=is_hidden
        )
        
        # Проверка на IP-адрес вместо домена
        if self.ip_url_pattern.match(url):
            link_info.is_suspicious = True
            link_info.issues.append("Ссылка использует IP-адрес вместо домена")
        
        # Проверка на сокращённую ссылку
        if domain in self.short_url_domains:
            link_info.is_suspicious = True
            link_info.issues.append(f"Сокращённая ссылка ({domain}) - невозможно определить реальный адрес")
        
        # Проверка на подозрительный TLD
        high_risk_tlds = self.suspicious_data.get("high_risk_tlds", [])
        for tld in high_risk_tlds:
            if domain.endswith(tld):
                link_info.is_suspicious = True
                link_info.issues.append(f"Подозрительный домен верхнего уровня: {tld}")
                break
        
        # Проверка на подозрительные подстроки в домене
        suspicious_subs = self.suspicious_data.get("suspicious_substrings", [])
        for sub in suspicious_subs:
            if sub in domain:
                link_info.is_suspicious = True
                link_info.issues.append(f"Подозрительный паттерн в домене: '{sub}'")
                break
        
        # Проверка на look-alike домен известного бренда
        self._check_lookalike_link(link_info)
        
        # Проверка на слишком длинный URL (часто используется для маскировки)
        if len(url) > 200:
            link_info.is_suspicious = True
            link_info.issues.append("Подозрительно длинный URL")
        
        # Проверка на множественные редиректы в URL
        if url.count('http') > 1:
            link_info.is_suspicious = True
            link_info.issues.append("URL содержит вложенные ссылки (возможный редирект)")
        
        return link_info
    
    def _check_lookalike_link(self, link_info: LinkInfo):
        """Проверка ссылки на имитацию известного бренда"""
        domain = link_info.domain.lower()
        domain_name = domain.split('.')[0] if domain else ""
        
        for brand_key, brand_data in self.brands.items():
            legit_domains = [d.lower() for d in brand_data["domains"]]
            
            # Пропускаем легитимные домены
            if domain in legit_domains:
                continue
            
            # Проверяем ключевые слова бренда в домене
            for keyword in brand_data["keywords"]:
                if keyword.lower() in domain_name and domain not in legit_domains:
                    link_info.is_suspicious = True
                    link_info.issues.append(
                        f"Домен имитирует '{brand_data['name']}'. Легитимные домены: {', '.join(legit_domains[:2])}"
                    )
                    return
    
    def _check_phishing_patterns(self, result: BodyAnalysisResult, text: str):
        """Проверка на типичные паттерны фишинга"""
        patterns = [
            # Запрос учётных данных
            (r'(введите|укажите|подтвердите).{0,30}(пароль|логин|pin|cvv|код)', 
             "Запрос конфиденциальных данных", 25),
            # Угроза блокировки
            (r'(аккаунт|счёт|карта).{0,30}(заблокирован|приостановлен|ограничен)',
             "Угроза блокировки аккаунта", 20),
            # Срочность
            (r'в течение.{0,20}(часов|минут|24|48)',
             "Создание искусственной срочности", 15),
            # Выигрыш
            (r'(поздравляем|congratulations).{0,50}(выигра|won|winner|prize)',
             "Сообщение о выигрыше", 25),
            # Запрос перевода
            (r'(перевед|transfer|send).{0,30}(деньги|money|средств|bitcoin|crypto)',
             "Запрос денежного перевода", 30),
        ]
        
        for pattern, description, score in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                result.score += score
                result.issues.append({
                    "type": "phishing_pattern",
                    "severity": "high" if score >= 20 else "medium",
                    "message": description,
                    "details": f"Обнаружен типичный паттерн фишингового письма: {description.lower()}"
                })
    
    def _extract_domain(self, url: str) -> str:
        """Извлечь домен из URL"""
        try:
            # Добавляем схему если отсутствует
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except:
            return ""

