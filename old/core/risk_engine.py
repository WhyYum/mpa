# -*- coding: utf-8 -*-
"""
Движок оценки риска
Объединяет результаты всех анализаторов и вычисляет итоговый риск
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

from .sender_analyzer import SenderAnalyzer, SenderAnalysisResult
from .header_analyzer import HeaderAnalyzer, HeaderAnalysisResult
from .body_analyzer import BodyAnalyzer, BodyAnalysisResult
from .attachment_analyzer import AttachmentAnalyzer, AttachmentAnalysisResult


class RiskLevel(Enum):
    """Уровни риска"""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AnalysisDetail:
    """Детальная информация об одной проверке"""
    category: str  # sender, headers, body, attachments
    check_name: str
    severity: str  # low, medium, high, critical
    score: int
    message: str
    details: str
    block_content: str = ""  # Содержимое блока, на который сработала проверка


@dataclass 
class EmailAnalysisResult:
    """Полный результат анализа письма"""
    # Основные данные письма
    uid: str = ""
    message_id: str = ""
    subject: str = ""
    from_name: str = ""
    from_email: str = ""
    date: Optional[Any] = None
    
    # Оценка риска
    total_score: int = 0
    risk_level: RiskLevel = RiskLevel.SAFE
    classification: str = "Безопасное"  # Безопасное, Подозрительное, Спам, Фишинг
    
    # Детальные результаты анализов
    sender_result: Optional[SenderAnalysisResult] = None
    header_result: Optional[HeaderAnalysisResult] = None
    body_result: Optional[BodyAnalysisResult] = None
    attachment_result: Optional[AttachmentAnalysisResult] = None
    
    # Все проблемы объединённые
    all_issues: List[AnalysisDetail] = field(default_factory=list)
    
    # Флаги для автоматических действий
    should_move_to_spam: bool = False
    is_phishing: bool = False
    is_spam: bool = False
    
    # Информация о домене (для tooltip)
    domain_info: Dict = field(default_factory=dict)


class RiskEngine:
    """Движок оценки риска"""
    
    def __init__(self, thresholds: Dict = None):
        self.sender_analyzer = SenderAnalyzer()
        self.header_analyzer = HeaderAnalyzer()
        self.body_analyzer = BodyAnalyzer()
        self.attachment_analyzer = AttachmentAnalyzer()
        
        # Пороговые значения
        self.thresholds = thresholds or {
            "safe": 20,        # 0-20: безопасное
            "suspicious": 50,  # 20-50: подозрительное
            "spam": 80,        # 50-80: спам
            "phishing": 100    # 80+: фишинг
        }
        
        # Критические признаки, которые сразу помечают как спам/фишинг
        self.critical_triggers = [
            "brand_spoofing",
            "link_mismatch", 
            "return_path_mismatch",
            "spf_fail",
            "dangerous_attachment"
        ]
    
    def analyze_email(self, parsed_email) -> EmailAnalysisResult:
        """Провести полный анализ письма"""
        result = EmailAnalysisResult(
            uid=parsed_email.uid,
            message_id=parsed_email.message_id,
            subject=parsed_email.subject,
            from_name=parsed_email.from_name,
            from_email=parsed_email.from_email,
            date=parsed_email.date
        )
        
        # 1. Анализ отправителя
        result.sender_result = self.sender_analyzer.analyze(
            parsed_email.from_name,
            parsed_email.from_email
        )
        self._collect_issues(result, result.sender_result, "sender")
        
        # 2. Анализ заголовков
        result.header_result = self.header_analyzer.analyze(
            parsed_email.headers,
            parsed_email.from_email
        )
        self._collect_issues(result, result.header_result, "headers")
        
        # 3. Анализ тела письма
        result.body_result = self.body_analyzer.analyze(
            parsed_email.body_text,
            parsed_email.body_html,
            parsed_email.subject
        )
        self._collect_issues(result, result.body_result, "body")
        
        # 4. Анализ вложений
        if parsed_email.attachments:
            result.attachment_result = self.attachment_analyzer.analyze(
                parsed_email.attachments
            )
            self._collect_issues(result, result.attachment_result, "attachments")
        
        # 5. Вычисляем итоговый балл
        self._calculate_total_score(result)
        
        # 6. Определяем уровень риска и классификацию
        self._classify_email(result)
        
        # 7. Получаем информацию о домене
        if result.sender_result and result.sender_result.domain:
            result.domain_info = self.header_analyzer.get_domain_info(
                result.sender_result.domain
            )
        
        return result
    
    def _collect_issues(self, result: EmailAnalysisResult, analysis_result, category: str):
        """Собрать проблемы из результата анализа"""
        if not analysis_result:
            return
        
        for issue in analysis_result.issues:
            detail = AnalysisDetail(
                category=category,
                check_name=issue.get("type", "unknown"),
                severity=issue.get("severity", "low"),
                score=self._severity_to_score(issue.get("severity", "low")),
                message=issue.get("message", ""),
                details=issue.get("details", ""),
                block_content=issue.get("block_content", "")
            )
            result.all_issues.append(detail)
    
    def _severity_to_score(self, severity: str) -> int:
        """Преобразовать severity в баллы"""
        scores = {
            "low": 5,
            "medium": 15,
            "high": 25,
            "critical": 40
        }
        return scores.get(severity, 5)
    
    def _calculate_total_score(self, result: EmailAnalysisResult):
        """Вычислить итоговый балл риска"""
        total = 0
        
        if result.sender_result:
            total += result.sender_result.score
        if result.header_result:
            total += result.header_result.score
        if result.body_result:
            total += result.body_result.score
        if result.attachment_result:
            total += result.attachment_result.score
        
        result.total_score = min(total, 200)  # Ограничиваем максимум
    
    def _classify_email(self, result: EmailAnalysisResult):
        """Классифицировать письмо по уровню риска"""
        score = result.total_score
        
        # Проверяем критические триггеры
        has_critical = False
        for issue in result.all_issues:
            if issue.check_name in self.critical_triggers:
                has_critical = True
                break
        
        # Классификация по баллам
        if score <= self.thresholds["safe"]:
            result.risk_level = RiskLevel.SAFE
            result.classification = "Безопасное"
        elif score <= self.thresholds["suspicious"]:
            result.risk_level = RiskLevel.MEDIUM
            result.classification = "Подозрительное"
        elif score <= self.thresholds["spam"]:
            result.risk_level = RiskLevel.HIGH
            result.classification = "Спам"
            result.is_spam = True
            result.should_move_to_spam = True
        else:
            result.risk_level = RiskLevel.CRITICAL
            result.classification = "Фишинг"
            result.is_phishing = True
            result.should_move_to_spam = True
        
        # Если есть критические триггеры - сразу фишинг
        if has_critical and score > self.thresholds["safe"]:
            result.risk_level = RiskLevel.CRITICAL
            result.classification = "Фишинг"
            result.is_phishing = True
            result.should_move_to_spam = True
        
        # Особые случаи
        if result.sender_result and result.sender_result.is_brand_spoofing:
            result.is_phishing = True
            result.should_move_to_spam = True
            result.classification = "Фишинг"
        
        if result.attachment_result and result.attachment_result.dangerous_attachments > 0:
            result.is_phishing = True
            result.should_move_to_spam = True
            result.classification = "Фишинг (опасное вложение)"
    
    def get_risk_color(self, risk_level: RiskLevel) -> str:
        """Получить цвет для уровня риска"""
        colors = {
            RiskLevel.SAFE: "#4CAF50",      # Зелёный
            RiskLevel.LOW: "#8BC34A",       # Светло-зелёный
            RiskLevel.MEDIUM: "#FFC107",    # Жёлтый
            RiskLevel.HIGH: "#FF9800",      # Оранжевый
            RiskLevel.CRITICAL: "#F44336"   # Красный
        }
        return colors.get(risk_level, "#9E9E9E")
    
    def get_classification_emoji(self, classification: str) -> str:
        """Получить эмодзи для классификации"""
        emojis = {
            "Безопасное": "✅",
            "Подозрительное": "⚠️",
            "Спам": "🚫",
            "Фишинг": "🎣",
            "Фишинг (опасное вложение)": "☠️"
        }
        return emojis.get(classification, "❓")
    
    def format_analysis_report(self, result: EmailAnalysisResult) -> str:
        """Форматировать отчёт анализа в текст"""
        lines = [
            f"{'='*60}",
            f"📧 АНАЛИЗ ПИСЬМА",
            f"{'='*60}",
            f"",
            f"От: {result.from_name} <{result.from_email}>",
            f"Тема: {result.subject}",
            f"Дата: {result.date}",
            f"",
            f"{'─'*60}",
            f"📊 РЕЗУЛЬТАТ: {self.get_classification_emoji(result.classification)} {result.classification}",
            f"Балл риска: {result.total_score}/200",
            f"{'─'*60}",
        ]
        
        if result.all_issues:
            lines.append("")
            lines.append("🔍 ОБНАРУЖЕННЫЕ ПРОБЛЕМЫ:")
            lines.append("")
            
            # Группируем по категориям
            categories = {
                "sender": "👤 Отправитель",
                "headers": "📋 Заголовки",
                "body": "📝 Содержимое",
                "attachments": "📎 Вложения"
            }
            
            for cat_key, cat_name in categories.items():
                cat_issues = [i for i in result.all_issues if i.category == cat_key]
                if cat_issues:
                    lines.append(f"\n{cat_name}:")
                    for issue in cat_issues:
                        severity_icon = {"low": "ℹ️", "medium": "⚠️", "high": "🔶", "critical": "🔴"}.get(issue.severity, "•")
                        lines.append(f"  {severity_icon} {issue.message}")
                        if issue.details:
                            lines.append(f"     └─ {issue.details}")
        else:
            lines.append("")
            lines.append("✅ Проблем не обнаружено")
        
        lines.append("")
        lines.append(f"{'='*60}")
        
        return "\n".join(lines)

