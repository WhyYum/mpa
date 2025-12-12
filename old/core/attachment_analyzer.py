# -*- coding: utf-8 -*-
"""
Анализатор вложений письма
Проверяет: расширения файлов, MIME-типы, подозрительные паттерны
"""

import re
import json
import os
import hashlib
from typing import Dict, List, Optional
from dataclasses import dataclass, field


DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")


@dataclass
class AttachmentInfo:
    """Информация о вложении"""
    filename: str
    extension: str
    content_type: str
    size: int
    md5_hash: str = ""
    sha256_hash: str = ""
    is_dangerous: bool = False
    risk_level: str = "safe"  # safe, suspicious, dangerous, critical
    issues: List[str] = field(default_factory=list)


@dataclass
class AttachmentAnalysisResult:
    """Результат анализа вложений"""
    score: int = 0
    issues: List[Dict] = field(default_factory=list)
    attachments: List[AttachmentInfo] = field(default_factory=list)
    
    # Статистика
    total_attachments: int = 0
    dangerous_attachments: int = 0
    suspicious_attachments: int = 0


class AttachmentAnalyzer:
    """Анализатор вложений"""
    
    def __init__(self):
        self.dangerous_data = self._load_dangerous_extensions()
        
        # MIME типы для проверки соответствия
        self.expected_mimes = {
            '.pdf': ['application/pdf'],
            '.doc': ['application/msword'],
            '.docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
            '.xls': ['application/vnd.ms-excel'],
            '.xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
            '.ppt': ['application/vnd.ms-powerpoint'],
            '.pptx': ['application/vnd.openxmlformats-officedocument.presentationml.presentation'],
            '.zip': ['application/zip', 'application/x-zip-compressed'],
            '.rar': ['application/x-rar-compressed', 'application/vnd.rar'],
            '.7z': ['application/x-7z-compressed'],
            '.jpg': ['image/jpeg'],
            '.jpeg': ['image/jpeg'],
            '.png': ['image/png'],
            '.gif': ['image/gif'],
            '.txt': ['text/plain'],
            '.html': ['text/html'],
            '.exe': ['application/x-msdownload', 'application/x-msdos-program', 'application/octet-stream'],
        }
    
    def _load_dangerous_extensions(self) -> Dict:
        """Загрузить данные об опасных расширениях"""
        try:
            path = os.path.join(DATA_DIR, "dangerous_extensions.json")
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            return {}
    
    def analyze(self, attachments: List) -> AttachmentAnalysisResult:
        """Провести анализ всех вложений"""
        result = AttachmentAnalysisResult()
        result.total_attachments = len(attachments)
        
        for attachment in attachments:
            att_info = self._analyze_single_attachment(attachment)
            result.attachments.append(att_info)
            
            if att_info.is_dangerous:
                if att_info.risk_level == "critical":
                    result.dangerous_attachments += 1
                    result.score += 50
                elif att_info.risk_level == "dangerous":
                    result.dangerous_attachments += 1
                    result.score += 35
                elif att_info.risk_level == "suspicious":
                    result.suspicious_attachments += 1
                    result.score += 20
                
                # Добавляем проблемы в общий список
                for issue in att_info.issues:
                    result.issues.append({
                        "type": "dangerous_attachment",
                        "severity": att_info.risk_level,
                        "message": f"Опасное вложение: {att_info.filename}",
                        "details": issue
                    })
        
        return result
    
    def _analyze_single_attachment(self, attachment) -> AttachmentInfo:
        """Анализ одного вложения"""
        filename = attachment.filename if hasattr(attachment, 'filename') else str(attachment.get('filename', ''))
        content_type = attachment.content_type if hasattr(attachment, 'content_type') else str(attachment.get('content_type', ''))
        size = attachment.size if hasattr(attachment, 'size') else int(attachment.get('size', 0))
        content = attachment.content if hasattr(attachment, 'content') else attachment.get('content', b'')
        
        # Извлекаем расширение
        extension = self._get_extension(filename)
        
        att_info = AttachmentInfo(
            filename=filename,
            extension=extension,
            content_type=content_type,
            size=size
        )
        
        # Вычисляем хэши если есть контент
        if content:
            att_info.md5_hash = hashlib.md5(content).hexdigest()
            att_info.sha256_hash = hashlib.sha256(content).hexdigest()
        
        # 1. Проверка критически опасных расширений
        self._check_critical_extensions(att_info, extension, filename)
        
        # 2. Проверка высокорисковых расширений
        self._check_high_risk_extensions(att_info, extension)
        
        # 3. Проверка двойных расширений
        self._check_double_extension(att_info, filename)
        
        # 4. Проверка соответствия MIME-типа
        self._check_mime_mismatch(att_info, extension, content_type)
        
        # 5. Проверка на макросы
        self._check_macro_extensions(att_info, extension)
        
        # 6. Проверка скрытого расширения
        self._check_hidden_extension(att_info, filename)
        
        # Определяем итоговый уровень риска
        if att_info.issues:
            if any("критически опасн" in issue.lower() or "исполняем" in issue.lower() for issue in att_info.issues):
                att_info.risk_level = "critical"
                att_info.is_dangerous = True
            elif any("двойное расширение" in issue.lower() or "mime" in issue.lower() for issue in att_info.issues):
                att_info.risk_level = "dangerous"
                att_info.is_dangerous = True
            elif any("макрос" in issue.lower() or "архив" in issue.lower() for issue in att_info.issues):
                att_info.risk_level = "suspicious"
                att_info.is_dangerous = True
        
        return att_info
    
    def _get_extension(self, filename: str) -> str:
        """Получить расширение файла"""
        if '.' in filename:
            return '.' + filename.rsplit('.', 1)[-1].lower()
        return ""
    
    def _check_critical_extensions(self, att_info: AttachmentInfo, extension: str, filename: str):
        """Проверка критически опасных расширений"""
        critical_exts = self.dangerous_data.get("critical_extensions", [])
        
        if extension.lower() in critical_exts:
            att_info.is_dangerous = True
            att_info.risk_level = "critical"
            att_info.issues.append(
                f"Критически опасное расширение '{extension}' - это исполняемый файл, который может содержать вирус или вредоносный код"
            )
    
    def _check_high_risk_extensions(self, att_info: AttachmentInfo, extension: str):
        """Проверка высокорисковых расширений"""
        high_risk_exts = self.dangerous_data.get("high_risk_extensions", [])
        
        if extension.lower() in high_risk_exts:
            att_info.issues.append(
                f"Расширение '{extension}' требует осторожности - файлы этого типа могут содержать вредоносный код или макросы"
            )
    
    def _check_double_extension(self, att_info: AttachmentInfo, filename: str):
        """Проверка на двойное расширение"""
        # Паттерны двойных расширений
        double_ext_patterns = self.dangerous_data.get("double_extension_patterns", [])
        
        filename_lower = filename.lower()
        for pattern in double_ext_patterns:
            if filename_lower.endswith(pattern):
                att_info.is_dangerous = True
                att_info.risk_level = "critical"
                att_info.issues.append(
                    f"Обнаружено двойное расширение '{pattern}' - это классический приём маскировки вредоносных файлов"
                )
                return
        
        # Общая проверка на несколько расширений
        parts = filename.split('.')
        if len(parts) > 2:
            extensions = ['.' + p.lower() for p in parts[1:]]
            critical_exts = self.dangerous_data.get("critical_extensions", [])
            
            for ext in extensions:
                if ext in critical_exts:
                    att_info.is_dangerous = True
                    att_info.risk_level = "critical"
                    att_info.issues.append(
                        f"Файл содержит опасное расширение '{ext}' среди нескольких расширений - попытка маскировки"
                    )
                    break
    
    def _check_mime_mismatch(self, att_info: AttachmentInfo, extension: str, content_type: str):
        """Проверка несоответствия MIME-типа и расширения"""
        if not extension or not content_type:
            return
        
        expected = self.expected_mimes.get(extension.lower(), [])
        
        if expected and content_type.lower() not in [m.lower() for m in expected]:
            # Исключение для generic типов
            if content_type.lower() not in ['application/octet-stream', 'application/binary']:
                att_info.issues.append(
                    f"Несоответствие MIME-типа: файл '{extension}' имеет тип '{content_type}', ожидается '{expected[0]}'. Возможна подмена расширения."
                )
        
        # Особая проверка: исполняемый MIME для безопасного расширения
        dangerous_mimes = ['application/x-msdownload', 'application/x-msdos-program', 
                          'application/x-executable', 'application/x-dosexec']
        
        safe_extensions = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.jpg', '.png', '.gif', '.txt']
        
        if extension.lower() in safe_extensions and content_type.lower() in dangerous_mimes:
            att_info.is_dangerous = True
            att_info.risk_level = "critical"
            att_info.issues.append(
                f"КРИТИЧЕСКАЯ УГРОЗА: Файл выглядит как '{extension}', но MIME-тип указывает на исполняемый файл!"
            )
    
    def _check_macro_extensions(self, att_info: AttachmentInfo, extension: str):
        """Проверка расширений с макросами"""
        macro_exts = self.dangerous_data.get("macro_extensions", [])
        
        if extension.lower() in macro_exts:
            att_info.issues.append(
                f"Файл '{extension}' может содержать макросы - они часто используются для распространения вредоносного ПО"
            )
    
    def _check_hidden_extension(self, att_info: AttachmentInfo, filename: str):
        """Проверка на скрытое расширение (множество пробелов перед настоящим)"""
        # Проверяем на множество пробелов в имени файла
        if '   ' in filename:  # Три или более пробела подряд
            att_info.issues.append(
                "Имя файла содержит множество пробелов - возможна попытка скрыть настоящее расширение"
            )
        
        # Проверяем на Unicode-символы, имитирующие расширения
        # Например: filename.txt[RLO].exe где [RLO] - символ reverse text
        if '\u202e' in filename or '\u200e' in filename or '\u200f' in filename:
            att_info.is_dangerous = True
            att_info.risk_level = "critical"
            att_info.issues.append(
                "Обнаружены специальные Unicode-символы для скрытия расширения - высокая вероятность вредоносного файла"
            )

