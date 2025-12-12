# -*- coding: utf-8 -*-
"""
Анализатор заголовков письма
Проверяет: SPF, DKIM, DMARC, Return-Path, Received и т.д.
"""

import re
import socket
import dns.resolver
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class AuthenticationResult:
    """Результат проверки аутентификации"""
    status: str  # pass, fail, none, softfail, neutral, temperror, permerror
    details: str = ""


@dataclass
class HeaderAnalysisResult:
    """Результат анализа заголовков"""
    score: int = 0
    issues: List[Dict] = field(default_factory=list)
    
    # Результаты аутентификации
    spf: Optional[AuthenticationResult] = None
    dkim: Optional[AuthenticationResult] = None
    dmarc: Optional[AuthenticationResult] = None
    
    # Данные из заголовков
    return_path: str = ""
    from_domain: str = ""
    received_chain: List[Dict] = field(default_factory=list)
    
    # Флаги
    return_path_mismatch: bool = False
    suspicious_route: bool = False
    missing_authentication: bool = False


class HeaderAnalyzer:
    """Анализатор заголовков письма"""
    
    def __init__(self):
        # Паттерны для парсинга
        self.received_pattern = re.compile(
            r'from\s+(\S+).*?by\s+(\S+)',
            re.IGNORECASE | re.DOTALL
        )
        self.ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
        
    def analyze(self, headers: Dict[str, str], from_email: str) -> HeaderAnalysisResult:
        """Провести полный анализ заголовков"""
        result = HeaderAnalysisResult()
        
        # Извлекаем домен отправителя
        if "@" in from_email:
            result.from_domain = from_email.split("@")[-1].lower()
        
        # 1. Проверка SPF
        self._check_spf(result, headers)
        
        # 2. Проверка DKIM
        self._check_dkim(result, headers)
        
        # 3. Проверка DMARC
        self._check_dmarc(result, headers)
        
        # 4. Проверка Return-Path
        self._check_return_path(result, headers, result.from_domain)
        
        # 5. Анализ цепочки Received
        self._analyze_received_chain(result, headers)
        
        # 6. Проверка на отсутствие аутентификации
        self._check_missing_auth(result)
        
        return result
    
    def _check_spf(self, result: HeaderAnalysisResult, headers: Dict[str, str]):
        """Проверка SPF из заголовков"""
        # Ищем результат SPF в заголовках
        spf_result = None
        
        # Проверяем Received-SPF
        received_spf = headers.get("Received-SPF", "")
        if received_spf:
            spf_result = self._parse_auth_result(received_spf)
        
        # Проверяем Authentication-Results
        auth_results = headers.get("Authentication-Results", "")
        if auth_results and not spf_result:
            spf_match = re.search(r'spf=(\w+)', auth_results, re.IGNORECASE)
            if spf_match:
                spf_result = AuthenticationResult(
                    status=spf_match.group(1).lower(),
                    details=auth_results
                )
        
        result.spf = spf_result
        
        if spf_result:
            if spf_result.status == "fail":
                result.score += 30
                result.issues.append({
                    "type": "spf_fail",
                    "severity": "critical",
                    "message": "SPF проверка не пройдена (FAIL)",
                    "details": "Письмо отправлено с сервера, не имеющего права отправлять почту от имени этого домена. Это сильный признак подделки."
                })
            elif spf_result.status == "softfail":
                result.score += 15
                result.issues.append({
                    "type": "spf_softfail",
                    "severity": "medium",
                    "message": "SPF проверка: SoftFail",
                    "details": "Сервер отправителя не полностью авторизован для отправки от имени домена."
                })
            elif spf_result.status == "none":
                result.score += 10
                result.issues.append({
                    "type": "spf_none",
                    "severity": "low",
                    "message": "SPF запись отсутствует",
                    "details": "У домена отправителя нет SPF записи. Невозможно проверить подлинность отправителя."
                })
    
    def _check_dkim(self, result: HeaderAnalysisResult, headers: Dict[str, str]):
        """Проверка DKIM из заголовков"""
        dkim_result = None
        
        # Проверяем наличие DKIM-Signature
        dkim_signature = headers.get("DKIM-Signature", "")
        
        # Проверяем результат в Authentication-Results
        auth_results = headers.get("Authentication-Results", "")
        if auth_results:
            dkim_match = re.search(r'dkim=(\w+)', auth_results, re.IGNORECASE)
            if dkim_match:
                dkim_result = AuthenticationResult(
                    status=dkim_match.group(1).lower(),
                    details=auth_results
                )
        
        result.dkim = dkim_result
        
        if dkim_result:
            if dkim_result.status == "fail":
                result.score += 25
                result.issues.append({
                    "type": "dkim_fail",
                    "severity": "high",
                    "message": "DKIM подпись недействительна (FAIL)",
                    "details": "Криптографическая подпись письма не прошла проверку. Письмо могло быть изменено или подделано."
                })
        elif not dkim_signature:
            result.score += 5
            result.issues.append({
                "type": "dkim_missing",
                "severity": "low",
                "message": "DKIM подпись отсутствует",
                "details": "Письмо не имеет криптографической подписи DKIM."
            })
    
    def _check_dmarc(self, result: HeaderAnalysisResult, headers: Dict[str, str]):
        """Проверка DMARC из заголовков"""
        dmarc_result = None
        
        auth_results = headers.get("Authentication-Results", "")
        if auth_results:
            dmarc_match = re.search(r'dmarc=(\w+)', auth_results, re.IGNORECASE)
            if dmarc_match:
                dmarc_result = AuthenticationResult(
                    status=dmarc_match.group(1).lower(),
                    details=auth_results
                )
        
        result.dmarc = dmarc_result
        
        if dmarc_result and dmarc_result.status == "fail":
            result.score += 20
            result.issues.append({
                "type": "dmarc_fail",
                "severity": "high",
                "message": "DMARC проверка не пройдена",
                "details": "Письмо не соответствует политике аутентификации домена отправителя."
            })
    
    def _check_return_path(self, result: HeaderAnalysisResult, headers: Dict[str, str], from_domain: str):
        """Проверка Return-Path"""
        return_path = headers.get("Return-Path", "")
        
        # Извлекаем email из Return-Path
        match = re.search(r'<([^>]+)>', return_path)
        if match:
            return_path_email = match.group(1)
        else:
            return_path_email = return_path.strip()
        
        result.return_path = return_path_email
        
        if not return_path_email or not from_domain:
            return
        
        # Извлекаем домен из Return-Path
        if "@" in return_path_email:
            return_path_domain = return_path_email.split("@")[-1].lower()
        else:
            return_path_domain = ""
        
        # Сравниваем домены
        if return_path_domain and return_path_domain != from_domain:
            # Проверяем, не являются ли они поддоменами
            if not return_path_domain.endswith(f".{from_domain}") and \
               not from_domain.endswith(f".{return_path_domain}"):
                result.return_path_mismatch = True
                result.score += 20
                result.issues.append({
                    "type": "return_path_mismatch",
                    "severity": "high",
                    "message": "Return-Path не соответствует отправителю",
                    "details": f"Адрес From: использует домен '{from_domain}', но Return-Path указывает на '{return_path_domain}'. Это признак подделки отправителя."
                })
    
    def _analyze_received_chain(self, result: HeaderAnalysisResult, headers: Dict[str, str]):
        """Анализ цепочки Received заголовков"""
        received_headers = []
        
        # Собираем все Received заголовки
        for key, value in headers.items():
            if key.lower() == "received":
                received_headers.append(value)
        
        # Также проверяем, если это один заголовок с несколькими значениями
        received_raw = headers.get("Received", "")
        if received_raw and received_raw not in received_headers:
            received_headers.append(received_raw)
        
        if not received_headers:
            return
        
        chain = []
        suspicious_ips = []
        
        for i, received in enumerate(received_headers):
            hop_info = {
                "raw": received[:200],  # Ограничиваем длину
                "from_server": "",
                "by_server": "",
                "ip": ""
            }
            
            # Парсим from и by
            match = self.received_pattern.search(received)
            if match:
                hop_info["from_server"] = match.group(1)
                hop_info["by_server"] = match.group(2)
            
            # Извлекаем IP
            ip_match = self.ip_pattern.search(received)
            if ip_match:
                hop_info["ip"] = ip_match.group(1)
                
                # Проверяем на подозрительные IP (приватные сети в публичных хопах)
                ip = ip_match.group(1)
                if not self._is_private_ip(ip):
                    # Можно добавить проверку геолокации и репутации
                    pass
            
            chain.append(hop_info)
        
        result.received_chain = chain
        
        # Проверка количества хопов
        if len(chain) > 10:
            result.score += 10
            result.issues.append({
                "type": "many_hops",
                "severity": "medium",
                "message": f"Много промежуточных серверов: {len(chain)}",
                "details": "Письмо прошло через большое количество серверов, что может указывать на использование прокси или ретрансляторов."
            })
    
    def _check_missing_auth(self, result: HeaderAnalysisResult):
        """Проверка на отсутствие аутентификации"""
        if not result.spf and not result.dkim and not result.dmarc:
            result.missing_authentication = True
            result.score += 15
            result.issues.append({
                "type": "no_authentication",
                "severity": "medium",
                "message": "Отсутствует аутентификация отправителя",
                "details": "Письмо не содержит результатов проверки SPF, DKIM или DMARC. Невозможно подтвердить подлинность отправителя."
            })
    
    def _parse_auth_result(self, header_value: str) -> AuthenticationResult:
        """Парсинг результата аутентификации"""
        header_lower = header_value.lower()
        
        if header_lower.startswith("pass"):
            return AuthenticationResult(status="pass", details=header_value)
        elif header_lower.startswith("fail"):
            return AuthenticationResult(status="fail", details=header_value)
        elif header_lower.startswith("softfail"):
            return AuthenticationResult(status="softfail", details=header_value)
        elif header_lower.startswith("neutral"):
            return AuthenticationResult(status="neutral", details=header_value)
        elif header_lower.startswith("none"):
            return AuthenticationResult(status="none", details=header_value)
        else:
            return AuthenticationResult(status="unknown", details=header_value)
    
    def _is_private_ip(self, ip: str) -> bool:
        """Проверка, является ли IP приватным"""
        try:
            parts = [int(p) for p in ip.split('.')]
            if len(parts) != 4:
                return False
            
            # 10.x.x.x
            if parts[0] == 10:
                return True
            # 172.16.x.x - 172.31.x.x
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            # 192.168.x.x
            if parts[0] == 192 and parts[1] == 168:
                return True
            # 127.x.x.x (localhost)
            if parts[0] == 127:
                return True
            
            return False
        except:
            return False
    
    def get_domain_info(self, domain: str) -> Dict:
        """Получить информацию о домене через DNS"""
        info = {
            "domain": domain,
            "mx_records": [],
            "spf_record": "",
            "has_dmarc": False,
            "error": None
        }
        
        try:
            # MX записи
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                info["mx_records"] = [str(r.exchange).rstrip('.') for r in mx_records]
            except:
                pass
            
            # SPF запись
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                for r in txt_records:
                    txt = str(r).strip('"')
                    if txt.startswith('v=spf1'):
                        info["spf_record"] = txt
                        break
            except:
                pass
            
            # DMARC
            try:
                dmarc_domain = f"_dmarc.{domain}"
                dmarc_records = dns.resolver.resolve(dmarc_domain, 'TXT')
                for r in dmarc_records:
                    txt = str(r).strip('"')
                    if 'v=DMARC1' in txt:
                        info["has_dmarc"] = True
                        break
            except:
                pass
                
        except Exception as e:
            info["error"] = str(e)
        
        return info

