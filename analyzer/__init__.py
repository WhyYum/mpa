# -*- coding: utf-8 -*-
"""
Модуль анализа писем на спам и фишинг
"""

from .email_analyzer import EmailAnalyzer
from .analysis_result import AnalysisResult, CheckResult, CheckStatus, AnalysisLogger
from .data_loader import AnalysisData
from .dns_checker import get_mx_domain

__all__ = [
  'EmailAnalyzer', 
  'AnalysisResult', 
  'CheckResult', 
  'CheckStatus',
  'AnalysisLogger',
  'AnalysisData',
  'get_mx_domain'
]

