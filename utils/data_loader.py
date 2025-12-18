# -*- coding: utf-8 -*-
"""
Загрузка данных из JSON файлов
"""

import os
import json
from typing import Dict, Any


def load_json(path: str, default: Any = None) -> Any:
  """
  Загрузить JSON файл.
  
  Args:
    path: Путь к файлу
    default: Значение по умолчанию при ошибке
    
  Returns:
    Содержимое файла или default
  """
  try:
    with open(path, "r", encoding="utf-8") as f:
      return json.load(f)
  except Exception as e:
    print(f"Ошибка загрузки {path}: {e}")
    return default if default is not None else {}


def load_error_messages(data_dir: str) -> Dict:
  """
  Загрузить сообщения об ошибках из JSON.
  
  Args:
    data_dir: Путь к папке data
    
  Returns:
    Словарь с сообщениями об ошибках
  """
  path = os.path.join(data_dir, "error_messages.json")
  default = {
    "imap_errors": {},
    "default_error": "Ошибка подключения",
    "unknown_error": "Ошибка"
  }
  return load_json(path, default)

