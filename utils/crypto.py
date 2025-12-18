# -*- coding: utf-8 -*-
"""
Утилиты шифрования
"""

import base64


def encode_password(password: str) -> str:
  """Кодировать пароль в Base64"""
  return base64.b64encode(password.encode('utf-8')).decode('utf-8')


def decode_password(encoded: str) -> str:
  """Декодировать пароль из Base64"""
  try:
    return base64.b64decode(encoded.encode('utf-8')).decode('utf-8')
  except Exception:
    return encoded  # Если не удалось - возвращаем как есть

