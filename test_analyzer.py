# -*- coding: utf-8 -*-
"""
Скрипт тестирования анализатора на реальных письмах v2.0
Проверяет, что спам/фишинг детектируется, а легитимные письма - нет
"""

import os
import email
from email.header import decode_header
from email.utils import parseaddr, parsedate_to_datetime
from datetime import datetime
from analyzer import EmailAnalyzer

# Пути
DATA_DIR = "data"
LOGS_DIR = "logs"
MAILS_DIR = "mails/average.scam.victim@gmail.com"


def decode_header_value(header):
  """Декодировать заголовок"""
  if not header:
    return ""
  try:
    decoded_parts = decode_header(header)
    result = []
    for content, charset in decoded_parts:
      if isinstance(content, bytes):
        charset = charset or 'utf-8'
        result.append(content.decode(charset, errors='replace'))
      else:
        result.append(content)
    return "".join(result)
  except:
    return header


def parse_eml_file(filepath: str) -> dict:
  """Парсинг .eml файла"""
  with open(filepath, "rb") as f:
    msg = email.message_from_bytes(f.read())
  
  # Заголовки
  subject = decode_header_value(msg.get("Subject", ""))
  from_header = msg.get("From", "")
  from_name, from_email = parseaddr(from_header)
  from_name = decode_header_value(from_name)
  to_email = msg.get("To", "")
  
  date = None
  date_str = msg.get("Date", "")
  if date_str:
    try:
      date = parsedate_to_datetime(date_str)
    except:
      pass
  
  message_id = msg.get("Message-ID", "") or f"test-{os.path.basename(filepath)}"
  
  # Все заголовки
  headers = {}
  for key in msg.keys():
    value = msg.get(key, "")
    if isinstance(value, str):
      headers[key] = value
  
  # Тело
  body_text = ""
  body_html = ""
  attachments = []
  
  if msg.is_multipart():
    for part in msg.walk():
      content_type = part.get_content_type()
      content_disposition = str(part.get("Content-Disposition", ""))
      
      if "attachment" in content_disposition:
        filename = part.get_filename()
        if filename:
          filename = decode_header_value(filename)
          content = part.get_payload(decode=True)
          attachments.append({
            "filename": filename,
            "content_type": content_type,
            "size": len(content) if content else 0
          })
      elif content_type == "text/plain":
        payload = part.get_payload(decode=True)
        if payload:
          charset = part.get_content_charset() or 'utf-8'
          body_text += payload.decode(charset, errors='replace')
      elif content_type == "text/html":
        payload = part.get_payload(decode=True)
        if payload:
          charset = part.get_content_charset() or 'utf-8'
          body_html += payload.decode(charset, errors='replace')
  else:
    content_type = msg.get_content_type()
    payload = msg.get_payload(decode=True)
    if payload:
      charset = msg.get_content_charset() or 'utf-8'
      text = payload.decode(charset, errors='replace')
      if content_type == "text/html":
        body_html = text
      else:
        body_text = text
  
  return {
    "message_id": message_id,
    "subject": subject,
    "from_name": from_name,
    "from_email": from_email,
    "to_email": to_email,
    "date": date,
    "headers": headers,
    "body_text": body_text,
    "body_html": body_html,
    "attachments": attachments
  }


def analyze_single_file(analyzer, filepath: str, verbose: bool = True):
  """Анализировать один файл и показать детальный результат"""
  email_data = parse_eml_file(filepath)
  result = analyzer.analyze(email_data, "average.scam.victim@gmail.com")
  
  if verbose:
    print(f"\n{'='*60}")
    print(f"Файл: {os.path.basename(filepath)}")
    print(f"От: {email_data.get('from_name', '')} <{email_data.get('from_email', '')}>")
    print(f"Тема: {email_data.get('subject', '')}")
    print(f"{'='*60}")
    print(f"Результат: {result.risk_level.upper()} (score: {result.total_score:.1f})")
    print(f"Спам: {'ДА' if result.is_spam else 'нет'}")
    print(f"Фишинг: {'ДА' if result.is_phishing else 'нет'}")
    print(f"\nПроверки:")
    for check in result.checks:
      icon = "✗" if check.status.value == "fail" else ("⚠" if check.status.value == "warning" else "✓")
      print(f"  {icon} {check.name}: {check.title} ({check.score:+.1f})")
      if check.status.value == "fail" and check.description:
        print(f"      → {check.description}")
  
  return result


def main():
  print("=" * 70)
  print("ТЕСТИРОВАНИЕ АНАЛИЗАТОРА ПИСЕМ v2.0")
  print("=" * 70)
  
  # Инициализация
  analyzer = EmailAnalyzer(DATA_DIR, LOGS_DIR)
  
  # Тестовые файлы
  test_files = [
    # Должны быть СПАМ/ФИШИНГ
    ("Security Alert - clearly.not.scammer@gmail.com - 2025-12-13 0055.eml", True),
    ("You are being scammed - Steam Support (clearly.not.scammer@gmail.com) - 2025-12-13 0055.eml", True),
    ("ѕесuritу Аlert - clearly.not.scammer@gmail.com - 2025-12-13 0037.eml", True),
    
    # Должны быть БЕЗОПАСНЫ
    ("Ваш аккаунт Google восстановлен - Google (no-reply@accounts.google.com) - 2025-12-07 2116.eml", False),
    ("Тестовое письмо - WhyYum (me@whyyum.com) - 2025-12-07 2247.eml", False),
    ("Sign in to Selectext requested at 2025 December 12 23 01 UTC - noreply@login.selectext.app - 2025-12-13 0201.eml", False),
  ]
  
  # Статистика
  correct = 0
  total = 0
  errors = []
  
  for filename, expected_spam in test_files:
    filepath = os.path.join(MAILS_DIR, filename)
    if not os.path.exists(filepath):
      print(f"⚠️ Файл не найден: {filename}")
      continue
    
    try:
      result = analyze_single_file(analyzer, filepath, verbose=True)
      total += 1
      
      is_detected_spam = result.is_spam or result.is_phishing or result.risk_level == "critical"
      
      if is_detected_spam == expected_spam:
        correct += 1
        print(f"\n✅ ПРАВИЛЬНО: {'спам обнаружен' if expected_spam else 'письмо безопасно'}")
      else:
        if expected_spam:
          errors.append(f"FALSE NEGATIVE: {filename}")
          print(f"\n❌ ОШИБКА: спам НЕ обнаружен!")
        else:
          errors.append(f"FALSE POSITIVE: {filename}")
          print(f"\n❌ ОШИБКА: легитимное письмо помечено как спам!")
      
    except Exception as e:
      print(f"❌ Ошибка обработки {filename}: {e}")
      import traceback
      traceback.print_exc()
  
  # Итоги
  print("\n" + "=" * 70)
  print("📊 ИТОГОВЫЕ РЕЗУЛЬТАТЫ:")
  print(f"   Правильно: {correct}/{total} ({100*correct/total:.0f}%)" if total > 0 else "")
  
  if errors:
    print(f"\n⚠️ ОШИБКИ ({len(errors)}):")
    for err in errors:
      print(f"   • {err}")
  else:
    print(f"\n✅ ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО!")
  
  print("=" * 70)


if __name__ == "__main__":
  main()

