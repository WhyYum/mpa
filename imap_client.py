# -*- coding: utf-8 -*-
"""
IMAP клиент для подключения к почте
"""

import imaplib
import email
from email.header import decode_header
from email.utils import parseaddr, parsedate_to_datetime
from email.message import Message
from typing import Optional, Union, List, Dict, Any, Tuple
from datetime import datetime
from config import EmailAccount


class IMAPClient:
  """IMAP клиент"""
  
  def __init__(self, account: EmailAccount):
    self.account = account
    self.connection: Optional[Union[imaplib.IMAP4, imaplib.IMAP4_SSL]] = None
  
  def connect(self) -> bool:
    """Подключиться к серверу"""
    try:
      print(f"Подключение к {self.account.host}:{self.account.port}...")
      
      if self.account.use_ssl:
        self.connection = imaplib.IMAP4_SSL(self.account.host, self.account.port)
      else:
        self.connection = imaplib.IMAP4(self.account.host, self.account.port)
        if self.account.use_starttls:
          self.connection.starttls()
      
      # Авторизация
      self.connection.login(self.account.email, self.account.password)
      print(f"✅ Успешно подключено к {self.account.email}")
      return True, None
      
    except imaplib.IMAP4.error as e:
      print(f"❌ Ошибка авторизации: {e}")
      return False, e
    except Exception as e:
      print(f"❌ Ошибка подключения: {e}")
      return False, e
  
  def disconnect(self):
    """Отключиться от сервера"""
    if self.connection:
      try:
        self.connection.logout()
        print("Отключено от сервера")
      except:
        pass
      self.connection = None
  
  def select_folder(self, folder: str = "INBOX") -> int:
    """Выбрать папку и вернуть кол-во писем"""
    if not self.connection:
      return 0
    
    try:
      status, data = self.connection.select(folder)
      if status == "OK":
        count = int(data[0])
        print(f"📁 Папка {folder}: {count} писем")
        return count
      return 0
    except Exception as e:
      print(f"Ошибка выбора папки: {e}")
      return 0
  
  def get_unread_count(self) -> int:
    """Получить количество непрочитанных писем"""
    if not self.connection:
      return 0
    
    try:
      status, data = self.connection.search(None, 'UNSEEN')
      if status == "OK":
        uids = data[0].split()
        return len(uids)
      return 0
    except Exception as e:
      print(f"Ошибка: {e}")
      return 0
  
  def get_folders(self) -> List[str]:
    """Получить список папок"""
    if not self.connection:
      return []
    
    try:
      status, folders = self.connection.list()
      if status != "OK":
        return []
      
      result = []
      for folder in folders:
        if isinstance(folder, bytes):
          # Парсим имя папки
          decoded = folder.decode('utf-8', errors='replace')
          # Извлекаем имя в кавычках
          if '"' in decoded:
            parts = decoded.split('"')
            if len(parts) >= 2:
              result.append(parts[-2])
      return result
    except Exception as e:
      print(f"Ошибка получения папок: {e}")
      return []
  
  def print_status(self):
    """Вывести статус подключения"""
    if not self.connection:
      print("❌ Не подключено")
      return
    
    # Выбираем INBOX
    total = self.select_folder("INBOX")
    unread = self.get_unread_count()
    
    print(f"\n📊 Статус почтового ящика:")
    print(f"   Всего писем:       {total}")
    print(f"   Непрочитанных:     {unread}")
    
    # Список папок
    folders = self.get_folders()
    if folders:
      print(f"   Папки: {', '.join(folders[:5])}{'...' if len(folders) > 5 else ''}")
  
  def get_message_uids(self, folder: str = "INBOX", 
                       criteria: str = "ALL", 
                       limit: int = 50) -> List[str]:
    """Получить список UID писем"""
    if not self.connection:
      return []
    
    try:
      self.select_folder(folder)
      status, data = self.connection.uid('search', None, criteria)
      if status != "OK":
        return []
      
      uids = data[0].decode().split()
      # Возвращаем последние N писем (новые в конце)
      return uids[-limit:] if limit else uids
    except Exception as e:
      print(f"Ошибка получения UID: {e}")
      return []
  
  def fetch_email(self, uid: str) -> Optional[Dict[str, Any]]:
    """Получить полные данные письма по UID (без пометки как прочитанное)"""
    if not self.connection:
      return None
    
    try:
      # BODY.PEEK[] - получить письмо БЕЗ пометки как прочитанное
      status, data = self.connection.uid('fetch', uid, '(BODY.PEEK[])')
      if status != "OK" or not data or not data[0]:
        return None
      
      raw_email = data[0][1]
      msg = email.message_from_bytes(raw_email)
      
      return self._parse_email(uid, msg)
    except Exception as e:
      print(f"Ошибка получения письма {uid}: {e}")
      return None
  
  def _parse_email(self, uid: str, msg: Message) -> Dict[str, Any]:
    """Распарсить email сообщение"""
    # Декодируем заголовки
    subject = self._decode_header(msg.get("Subject", ""))
    from_header = msg.get("From", "")
    from_name, from_email = parseaddr(from_header)
    from_name = self._decode_header(from_name)
    
    to_email = msg.get("To", "")
    
    # Дата
    date_str = msg.get("Date", "")
    date = None
    if date_str:
      try:
        date = parsedate_to_datetime(date_str)
      except:
        pass
    
    # Message-ID
    message_id = msg.get("Message-ID", "") or f"uid-{uid}"
    
    # Все заголовки
    headers = {}
    for key in msg.keys():
      value = msg.get(key, "")
      if isinstance(value, str):
        headers[key] = value
    
    # Тело письма и вложения
    body_text = ""
    body_html = ""
    attachments = []
    
    if msg.is_multipart():
      for part in msg.walk():
        content_type = part.get_content_type()
        content_disposition = str(part.get("Content-Disposition", ""))
        
        # Вложение
        if "attachment" in content_disposition:
          filename = part.get_filename()
          if filename:
            filename = self._decode_header(filename)
            content = part.get_payload(decode=True)
            attachments.append({
              "filename": filename,
              "content_type": content_type,
              "size": len(content) if content else 0
            })
        # Текст
        elif content_type == "text/plain":
          payload = part.get_payload(decode=True)
          if payload:
            charset = part.get_content_charset() or 'utf-8'
            body_text += payload.decode(charset, errors='replace')
        # HTML
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
      "uid": uid,
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
  
  def _decode_header(self, header: str) -> str:
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
  
  def _encode_folder_name(self, folder: str) -> str:
    """Кодировать имя папки в IMAP UTF-7"""
    try:
      # Если ASCII - возвращаем как есть
      folder.encode('ascii')
      return folder
    except UnicodeEncodeError:
      # Кодируем в modified UTF-7 для IMAP
      result = []
      ascii_part = ""
      
      for char in folder:
        if ord(char) < 128 and char != '&':
          if ascii_part != "":
            result.append(ascii_part)
            ascii_part = ""
          result.append(char)
        else:
          ascii_part += char
      
      if ascii_part:
        # Кодируем non-ASCII часть в modified UTF-7
        encoded = ascii_part.encode('utf-16-be')
        import base64
        b64 = base64.b64encode(encoded).decode('ascii').rstrip('=')
        result.append('&' + b64.replace('/', ',') + '-')
      
      return ''.join(result)
  
  def move_to_spam(self, uid: str, spam_folder: str = "Spam") -> bool:
    """Переместить письмо в спам"""
    if not self.connection:
      return False
    
    try:
      # Пробуем разные названия папки спама
      spam_folders = [spam_folder, "Spam", "Junk", "Спам", "[Gmail]/Spam", "INBOX.Spam", 
                      "&BCEEPwQwBDw-", "[Gmail]/&BCEEPwQwBDw-"]  # "Спам" в UTF-7
      
      for folder in spam_folders:
        encoded_folder = self._encode_folder_name(folder)
        try:
          status, _ = self.connection.uid('copy', uid, encoded_folder)
          if status == "OK":
            # Помечаем для удаления из текущей папки
            self.connection.uid('store', uid, '+FLAGS', '\\Deleted')
            self.connection.expunge()
            print(f"📧 Письмо {uid} перемещено в {folder}")
            return True
        except:
          continue
      
      return False
    except Exception as e:
      print(f"Ошибка перемещения в спам: {e}")
      return False

