# -*- coding: utf-8 -*-
"""
IMAP клиент для работы с почтовыми ящиками
"""

import imaplib
import email
import ssl
from email.message import Message
from email.header import decode_header
from email.utils import parseaddr
from typing import List, Optional, Dict, Any, Union
from dataclasses import dataclass, field
from datetime import datetime
import re


@dataclass
class EmailAttachment:
    """Вложение письма"""
    filename: str
    content_type: str
    size: int
    content: bytes = field(repr=False)


@dataclass
class ParsedEmail:
    """Распарсенное письмо"""
    uid: str
    message_id: str
    subject: str
    from_name: str
    from_email: str
    to_email: str
    date: Optional[datetime]
    headers: Dict[str, str]
    body_text: str
    body_html: str
    attachments: List[EmailAttachment]
    raw_headers: str
    
    # Поля для результатов анализа
    risk_score: int = 0
    risk_level: str = "safe"
    analysis_results: Dict[str, Any] = field(default_factory=dict)


class EmailClient:
    """IMAP клиент для работы с почтой"""
    
    def __init__(self, host: str, port: int = 993, 
                 use_ssl: bool = True, use_starttls: bool = False):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.use_starttls = use_starttls
        self.connection: Optional[Union[imaplib.IMAP4, imaplib.IMAP4_SSL]] = None
        self.current_folder: str = "INBOX"
    
    @classmethod
    def from_account(cls, account) -> "EmailClient":
        """Создать клиент из объекта EmailAccount"""
        return cls(
            host=account.host,
            port=account.port,
            use_ssl=account.use_ssl,
            use_starttls=account.use_starttls
        )
    
    def connect(self, email_address: str, password: str) -> bool:
        """Подключиться к IMAP серверу"""
        try:
            if self.use_ssl:
                self.connection = imaplib.IMAP4_SSL(self.host, self.port)
            else:
                self.connection = imaplib.IMAP4(self.host, self.port)
                if self.use_starttls:
                    self.connection.starttls()
            
            self.connection.login(email_address, password)
            return True
        except imaplib.IMAP4.error as e:
            print(f"Ошибка авторизации IMAP: {e}")
            return False
        except Exception as e:
            print(f"Ошибка подключения: {e}")
            return False
    
    def disconnect(self):
        """Отключиться от сервера"""
        if self.connection:
            try:
                self.connection.logout()
            except:
                pass
            self.connection = None
    
    def select_folder(self, folder: str = "INBOX") -> bool:
        """Выбрать папку"""
        if not self.connection:
            return False
        try:
            status, _ = self.connection.select(folder)
            if status == "OK":
                self.current_folder = folder
                return True
            return False
        except Exception as e:
            print(f"Ошибка выбора папки: {e}")
            return False
    
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
                    match = re.search(rb'"([^"]+)"$', folder)
                    if match:
                        folder_name = match.group(1).decode('utf-8', errors='replace')
                        result.append(folder_name)
            return result
        except Exception as e:
            print(f"Ошибка получения папок: {e}")
            return []
    
    def get_unread_uids(self) -> List[str]:
        """Получить UID непрочитанных писем"""
        if not self.connection:
            return []
        try:
            status, data = self.connection.uid('search', None, 'UNSEEN')
            if status != "OK":
                return []
            uids = data[0].decode().split()
            return uids
        except Exception as e:
            print(f"Ошибка получения непрочитанных писем: {e}")
            return []
    
    def get_all_uids(self, limit: int = 100) -> List[str]:
        """Получить UID всех писем (с ограничением)"""
        if not self.connection:
            return []
        try:
            status, data = self.connection.uid('search', None, 'ALL')
            if status != "OK":
                return []
            uids = data[0].decode().split()
            return uids[-limit:] if len(uids) > limit else uids
        except Exception as e:
            print(f"Ошибка получения писем: {e}")
            return []
    
    def fetch_email(self, uid: str) -> Optional[ParsedEmail]:
        """Получить и распарсить письмо по UID"""
        if not self.connection:
            return None
        try:
            status, data = self.connection.uid('fetch', uid, '(RFC822)')
            if status != "OK" or not data or not data[0]:
                return None
            
            raw_email = data[0][1]
            msg = email.message_from_bytes(raw_email)
            
            return self._parse_email(uid, msg)
        except Exception as e:
            print(f"Ошибка получения письма {uid}: {e}")
            return None
    
    def _parse_email(self, uid: str, msg: Message) -> ParsedEmail:
        """Распарсить email сообщение"""
        # Декодируем тему
        subject = self._decode_header(msg.get("Subject", ""))
        
        # Парсим отправителя
        from_header = msg.get("From", "")
        from_name, from_email = parseaddr(from_header)
        from_name = self._decode_header(from_name)
        
        # Получатель
        to_email = msg.get("To", "")
        
        # Дата
        date_str = msg.get("Date", "")
        date = self._parse_date(date_str)
        
        # Message-ID
        message_id = msg.get("Message-ID", "")
        
        # Собираем все заголовки
        headers = {}
        raw_headers_list = []
        for key in msg.keys():
            value = msg.get(key, "")
            if isinstance(value, str):
                headers[key] = value
                raw_headers_list.append(f"{key}: {value}")
        raw_headers = "\n".join(raw_headers_list)
        
        # Извлекаем тело письма и вложения
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
                        if content:
                            attachments.append(EmailAttachment(
                                filename=filename,
                                content_type=content_type,
                                size=len(content),
                                content=content
                            ))
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
        
        return ParsedEmail(
            uid=uid,
            message_id=message_id,
            subject=subject,
            from_name=from_name,
            from_email=from_email,
            to_email=to_email,
            date=date,
            headers=headers,
            body_text=body_text,
            body_html=body_html,
            attachments=attachments,
            raw_headers=raw_headers
        )
    
    def _decode_header(self, header: str) -> str:
        """Декодировать заголовок письма"""
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
    
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Распарсить дату письма"""
        if not date_str:
            return None
        try:
            from email.utils import parsedate_to_datetime
            return parsedate_to_datetime(date_str)
        except:
            return None
    
    def move_to_spam(self, uid: str, spam_folder: str = "Spam") -> bool:
        """Переместить письмо в спам"""
        if not self.connection:
            return False
        try:
            # Копируем в спам
            status, _ = self.connection.uid('copy', uid, spam_folder)
            if status != "OK":
                # Пробуем альтернативные названия
                for folder in ["Spam", "Junk", "Спам", "[Gmail]/Spam", "INBOX.Spam"]:
                    status, _ = self.connection.uid('copy', uid, folder)
                    if status == "OK":
                        break
            
            if status == "OK":
                # Помечаем для удаления
                self.connection.uid('store', uid, '+FLAGS', '\\Deleted')
                self.connection.expunge()
                return True
            return False
        except Exception as e:
            print(f"Ошибка перемещения в спам: {e}")
            return False
    
    def mark_as_spam(self, uid: str) -> bool:
        """Пометить письмо как спам (флаг)"""
        if not self.connection:
            return False
        try:
            # Помечаем флагом спама (если поддерживается)
            self.connection.uid('store', uid, '+FLAGS', '\\Junk')
            return True
        except:
            return False

