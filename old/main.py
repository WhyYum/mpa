# -*- coding: utf-8 -*-
"""
📧 Анализатор почтовых писем на фишинг

Программа для фильтрации входящих писем на предмет спама и фишинга.
Проверяет отправителя, заголовки, содержимое и вложения писем.

Запуск:
    python main.py          - GUI режим
    python main.py --cli    - CLI режим (для тестирования)
"""

import sys
import os

# Добавляем текущую директорию в путь
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def run_gui():
    """Запуск GUI приложения"""
    from gui.main_window import MainWindow
    
    app = MainWindow()
    app.run()


def run_cli():
    """CLI режим для тестирования"""
    from config import AppConfig, EmailAccount
    from core.email_client import EmailClient
    from core.risk_engine import RiskEngine
    
    print("=" * 60)
    print("📧 Анализатор почтовых писем на фишинг")
    print("=" * 60)
    print()
    
    # Загружаем конфиг
    config = AppConfig.load()
    
    if not config.accounts:
        print("Нет настроенных аккаунтов.")
        print("Добавьте аккаунт через GUI или отредактируйте accounts.json")
        return
    
    risk_engine = RiskEngine()
    
    for account in config.accounts:
        if not account.enabled:
            continue
        
        print(f"\n📬 Подключение к {account.email}...")
        
        client = EmailClient(account.host, account.port)
        if not client.connect(account.email, account.password):
            print(f"❌ Ошибка подключения к {account.email}")
            continue
        
        print(f"✅ Подключено к {account.email}")
        
        # Получаем последние письма
        client.select_folder("INBOX")
        uids = client.get_all_uids(limit=10)
        
        print(f"📨 Найдено {len(uids)} писем для анализа\n")
        
        for uid in uids:
            email = client.fetch_email(uid)
            if not email:
                continue
            
            result = risk_engine.analyze_email(email)
            
            # Выводим отчёт
            print(risk_engine.format_analysis_report(result))
            print()
        
        client.disconnect()
    
    print("\n✅ Анализ завершён")


def main():
    """Точка входа"""
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        run_cli()
    else:
        run_gui()


if __name__ == "__main__":
    main()

