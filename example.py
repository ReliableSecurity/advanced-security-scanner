#!/usr/bin/env python3
"""
Пример использования Advanced Security Scanner
Демонстрация основных возможностей сканера
"""

import asyncio
import sys
import os
from pathlib import Path

# Добавляем путь к src
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from core.config_manager import ConfigManager
from scanners.nuclei_scanner import NucleiScanner
from scanners.tool_integrations import ToolIntegrationManager
from wstg_tests.wstg_core import WSTGCore
from api_tests.api_security_scanner import APISecurityScanner
from reports.report_generator import ReportGenerator

async def example_nuclei_scan():
    """Пример сканирования с Nuclei"""
    print("🔍 Пример сканирования с Nuclei")
    print("=" * 50)
    
    # Инициализация
    config_manager = ConfigManager()
    scanner = NucleiScanner(config_manager)
    
    if not scanner.available:
        print("❌ Nuclei не доступен. Установите его для запуска этого примера.")
        return None
    
    # Настройки сканирования
    target = "https://httpbin.org"  # Безопасная тестовая цель
    options = {
        'templates': ['technologies'],  # Только технологии для безопасности
        'rate_limit': 50,
        'timeout': 5
    }
    
    print(f"🎯 Цель: {target}")
    print(f"⚙️ Настройки: {options}")
    print("⏳ Запуск сканирования...")
    
    # Запуск сканирования
    result = await scanner.scan_async([target], options)
    
    # Отображение результатов
    print(f"\n📊 Статус: {result['status']}")
    print(f"📈 Найдено результатов: {len(result['results'])}")
    
    if result['results']:
        print("\n🔍 Первые 3 результата:")
        for i, finding in enumerate(result['results'][:3], 1):
            print(f"{i}. {finding.get('name', 'Unknown')}")
            print(f"   Severity: {finding.get('severity_level', 'info')}")
            print(f"   Host: {finding.get('host', 'N/A')}")
            print()
    
    return result

async def example_wstg_test():
    """Пример OWASP WSTG тестирования"""
    print("\n🛡️ Пример OWASP WSTG тестирования")
    print("=" * 50)
    
    # Инициализация
    config_manager = ConfigManager()
    wstg = WSTGCore(config_manager)
    
    target = "https://httpbin.org"
    print(f"🎯 Цель: {target}")
    print("⏳ Запуск WSTG тестов информационного сбора...")
    
    # Запуск тестов категории INFO
    results = await wstg.run_test_category(target, 'WSTG-INFO')
    
    print(f"\n📊 Выполнено тестов: {len(results)}")
    
    for result in results:
        print(f"\n🧪 Тест: {result.test_name}")
        print(f"   ID: {result.test_id}")
        print(f"   Статус: {result.status}")
        print(f"   Находок: {len(result.findings)}")
        
        if result.findings:
            print("   Основные находки:")
            for finding in result.findings[:2]:
                print(f"   - {finding['description']} (Severity: {finding['severity']})")
    
    return results

async def example_api_security_scan():
    """Пример тестирования API безопасности"""
    print("\n🌐 Пример тестирования API безопасности")
    print("=" * 50)
    
    # Инициализация
    config_manager = ConfigManager()
    api_scanner = APISecurityScanner(config_manager)
    
    target = "https://httpbin.org"
    print(f"🎯 Цель: {target}")
    print("⏳ Обнаружение API endpoints...")
    
    # Обнаружение endpoints
    endpoints = await api_scanner.discover_endpoints(target)
    print(f"📍 Найдено endpoints: {len(endpoints)}")
    
    if endpoints:
        print("🔍 Первые 3 endpoint:")
        for i, endpoint in enumerate(endpoints[:3], 1):
            print(f"{i}. {endpoint.method} {endpoint.url}")
        
        print("\n⏳ Запуск тестов безопасности...")
        
        # Запуск тестов (только на первом endpoint для безопасности)
        test_results = await api_scanner.run_security_tests(
            endpoints[:1], 
            {'tests': ['data_exposure', 'error_handling']}  # Безопасные тесты
        )
        
        print(f"🧪 Выполнено тестов: {len(test_results)}")
        
        for result in test_results:
            print(f"\n🔬 Тест: {result.test_name}")
            print(f"   Endpoint: {result.endpoint.method} {result.endpoint.url}")
            print(f"   Статус: {result.status}")
            print(f"   Находок: {len(result.findings)}")
    
    return endpoints

def example_report_generation(scan_data):
    """Пример генерации отчета"""
    print("\n📄 Пример генерации отчета")
    print("=" * 50)
    
    if not scan_data:
        print("❌ Нет данных для генерации отчета")
        return
    
    # Инициализация генератора отчетов
    config_manager = ConfigManager()
    report_generator = ReportGenerator(config_manager)
    
    # Подготовка данных для отчета
    report_data = {
        'target': 'https://httpbin.org',
        'start_time': scan_data.get('start_time'),
        'end_time': scan_data.get('end_time'),
        'tool_results': {
            'nuclei': scan_data
        }
    }
    
    try:
        # Генерация HTML отчета
        html_report = report_generator.generate_html_report(report_data, 'example_report.html')
        print(f"✅ HTML отчет создан: {html_report}")
        
        # Генерация JSON отчета
        json_report = report_generator.generate_json_report(report_data, 'example_report.json')
        print(f"✅ JSON отчет создан: {json_report}")
        
    except Exception as e:
        print(f"❌ Ошибка генерации отчета: {e}")

async def main():
    """Главная функция демонстрации"""
    print("🚀 Advanced Security Scanner - Демонстрация возможностей")
    print("=" * 60)
    print("\n⚠️ ВНИМАНИЕ: Этот пример использует безопасные тестовые цели.")
    print("⚠️ НЕ запускайте сканирование против чужих ресурсов без разрешения!")
    print("⚠️ Используйте только на собственных системах или тестовых средах.")
    
    input("\n📝 Нажмите Enter для продолжения или Ctrl+C для выхода...")
    
    all_results = {}
    
    try:
        # 1. Тестирование Nuclei
        nuclei_result = await example_nuclei_scan()
        if nuclei_result:
            all_results['nuclei'] = nuclei_result
        
        # 2. OWASP WSTG тестирование
        wstg_results = await example_wstg_test()
        if wstg_results:
            all_results['wstg'] = {'results': wstg_results}
        
        # 3. API тестирование
        api_endpoints = await example_api_security_scan()
        if api_endpoints:
            all_results['api'] = {'endpoints': api_endpoints}
        
        # 4. Генерация отчета
        if all_results:
            example_report_generation(all_results.get('nuclei'))
        
        print("\n✅ Демонстрация завершена успешно!")
        print("\nℹ️ Для полного использования сканера:")
        print("   1. Установите все необходимые инструменты")
        print("   2. Запустите: python main.py")
        print("   3. Используйте графический интерфейс для настройки и сканирования")
        
    except KeyboardInterrupt:
        print("\n\n⏹ Демонстрация прервана пользователем")
    except Exception as e:
        print(f"\n❌ Ошибка во время демонстрации: {e}")
        print("💡 Убедитесь что все зависимости установлены: pip install -r requirements.txt")

if __name__ == "__main__":
    asyncio.run(main())