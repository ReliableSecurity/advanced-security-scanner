# Advanced Security Scanner

Мощный графический сканер безопасности, интегрирующий более 50 популярных инструментов безопасности, включая GVM/OpenVAS, Nuclei, и OWASP WSTG тестирование.

## 🚀 Основные возможности

### Интегрированные инструменты
- **GVM/OpenVAS** - Комплексная оценка уязвимостей
- **Nuclei** - Быстрое сканирование с шаблонами CVE
- **Nmap** - Сетевое сканирование и обнаружение сервисов
- **Nikto** - Сканирование веб-серверов
- **SQLMap** - Тестирование SQL инъекций
- **DIRB/Gobuster** - Поиск скрытых директорий
- **Wapiti** - Анализ веб-приложений
- **И многие другие...**

### Стандарты тестирования
- **OWASP WSTG** - Полная реализация Web Security Testing Guide
- **API Security** - Тестирование REST и GraphQL API
- **Network Security** - Анализ сетевой инфраструктуры
- **SSL/TLS Testing** - Проверка криптографических настроек

### Отчетность
- **HTML отчеты** с интерактивными графиками
- **PDF документы** для официальной отчетности
- **JSON формат** для интеграции с другими системами
- **Визуализация данных** с помощью диаграмм и графиков

## 🛠 Установка

### Системные требования
- **Операционная система:** Kali Linux, Ubuntu, Debian, или другие Linux дистрибутивы
- **Python:** 3.8 или выше
- **Память:** Минимум 4GB RAM (рекомендуется 8GB+)
- **Место на диске:** 2GB для установки + место для отчетов

### Установка зависимостей

```bash
# Обновление системы
sudo apt update && sudo apt upgrade -y

# Установка Python зависимостей
pip install -r requirements.txt

# Установка инструментов безопасности
sudo apt install -y nmap nikto dirb gobuster wapiti whatweb ffuf masscan

# Установка Nuclei
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
sudo cp ~/go/bin/nuclei /usr/local/bin/

# Установка шаблонов Nuclei
nuclei -update-templates

# Установка GVM/OpenVAS (опционально)
sudo apt install -y gvm
sudo gvm-setup
```

### Установка сканера

```bash
# Клонирование репозитория
git clone <repository-url>
cd security-scanner

# Установка Python зависимостей
pip install -r requirements.txt

# Запуск приложения
python main.py
```

## 🎯 Быстрый старт

### 1. Первый запуск
```bash
python main.py
```

### 2. Настройка инструментов
- Перейдите в раздел **⚙ Settings**
- Настройте пути к установленным инструментам
- Включите/выключите нужные сканеры

### 3. Простое сканирование
1. Введите целевой URL или IP в поле **Target**
2. Выберите профиль сканирования (Quick Scan рекомендуется для начала)
3. Выберите инструменты для использования
4. Нажмите **🚀 Start Scan**

### 4. Просмотр результатов
- Результаты отображаются в реальном времени
- Перейдите в **📊 Results** для детального анализа
- Сгенерируйте отчет в **📄 Reports**

## 📋 Профили сканирования

### Quick Scan (Быстрое сканирование)
- **Время:** 5-15 минут
- **Инструменты:** Nmap (топ-1000 портов), Nuclei (CVE шаблоны)
- **Применение:** Быстрая оценка основных уязвимостей

### Full Security Scan (Полное сканирование)
- **Время:** 30-60 минут
- **Инструменты:** Nmap, Nuclei, Nikto, DIRB, Wapiti
- **Применение:** Комплексная оценка безопасности

### Web Application Scan (Сканирование веб-приложений)
- **Время:** 20-45 минут
- **Инструменты:** Nuclei, Nikto, DIRB, SQLMap, WSTG тесты
- **Применение:** Фокус на безопасности веб-приложений

### API Security Scan (Тестирование API)
- **Время:** 10-30 минут
- **Инструменты:** Специализированные API тесты
- **Применение:** REST/GraphQL API безопасность

### Network Infrastructure Scan
- **Время:** 15-45 минут
- **Инструменты:** Nmap, Masscan, SSL тестирование
- **Применение:** Анализ сетевой инфраструктуры

## 🔧 Конфигурация

### Файлы конфигурации
```
~/.security_scanner/
├── config.yaml          # Основные настройки
├── tools.yaml           # Настройки инструментов
├── profiles.yaml        # Профили сканирования
└── scanner.db           # База данных результатов
```

### Пример настройки инструмента

```yaml
# tools.yaml
nuclei:
  enabled: true
  binary_path: /usr/local/bin/nuclei
  templates_dir: /home/user/nuclei-templates
  rate_limit: 150
  timeout: 10

nmap:
  enabled: true
  binary_path: /usr/bin/nmap
  timing: T4
  max_retries: 2
```

### Создание собственного профиля

```yaml
# profiles.yaml
custom_web_scan:
  name: "Custom Web Security Scan"
  description: "Мой кастомный профиль для веб-приложений"
  tools: ["nuclei", "nikto", "dirb"]
  nuclei_templates: ["cves", "exposed-panels", "vulnerabilities"]
  timeout: 1800
```

## 📊 OWASP WSTG Тестирование

Сканер реализует полный набор тестов из OWASP Web Security Testing Guide:

### Категории тестов
- **WSTG-INFO** - Сбор информации
- **WSTG-CONF** - Конфигурация и развертывание  
- **WSTG-IDNT** - Управление идентификацией
- **WSTG-ATHN** - Тестирование аутентификации
- **WSTG-ATHZ** - Тестирование авторизации
- **WSTG-SESS** - Управление сессиями
- **WSTG-INPV** - Валидация ввода
- **WSTG-ERRH** - Обработка ошибок
- **WSTG-CRYP** - Криптография
- **WSTG-BUSLOGIC** - Бизнес-логика
- **WSTG-CLNT** - Клиентская сторона

### Примеры тестов
- Анализ robots.txt и sitemap.xml
- Обнаружение технологий
- Тестирование заголовков безопасности
- Поиск резервных копий файлов
- Обнаружение админских интерфейсов
- Анализ SSL/TLS конфигурации

## 🌐 API Security Testing

### Поддерживаемые типы API
- **REST API** - Полный анализ REST endpoints
- **GraphQL** - Introspection и schema анализ
- **SOAP** - Базовое тестирование SOAP сервисов

### Тесты безопасности API
- **Аутентификация** - Тестирование JWT, OAuth, API ключей
- **Авторизация** - Проверка контроля доступа
- **Инъекции** - SQL, NoSQL, XSS, XXE
- **Rate Limiting** - Проверка ограничений запросов
- **CORS** - Анализ Cross-Origin настроек
- **Валидация входных данных**
- **Обработка ошибок**
- **Утечка данных**

## 📈 Отчетность

### Типы отчетов

#### HTML Отчеты
- Интерактивные графики и диаграммы
- Детализированные результаты по категориям
- Рекомендации по устранению
- Responsive дизайн для всех устройств

#### PDF Отчеты
- Профессиональное оформление
- Исполнительное резюме
- Таблицы и статистика
- Готов к представлению руководству

#### JSON Отчеты
- Структурированные данные
- Интеграция с SIEM системами
- Автоматизация обработки
- API совместимость

### Настройка отчетов

```python
# Пример генерации отчета
from reports.report_generator import ReportGenerator

generator = ReportGenerator(config_manager)
report_path = generator.generate_report(
    scan_results=results,
    format_type='html',  # html, pdf, json
    output_path='security_report.html'
)
```

## 🔒 Безопасность и этика

### ⚠️ Важные предупреждения
- **Используйте только на собственных ресурсах или с явного разрешения владельца**
- **Соблюдайте законодательство вашей страны**
- **Не используйте для злонамеренных целей**
- **Будьте осторожны с агрессивными настройками сканирования**

### Рекомендации по использованию
- Начинайте с Quick Scan профиля
- Тестируйте в нерабочее время
- Уведомляйте владельцев систем
- Документируйте все действия
- Следуйте принципам ответственного раскрытия

## 🤝 Вклад в проект

### Разработка
```bash
# Клонирование для разработки
git clone <repository-url>
cd security-scanner

# Создание виртуального окружения
python -m venv venv
source venv/bin/activate

# Установка зависимостей разработки
pip install -r requirements.txt
pip install pytest black flake8
```

### Структура проекта
```
security-scanner/
├── main.py                    # Точка входа
├── src/
│   ├── core/                  # Основная логика
│   ├── gui/                   # Графический интерфейс
│   ├── scanners/              # Интеграции сканеров
│   ├── wstg_tests/            # OWASP WSTG тесты
│   ├── api_tests/             # API тестирование
│   └── reports/               # Генерация отчетов
├── templates/                 # Шаблоны отчетов
├── logs/                      # Лог файлы
├── reports/                   # Готовые отчеты
└── requirements.txt
```

## 🐛 Устранение проблем

### Частые проблемы

#### "Tool not found" ошибки
```bash
# Проверка установки инструментов
which nmap nuclei nikto

# Установка недостающих
sudo apt install nmap nikto
```

#### Проблемы с разрешениями
```bash
# Права на выполнение
chmod +x main.py

# Для сырых сокетов (Nmap SYN scan)
sudo setcap cap_net_raw+ep /usr/bin/nmap
```

#### Проблемы с GUI
```bash
# Установка GUI зависимостей
sudo apt install python3-pyqt5 python3-pyqt5-dev
```

### Логи и отладка
- Логи находятся в `logs/scanner.log`
- Для подробных логов установите `DEBUG` уровень в настройках
- Используйте `--verbose` флаг при запуске

## 📚 Документация API

### Основные классы

```python
from core.config_manager import ConfigManager
from scanners.gvm_scanner import GVMScanner
from scanners.nuclei_scanner import NucleiScanner
from wstg_tests.wstg_core import WSTGCore
from api_tests.api_security_scanner import APISecurityScanner

# Инициализация
config = ConfigManager()
gvm = GVMScanner(config)
nuclei = NucleiScanner(config)
```

### Пример сканирования

```python
import asyncio
from core.config_manager import ConfigManager
from scanners.nuclei_scanner import NucleiScanner

async def scan_example():
    config = ConfigManager()
    scanner = NucleiScanner(config)
    
    result = await scanner.scan_async(
        targets=['https://example.com'],
        options={'templates': ['cves', 'exposed-panels']}
    )
    
    print(f"Found {len(result['results'])} issues")

# Запуск
asyncio.run(scan_example())
```

## 📞 Поддержка

### Получение помощи
- 📧 Email: support@security-scanner.dev
- 🐛 Issues: GitHub Issues
- 💬 Discussions: GitHub Discussions
- 📖 Wiki: GitHub Wiki

### Коммьюнити
- 🐦 Twitter: @SecurityScanner
- 💬 Discord: Security Scanner Community
- 📺 YouTube: Security Scanner Channel

## 👨‍💻 Автор

**ReliableSecurity**
- GitHub: https://github.com/ReliableSecurity
- Telegram: @ReliableSecurity

## 📄 Лицензия

Этот проект распространяется под лицензией MIT. См. файл `LICENSE` для подробностей.

## 🏆 Благодарности

- OWASP Foundation за WSTG стандарт
- ProjectDiscovery за Nuclei
- OpenVAS/GVM проект
- Все разработчики инструментов безопасности
- Сообщество информационной безопасности

---

**Сделано с ❤️ для сообщества кибербезопасности**

*Помните: с большой силой приходит большая ответственность. Используйте этот инструмент этично и законно.*