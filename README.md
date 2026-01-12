# Security Manager
[![GitHub](https://img.shields.io/badge/github-repo-blue?logo=github)](https://github.com/Tosa5656/SecurityManager)
[![Stars](https://img.shields.io/github/stars/Tosa5656/SecurityManager?style=flat&logo=GitHub&color=blue)](https://github.com/Tosa5656/SecurityManager/stargazers)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://github.com/Tosa5656/SecurityManager/blob/master/LICENSE.md)
[![Coverage](https://img.shields.io/badge/coverage-80%25-green)]()
![GitHub commit activity](https://img.shields.io/github/commit-activity/t/Tosa5656/SecurityManager)
![GitHub last commit](https://img.shields.io/github/last-commit/Tosa5656/SecurityManager)
![GitHub contributors](https://img.shields.io/github/contributors/Tosa5656/SecurityManager)

Проект направлен на облегчение работы для администраторов, а именно помощь в мониторинге и защиты системы. Для выполнения это задачи проект предоставляет набор утилит, затрагивающих основные аспекты защиты системы.

## Доступные утилиты
### smssh - Менеджер безопасности SSH
Инструмент анализа и усиления безопасности SSH сервера.

**Функции:**
- Анализ конфигурации SSH и рекомендации по безопасности
- Автоматическое усиление конфигурации SSH
- Мониторинг атак на SSH в реальном времени
- Парсинг логов SSH и поиск разных видов атак
- Генерация пар ключей SSH для безопасной аутентификации

**Использование:**
```bash
smssh help                    # Показать справку
smssh analyze                 # Анализ конфигурации SSH
smssh generate <output>       # Генерация безопасной конфигурации
smssh check                   # Проверка текущей конфигурации
smssh apply                   # Применение исправлений безопасности
smssh monitor                 # Мониторинг атак
smssh parse-log <logfile>     # Парсинг логов SSH
smssh gen-key <keyname>       # Генерация ключей SSH
```

### smlog - Анализатор системных логов
Продвинутый инструмент мониторинга и анализа системных логов.
**Функции:**
- Мониторинг логов в реальном времени с правилами оповещений
- Интеграция с systemd journal
- Поиск и фильтрация логов
- Ротация и архивирование логов
- Корреляция событий безопасности

**Использование:**
```bash
smlog help                    # Показать справку
smlog read <logfile>          # Чтение файла логов
smlog search <pattern> <file> # Поиск в логах
smlog monitor                 # Запуск мониторинга
smlog report                  # Генерация отчетов
```

### smpass - Менеджер паролей
Инструмент для безопасного хранения паролей и криптографии.

**Функции:**
- Зашифрованное хранение паролей с использованием AES256
- Хэширование паролей SHA256
- Генерация безопасных паролей
- Управление базой данных паролей

**Использование:**
```bash
smpass help                    # Показать справку
smpass add-password            # Добавить новый пароль
smpass delete-password         # Удалить пароль
smpass hash-sha256 <string>    # Хэш SHA256
smpass hash-aes256 <string>    # Шифрование AES256
```

### smnet - Монитор сети
Инструмент мониторинга и анализа сетевого трафика.

**Функции:**
- Сканирование портов и мониторинг соединений
- Статистика сетевого трафика
- Мониторинг соединений в реальном времени
- Статистика интерфейсов

**Использование:**
```bash
smnet help                    # Показать справку
smnet scan                    # Сканирование портов
smnet connections             # Мониторинг соединений
smnet stats                   # Статистика сети
```

### smdb - База данных возможных атак
Интеграция базы знаний MITRE ATT&CK с рекомендациями по защите Security Manager.

**Функции:**
- База техник основнная на MITRE ATT&CK
- Описание и анализ атак
- Рекомендации по защите с помощью Security Manager
- Возможности полнотекстового поиска
- Интеграция HTML документации

## API
Для работы с инструментами удобно через код реализованно API.  
[API README](https://github.com/Tosa5656/SecurityManager/tree/master/api)  
[Документация](https://github.com/Tosa5656/SecurityManager/blob/master/doc/api/html/index.html)

**Использование:**
```bash
smdb help                    # Показать справку
smdb list                    # Список всех атак
smdb search <keyword>        # Поиск атак
smdb show <attack_id>        # Показать детали атаки
smdb tools <attack_id>       # Показать инструменты защиты
```

## Установка

### Из исходного кода
```bash
git clone https://github.com/Tosa5656/SecurityManager
cd SecurityManager
make
make check
make doc
sudo make install
```

### Только документация
```bash
# Генерация документации
make doc

# Установка только документации (требуются права root)
sudo make install-doc-only

# Просмотр документации
xdg-open doc/utils/index.html
xdg-open doc/doxygen/html/index.html
```

### Системные требования
- Операционная система Linux
- Компилятор, совместимый с C++20
- Библиотеки разработки OpenSSL
- Библиотеки разработки libpcap
- База данных MaxMind GeoLite2

## Функции безопасности
- Обнаружение разных SSH атак
- Анализ атак на основе GeoIP
- Зашифрованное хранение паролей
- Мониторинг безопасности в реальном времени
- Автоматическое усиление безопасности
- База знаний основанная на MITRE ATT&CK
