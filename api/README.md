# Security Manager API

Security Manager  API обеспечивает программный доступ ко всем утилитам Security Manager через код на C++.

## Архитектура

Для повышения удобства сопровождения API организован в отдельные модули:

```
api/
├── include/                 # Заголовочные файлы
│   ├── securitymanager.h    # Основной заголовок
│   ├── smpass_api.h         # Менеджер паролей
│   ├── smnet_api.h          # Менеджер сети
│   ├── smlog_api.h          # Анализ логов
│   ├── smssh_api.h          # Менеджер безопасности SSH
│   └── smdb_api.h           # База возможных атак
└── src/                     # Файлы реализации
    ├── smpass_api.cpp
    ├── smnet_api.cpp
    ├── smlog_api.cpp
    ├── smssh_api.cpp
    └── smdb_api.cpp
```

## Функции

- **Модульная архитектура**: Для каждой утилиты предусмотрены отдельные API с понятными интерфейсами.
- **Отслеживание ошибок**: Комплексная система отчетности об ошибках с использованием шаблона Result.
- **Строгая типизация**: Строго типизированные интерфейсы с современными возможностями C++
- **Кросс-платформенность**: Совместимо с многими дистрибутивами Linux.
- **MITRE ATT&CK интеграция**: Доступ к базе данных атак программным способом

## Начало работы

```cpp
#include <securitymanager.h>

int main()
{
    // Инициализация API
    SecurityManager::initialize();

    // Использование менеджера паролей
    SecurityManager::PasswordManager pwd_mgr;
    auto hash = pwd_mgr.hashString("password", SecurityManager::HashAlgorithm::SHA256);

    // Использование менеджера сети
    SecurityManager::NetworkMonitor net_mgr;
    auto ports = net_mgr.scanPorts();

    // Использование базы возможных атак
    SecurityManager::AttackDatabase attack_db;
    auto attacks = attack_db.searchAttacks("brute force");

    // Очистка данных
    SecurityManager::cleanup();
    return 0;
}
```

## Сборка

```bash
make libsecurity_manager.a  # Build static library
make all                    # Build all utilities + API
```

## Компоненты API

### PasswordManager (`smpass_api.h`)
Надежное средство хранения и хеширования паролей.

```cpp
SecurityManager::PasswordManager pwd_mgr;
auto hash = pwd_mgr.hashString("password", SecurityManager::HashAlgorithm::SHA256);
auto result = pwd_mgr.addPassword("service.com", "username", "password");
```

### NetworkMonitor (`smnet_api.h`)
Возможности сканирования и мониторинга сети.

```cpp
SecurityManager::NetworkMonitor net_mgr;
auto ports = net_mgr.scanPorts(1, 1024);
auto connections = net_mgr.getActiveConnections();
```

### LogAnalyzer (`smlog_api.h`)
Инструменты для анализа и разбора системных журналов.

```cpp
SecurityManager::LogAnalyzer log_analyzer;
auto entries = log_analyzer.readLogFile("/var/log/syslog");
auto search_results = log_analyzer.searchLogFile("/var/log/auth.log", "sshd");
```

### SSHSecurity (`smssh_api.h`)
Анализ конфигурации SSH-сервера и обнаружение атак.

```cpp
SecurityManager::SSHSecurity ssh_sec;
auto report = ssh_sec.analyzeConfiguration("/etc/ssh/sshd_config");
auto attacks = ssh_sec.detectAttacks("/var/log/auth.log");
```

### AttackDatabase (`smdb_api.h`)
Интеграция с MITRE ATT&CK.

```cpp
SecurityManager::AttackDatabase attack_db;
auto attacks = attack_db.searchAttacks("brute force");
auto info = attack_db.getAttackInfo("T1110");
```

## Обработка ошибок

Все методы API возвращают объекты `Result<T>` с кодами ошибок и сообщениями:

```cpp
auto result = pwd_mgr.hashString("test", SecurityManager::HashAlgorithm::SHA256);
if (result.success()) {
    std::cout << "Hash: " << result.data << std::endl;
} else {
    std::cerr << "Error: " << result.message << std::endl;
}
```

## Зависимости

- OpenSSL (libssl, libcrypto)
- PCAP library (libpcap)
- MaxMind DB library (libmaxminddb)
- C++20 standard library

## Примеры

Подробный пример, демонстрирующий все возможности API, можно найти в файле `api/api_example.cpp`.

## Запуск тестов

```bash
make check          # Run all tests including API
make api_test       # Run API-specific tests
```

## Коды ошибок

- `SUCCESS`: Operation completed successfully
- `FILE_NOT_FOUND`: Specified file does not exist
- `PERMISSION_DENIED`: Insufficient permissions
- `INVALID_ARGUMENT`: Invalid function arguments
- `NETWORK_ERROR`: Network-related error
- `ENCRYPTION_ERROR`: Cryptographic operation failed
- `DATABASE_ERROR`: Database operation failed
- `UNKNOWN_ERROR`: Unspecified error


## Использование памяти

Все API-объекты используют шаблон RAII (Resource Acquisition Is Initialization — приобретение ресурсов как инициализация). Объекты автоматически очищают ресурсы, когда те выходят из области видимости.

## Информация о версии

```cpp
std::string version = SecurityManager::getVersion();
// Вернет "1.0.0"
```

## Содействие

При добавлении новых функций API:
1. Обновите заголовочный файл (`security_manager_api.h`)
2. Реализуйте в исходном файле (`security_manager_api.cpp`)
3. Добавите тесты в `api_test.cpp`
4. Обновите документацию
5. Добавьте примеры кода