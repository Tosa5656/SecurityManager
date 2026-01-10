# Security Manager API

The Security Manager API provides programmatic access to all Security Manager utilities through a modern, modular C++ interface.

## Architecture

The API is organized into separate modules for better maintainability:

```
api/
├── include/           # Public headers
│   ├── securitymanager.h    # Main unified header
│   ├── smpass_api.h         # Password management
│   ├── smnet_api.h          # Network monitoring
│   ├── smlog_api.h          # Log analysis
│   ├── smssh_api.h          # SSH security
│   └── smdb_api.h           # MITRE ATT&CK database
└── src/               # Implementation files
    ├── smpass_api.cpp
    ├── smnet_api.cpp
    ├── smlog_api.cpp
    ├── smssh_api.cpp
    └── smdb_api.cpp
```

## Features

- **Modular Design**: Separate APIs for each utility with clear interfaces
- **Unified Interface**: Single header includes all components
- **Error Handling**: Comprehensive error reporting with Result<T> pattern
- **Type Safety**: Strongly typed interfaces with modern C++ features
- **Cross-platform**: Compatible with Linux systems
- **MITRE ATT&CK Integration**: Access to attack database programmatically
- **Thread Safety**: Designed for concurrent use where applicable

## Quick Start

```cpp
#include <securitymanager.h>

int main()
{
    // Initialize API
    SecurityManager::initialize();

    // Use password manager
    SecurityManager::PasswordManager pwd_mgr;
    auto hash = pwd_mgr.hashString("password", SecurityManager::HashAlgorithm::SHA256);

    // Use network monitor
    SecurityManager::NetworkMonitor net_mgr;
    auto ports = net_mgr.scanPorts();

    // Use ATT&CK database
    SecurityManager::AttackDatabase attack_db;
    auto attacks = attack_db.searchAttacks("brute force");

    SecurityManager::cleanup();
    return 0;
}
```

## Building the API

### Using Make (recommended)
```bash
make libsecurity_manager.a  # Build static library
make all                    # Build all utilities + API
```

### Manual compilation
```bash
# Compile individual API modules
g++ -std=c++20 -Iapi/include -c api/src/smpass_api.cpp -o obj/smpass_api.o
g++ -std=c++20 -Iapi/include -c api/src/smnet_api.cpp -o obj/smnet_api.o
g++ -std=c++20 -Iapi/include -c api/src/smlog_api.cpp -o obj/smlog_api.o
g++ -std=c++20 -Iapi/include -c api/src/smssh_api.cpp -o obj/smssh_api.o
g++ -std=c++20 -Iapi/include -c api/src/smdb_api.cpp -o obj/smdb_api.o
g++ -std=c++20 -Iapi/include -c api/src/securitymanager.cpp -o obj/securitymanager.o

# Create static library
ar rcs libsecurity_manager.a obj/smpass_api.o obj/smnet_api.o obj/smlog_api.o obj/smssh_api.o obj/smdb_api.o obj/securitymanager.o [other deps]

# Compile your application
g++ -std=c++20 -Iapi/include -o my_app my_app.cpp libsecurity_manager.a -lssl -lcrypto -lpcap -lmaxminddb
```

## API Components

### PasswordManager (`smpass_api.h`)
Secure password storage and hashing utilities.

```cpp
SecurityManager::PasswordManager pwd_mgr;
auto hash = pwd_mgr.hashString("password", SecurityManager::HashAlgorithm::SHA256);
auto result = pwd_mgr.addPassword("service.com", "username", "password");
```

### NetworkMonitor (`smnet_api.h`)
Network scanning and monitoring capabilities.

```cpp
SecurityManager::NetworkMonitor net_mgr;
auto ports = net_mgr.scanPorts(1, 1024);
auto connections = net_mgr.getActiveConnections();
```

### LogAnalyzer (`smlog_api.h`)
System log parsing and analysis tools.

```cpp
SecurityManager::LogAnalyzer log_analyzer;
auto entries = log_analyzer.readLogFile("/var/log/syslog");
auto search_results = log_analyzer.searchLogFile("/var/log/auth.log", "sshd");
```

### SSHSecurity (`smssh_api.h`)
SSH server configuration analysis and attack detection.

```cpp
SecurityManager::SSHSecurity ssh_sec;
auto report = ssh_sec.analyzeConfiguration("/etc/ssh/sshd_config");
auto attacks = ssh_sec.detectAttacks("/var/log/auth.log");
```

### AttackDatabase (`smdb_api.h`)
MITRE ATT&CK framework integration and threat intelligence.

```cpp
SecurityManager::AttackDatabase attack_db;
auto attacks = attack_db.searchAttacks("brute force");
auto info = attack_db.getAttackInfo("T1110");
```

## Error Handling

All API methods return `Result<T>` objects with error codes and messages:

```cpp
auto result = pwd_mgr.hashString("test", SecurityManager::HashAlgorithm::SHA256);
if (result.success()) {
    std::cout << "Hash: " << result.data << std::endl;
} else {
    std::cerr << "Error: " << result.message << std::endl;
}
```

## Thread Safety

- API classes are not thread-safe by default
- Create separate instances for concurrent use
- LogAnalyzer supports monitoring from background threads

## Dependencies

- OpenSSL (libssl, libcrypto)
- PCAP library (libpcap)
- MaxMind DB library (libmaxminddb)
- C++20 standard library


## Using the API

### Basic Usage
```cpp
#include <security_manager/security_manager_api.h>

int main()
{
    // Initialize API
    SecurityManager::initialize();

    // Use password manager
    SecurityManager::Password::Manager pwd_mgr;
    auto hash_result = pwd_mgr.hashString("password", SecurityManager::Password::HashAlgorithm::SHA256);

    if (hash_result.success())
    {
        std::cout << "Hash: " << hash_result.data << std::endl;
    }

    // Use network monitor
    SecurityManager::Network::Monitor net_mgr;
    auto ports = net_mgr.scanPorts();

    // Cleanup
    SecurityManager::cleanup();
    return 0;
}
```

### Error Handling
```cpp
auto result = pwd_mgr.hashString("test", SecurityManager::Password::HashAlgorithm::SHA256);

if (result.success()) 
{
    // Use result.data
    std::cout << "Success: " << result.data << std::endl;
}
else
{
    // Handle error
    std::cerr << "Error: " << result.message << std::endl;
}
```

## API Components

### 1. Password Management
```cpp
SecurityManager::Password::Manager pwd_mgr;

// Hash passwords
auto sha256_hash = pwd_mgr.hashString("password", HashAlgorithm::SHA256);
auto aes256_hash = pwd_mgr.hashString("password", HashAlgorithm::AES256);

// Store and retrieve passwords
pwd_mgr.addPassword("service", "username", "password");
auto credentials = pwd_mgr.getPassword("service");
```

### 2. Network Monitoring
```cpp
SecurityManager::Network::Monitor net_mgr;

// Port scanning
auto ports = net_mgr.scanPorts();

// Network connections
auto connections = net_mgr.getConnections();

// Statistics
auto stats = net_mgr.getStatistics();
```

### 3. Log Analysis
```cpp
SecurityManager::Log::Analyzer log_analyzer;

// Read log files
auto entries = log_analyzer.readLogFile("/var/log/auth.log");

// Search logs
auto results = log_analyzer.searchLogFile("/var/log/syslog", "error");
```

### 4. SSH Security
```cpp
SecurityManager::SSH::Security ssh_sec;

// Analyze configuration
auto config_issues = ssh_sec.analyzeConfig("/etc/ssh/sshd_config");

// Detect attacks
auto attacks = ssh_sec.detectAttacks("/var/log/auth.log");
```

### 5. MITRE ATT&CK Database
```cpp
SecurityManager::ATTACK::Database attack_db;

// Search attacks
auto attacks = attack_db.searchAttacks("brute force");

// Get attack details
auto info = attack_db.getAttackInfo("T1110");

// Get protection tools
auto tools = attack_db.getProtectionTools("T1110");
```

## Linking with Your Application

### Static Library (recommended)
```bash
g++ -o my_app my_app.cpp -L. -lsecurity_manager -lssl -lcrypto -lpcap -lmaxminddb
```


## Examples

See `api/api_example.cpp` for a comprehensive example demonstrating all API features.

## Running Tests

```bash
make check          # Run all tests including API
make api_test       # Run API-specific tests
```

## Dependencies

- OpenSSL (libssl, libcrypto)
- libpcap
- libmaxminddb (GeoIP)
- C++20 compatible compiler

## Error Codes

- `SUCCESS`: Operation completed successfully
- `FILE_NOT_FOUND`: Specified file does not exist
- `PERMISSION_DENIED`: Insufficient permissions
- `INVALID_ARGUMENT`: Invalid function arguments
- `NETWORK_ERROR`: Network-related error
- `ENCRYPTION_ERROR`: Cryptographic operation failed
- `DATABASE_ERROR`: Database operation failed
- `UNKNOWN_ERROR`: Unspecified error

## Thread Safety

The API is designed to be thread-safe for most operations. However, some components (like log monitoring) may require external synchronization.

## Memory Management

All API objects use RAII (Resource Acquisition Is Initialization) pattern. Objects automatically clean up resources when they go out of scope.

## Version Information

```cpp
std::string version = SecurityManager::getVersion();
// Returns "1.0.0"
```

## Contributing

When adding new API functions:

1. Update the header file (`security_manager_api.h`)
2. Implement in the source file (`security_manager_api.cpp`)
3. Add tests to `api_test.cpp`
4. Update documentation
5. Update the example code