/**
 * @file smssh.cpp
 * @brief Инструмент командной строки для управления безопасностью SSH
 * @author Tosa5656
 * @date 4 января, 2026
 */

#include "sshConfig.h"
#include "sshAttackDetector.h"
#include "../logger/logger.h"
#include <iostream>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <regex>
#include <thread>
#include <chrono>

/**
 * @brief Display help information
 */
void help()
{
    std::cout << "Использование smssh:" << std::endl;
    std::cout << "smssh help - показать справочное сообщение" << std::endl;
    std::cout << "smssh analyze [путь_конфига] - проанализировать безопасность SSH конфигурации" << std::endl;
    std::cout << "smssh generate [путь_вывода] - сгенерировать безопасную SSH конфигурацию" << std::endl;
    std::cout << "smssh check [путь_конфига] - проверить текущую SSH конфигурацию" << std::endl;
    std::cout << "smssh apply [путь_конфига] - применить рекомендации по безопасности (создает резервную копию)" << std::endl;
    std::cout << "smssh show [путь_конфига] - показать текущую SSH конфигурацию" << std::endl;
    std::cout << "smssh monitor - запустить мониторинг SSH атак" << std::endl;
    std::cout << "smssh parse-log <путь_лога> - разобрать SSH лог и обнаружить атаки" << std::endl;
    std::cout << "smssh gen-key [имя_ключа] - сгенерировать SSH ключи хоста для аутентификации сервера" << std::endl;
    std::cout << "smssh post-config - показать шаги пост-конфигурации SSH сервера" << std::endl;
}

/**
 * @brief Analyze SSH configuration command
 * @param argc Argument count
 * @param argv Argument values
 */
void cmd_analyze(int argc, char* argv[])
{
    std::string config_path = "/etc/ssh/sshd_config";
    
    if (argc >= 3) {
        config_path = argv[2];
    }
    
    SSHConfig config(config_path);
    
    if (!config.loadConfig()) {
        LogError("Error: " + config.getLastError());
        return;
    }
    
    auto recommendations = config.analyzeSecurity();
    
    if (recommendations.empty()) {
        LogInfo("SSH configuration is secure!");
        return;
    }
    
    std::stringstream ss;
    ss << "Security Analysis for " << config_path << ":";
    LogInfo(ss.str());
    ss.str("");
    ss << "Found " << recommendations.size() << " security issue(s):";
    LogInfo(ss.str());
    LogInfo("");
    
    for (const auto& rec : recommendations) {
        std::string severity_color = "";
        
        if (rec.severity == "critical") {
            severity_color = "\033[1;31m"; // Красный
        } else if (rec.severity == "high") {
            severity_color = "\033[1;33m"; // Желтый
        } else if (rec.severity == "medium") {
            severity_color = "\033[1;36m"; // Голубой
        } else {
            severity_color = "\033[1;37m"; // Белый
        }
        
        ss.str("");
        ss << severity_color << "[" << rec.severity << "]\033[0m " << rec.key;
        LogInfo(ss.str());
        ss.str("");
        ss << "  Current:    " << rec.current_value;
        LogInfo(ss.str());
        ss.str("");
        ss << "  Recommended: " << rec.recommended_value;
        LogInfo(ss.str());
        ss.str("");
        ss << "  Description: " << rec.description;
        LogInfo(ss.str());
        LogInfo("");
    }
}

/**
 * @brief Команда генерации безопасной SSH конфигурации
 * @param argc Количество аргументов
 * @param argv Массив аргументов
 */
void cmd_generate(int argc, char* argv[])
{
    std::string output_path = "";
    
    if (argc >= 3) {
        output_path = argv[2];
    }
    
    SSHConfig config;
    std::string secure_config = config.generateSecureConfig();
    
    if (output_path.empty()) {
        std::cout << secure_config;
    } else {
        std::ofstream file(output_path);
        if (!file.is_open()) {
            LogError("Error: cannot write to file: " + output_path);
            return;
        }
        file << secure_config;
        file.close();
        LogInfo("Secure configuration written to: " + output_path);
    }
}

/**
 * @brief Команда проверки SSH конфигурации
 * @param argc Количество аргументов
 * @param argv Массив аргументов
 */
void cmd_check(int argc, char* argv[])
{
    std::string config_path = "/etc/ssh/sshd_config";
    
    if (argc >= 3) {
        config_path = argv[2];
    }
    
    SSHConfig config(config_path);
    
    if (!config.loadConfig()) {
        LogError("Error: " + config.getLastError());
        return;
    }
    
    std::stringstream ss;
    ss << "Current SSH Configuration (" << config_path << "):";
    LogInfo(ss.str());
    LogInfo("");
    
    auto settings = config.getCurrentSettings();
    
    if (settings.empty()) {
        LogInfo("No settings found.");
        return;
    }
    
    ss.str("");
    ss << std::left << std::setw(30) << "Setting" << "Value";
    LogInfo(ss.str());
    LogInfo(std::string(60, '-'));
    
    for (const auto& [key, value] : settings) {
        ss.str("");
        ss << std::setw(30) << key << value;
        LogInfo(ss.str());
    }
}

/**
 * @brief Команда применения рекомендаций по безопасности
 * @param argc Количество аргументов
 * @param argv Массив аргументов
 */
void cmd_apply(int argc, char* argv[])
{
    std::string config_path = "/etc/ssh/sshd_config";
    
    if (argc >= 3) {
        config_path = argv[2];
    }
    
    SSHConfig config(config_path);
    
    if (!config.loadConfig()) {
        LogError("Error: " + config.getLastError());
        return;
    }
    
    auto recommendations = config.analyzeSecurity();
    
    if (recommendations.empty()) {
        LogInfo("Configuration is already secure!");
        return;
    }
    
    std::stringstream ss;
    ss << "Applying " << recommendations.size() << " security recommendation(s)...";
    LogInfo(ss.str());
    
    // Создать резервную копию
    std::string backup_path = config_path + ".backup";
    std::ifstream src(config_path, std::ios::binary);
    std::ofstream dst(backup_path, std::ios::binary);
    
    if (src.is_open() && dst.is_open()) {
        dst << src.rdbuf();
        src.close();
        dst.close();
        LogInfo("Backup created: " + backup_path);
    } else {
        LogWarning("Warning: could not create backup file!");
    }
    
    // Применить рекомендации
    for (const auto& rec : recommendations) {
        config.setSetting(rec.key, rec.recommended_value);
        ss.str("");
        ss << "  Applied: " << rec.key << " = " << rec.recommended_value;
        LogInfo(ss.str());
    }
    
    // Сохранить конфигурацию
    if (config.saveConfig(config_path)) {
        LogInfo("");
        LogInfo("Configuration updated successfully!");
        LogInfo("Note: Restart SSH service to apply changes:");
        LogInfo("  systemctl restart sshd");
        LogInfo("  or");
        LogInfo("  systemctl restart ssh");
    } else {
        LogError("Error: " + config.getLastError());
        ss.str("");
        ss << "Restore from backup: cp " << backup_path << " " << config_path;
        LogError(ss.str());
    }
}

/**
 * @brief Команда отображения SSH конфигурации
 * @param argc Количество аргументов
 * @param argv Массив аргументов
 */
void cmd_show(int argc, char* argv[])
{
    cmd_check(argc, argv);
}

/**
 * @brief Команда генерации SSH ключей
 * @param key_name Имя ключа
 */
void cmd_gen_key(const std::string& key_name)
{
    std::cout << "Генерация пары SSH ключей хоста для сервера: " << key_name << std::endl;
    std::cout << "Это создаст SSH ключи сервера:" << std::endl;
    std::cout << "  - " << key_name << " (приватный ключ хоста)" << std::endl;
    std::cout << "  - " << key_name << ".pub (public host key)" << std::endl;
    std::cout << std::endl;

    // Создать директорию .ssh если она не существует
    std::string home_dir = std::getenv("HOME");
    std::string ssh_dir = home_dir + "/.ssh";

    // Использовать системный вызов для генерации SSH ключа
    std::string cmd = "ssh-keygen -t rsa -b 4096 -f " + ssh_dir + "/" + key_name + " -N \"\"";
    std::cout << "Executing: " << cmd << std::endl;

    int result = system(cmd.c_str());

    if (result == 0) {
        std::cout << std::endl;
        std::cout << "SSH host key pair generated successfully!" << std::endl;
        std::cout << "Private host key: " << ssh_dir << "/" << key_name << std::endl;
        std::cout << "Public host key:  " << ssh_dir << "/" << key_name << ".pub" << std::endl;
        std::cout << std::endl;
        std::cout << "Следующие шаги для настройки SSH сервера:" << std::endl;
        std::cout << "1. Скопируйте ключи на ваш SSH сервер:" << std::endl;
        std::cout << "   sudo cp " << ssh_dir << "/" << key_name << ".pub /etc/ssh/" << std::endl;
        std::cout << "2. Дайте клиенту приватный ключ: " << ssh_dir << "/" << key_name << std::endl;
        std::cout << std::endl;
        std::cout << "3. Обновите конфигурацию SSH сервера:" << std::endl;
        std::cout << "   sudo sh -c 'echo \"HostKey /etc/ssh/" << key_name << "\" >> /etc/ssh/sshd_config'" << std::endl;
        std::cout << std::endl;
        std::cout << "4. Перезапустите SSH службу:" << std::endl;
        std::cout << "   sudo systemctl restart sshd" << std::endl;
        std::cout << std::endl;
        std::cout << "5. Протестируйте соединение с SSH сервером с другой машины" << std::endl;
    } else {
        std::cout << "Не удалось сгенерировать пару SSH ключей хоста!" << std::endl;
    }
}

/**
 * @brief Команда отображения пост-конфигурационных шагов
 */
void cmd_post_config()
{
    std::cout << "=== SSH SERVER POST-CONFIGURATION STEPS ===" << std::endl;
    std::cout << std::endl;
    std::cout << "After applying security recommendations to SSH server configuration:" << std::endl;
    std::cout << std::endl;
    std::cout << "1. GENERATE SSH HOST KEYS" << std::endl;
    std::cout << "   smssh gen-key ssh_host_rsa_key" << std::endl;
    std::cout << "   or manually for server host keys:" << std::endl;
    std::cout << "   sudo ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N \"\"" << std::endl;
    std::cout << std::endl;
    std::cout << "2. ОБНОВИТЕ КОНФИГУРАЦИЮ SSH СЕРВЕРА" << std::endl;
    std::cout << "   Убедитесь, что следующие настройки установлены в /etc/ssh/sshd_config:" << std::endl;
    std::cout << "   Protocol 2" << std::endl;
    std::cout << "   PermitRootLogin no" << std::endl;
    std::cout << "   PasswordAuthentication no" << std::endl;
    std::cout << "   PubkeyAuthentication yes" << std::endl;
    std::cout << "   HostKey /etc/ssh/ssh_host_rsa_key" << std::endl;
    std::cout << std::endl;
    std::cout << "3. ПЕРЕЗАПУСТИТЕ SSH СЛУЖБУ" << std::endl;
    std::cout << "   sudo systemctl restart sshd" << std::endl;
    std::cout << "   или" << std::endl;
    std::cout << "   sudo systemctl restart ssh" << std::endl;
    std::cout << std::endl;
    std::cout << "4. ПРОТЕСТИРУЙТЕ СОЕДИНЕНИЕ С SSH СЕРВЕРОМ" << std::endl;
    std::cout << "   С другой машины протестируйте соединение:" << std::endl;
    std::cout << "   ssh user@your-server-ip" << std::endl;
    std::cout << "   Убедитесь, что можете войти в систему перед закрытием текущей сессии!" << std::endl;
    std::cout << std::endl;
    std::cout << "5. SETUP USER AUTHENTICATION" << std::endl;
    std::cout << "   On client machines, generate user keys:" << std::endl;
    std::cout << "   ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N \"\"" << std::endl;
    std::cout << "   Copy public keys to server:" << std::endl;
    std::cout << "   ssh-copy-id -i ~/.ssh/id_rsa.pub user@server" << std::endl;
    std::cout << std::endl;
    std::cout << "6. MONITOR SSH SERVER ATTACKS" << std::endl;
    std::cout << "   smssh monitor" << std::endl;
    std::cout << "   or parse existing logs:" << std::endl;
    std::cout << "   smssh parse-log /var/log/auth.log" << std::endl;
    std::cout << std::endl;
    std::cout << "IMPORTANT: Keep a backup terminal session open during testing!" << std::endl;
    std::cout << "   If you lose SSH access, you may need physical/console access to fix it." << std::endl;
    std::cout << std::endl;
    std::cout << "SSH SERVER SECURITY BEST PRACTICES:" << std::endl;
    std::cout << "   • Use dedicated SSH keys for server host authentication" << std::endl;
    std::cout << "   • Regularly rotate SSH host keys" << std::endl;
    std::cout << "   • Use fail2ban to protect against brute force attacks" << std::endl;
    std::cout << "   • Configure SSH to use non-standard port" << std::endl;
    std::cout << "   • Monitor SSH logs regularly with smssh" << std::endl;
    std::cout << "   • Use SSH certificates for large deployments" << std::endl;
    std::cout << std::endl;
}

void parse_ssh_log_line(const std::string& line, SSHAttackDetector& detector);

/**
 * @brief Команда мониторинга SSH атак
 */
void cmd_monitor()
{
    std::cout << "Starting SSH attack monitoring..." << std::endl;
    std::cout << "Press Ctrl+C to stop" << std::endl;

    SSHAttackDetector detector;

    // Мониторить /var/log/auth.log на новые записи
    std::string log_path = "/var/log/auth.log";
    std::ifstream log_file(log_path);

    if (!log_file.is_open()) {
        LogError("Cannot open log file: " + log_path);
        return;
    }

    // Перейти в конец файла для начала мониторинга с текущей позиции
    log_file.seekg(0, std::ios::end);
    std::streampos last_pos = log_file.tellg();

    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(5));

        log_file.clear();
        log_file.seekg(last_pos);

        std::string line;
        while (std::getline(log_file, line)) {
            // Разбирать строки SSH лога на попытки аутентификации
            parse_ssh_log_line(line, detector);
        }

        last_pos = log_file.tellg();

        // Анализировать обнаруженные атаки и генерировать оповещения
        auto alerts = detector.analyze();
        if (!alerts.empty()) {
            LogWarning("SSH Security Alerts Detected:");
            for (const auto& alert : alerts) {
                std::stringstream ss;
                ss << "[" << alert.severity << "] " << alert.type << " from " << alert.ip;
                if (!alert.username.empty()) {
                    ss << " (user: " << alert.username << ")";
                }
                ss << ": " << alert.description;
                LogWarning(ss.str());
            }
        }

        detector.clearOldAttempts(60); // Очистить старые попытки соединения старше 60 минут
    }
}

/**
 * @brief Команда разбора SSH лога
 * @param log_path Путь к файлу лога
 */
void cmd_parse_log(const std::string& log_path)
{
    std::cout << "Parsing SSH log file: " << log_path << std::endl;

    SSHAttackDetector detector;

    std::ifstream log_file(log_path);
    if (!log_file.is_open()) {
        LogError("Cannot open log file: " + log_path);
        return;
    }

    std::string line;
    int line_count = 0;

    while (std::getline(log_file, line)) {
        parse_ssh_log_line(line, detector);
        line_count++;

        if (line_count % 1000 == 0) {
            std::cout << "Processed " << line_count << " log lines..." << std::endl;
        }
    }

    log_file.close();

    std::cout << "Log parsing completed. Analyzing attacks..." << std::endl;

    // Отладка: показать разобранные попытки
    auto recent_attempts = detector.getRecentAttempts(60);
    std::cout << "Parsed " << recent_attempts.size() << " connection attempts" << std::endl;

    auto alerts = detector.analyze();

    if (alerts.empty()) {
        std::cout << "No SSH attacks detected!" << std::endl;
        return;
    }

    std::cout << "SSH Security Analysis Results:" << std::endl;
    std::cout << "=================================" << std::endl;

    std::map<std::string, int> alert_counts;
    for (const auto& alert : alerts) {
        alert_counts[alert.type]++;
    }

    for (const auto& [type, count] : alert_counts) {
        std::cout << type << ": " << count << " incidents" << std::endl;
    }

    std::cout << std::endl;
    std::cout << "Detailed Alerts:" << std::endl;
    for (const auto& alert : alerts) {
        std::cout << "[" << alert.severity << "] " << alert.type << " from " << alert.ip;
        if (!alert.username.empty()) {
            std::cout << " (user: " << alert.username << ")";
        }
        std::cout << std::endl;
        std::cout << "  " << alert.description << std::endl;

        for (const auto& [key, value] : alert.details) {
            std::cout << "  " << key << ": " << value << std::endl;
        }
        std::cout << std::endl;
    }
}

/**
 * @brief Разбор строки SSH лога для обнаружения атак
 * @param line Строка лога для разбора
 * @param detector Детектор SSH атак
 */
void parse_ssh_log_line(const std::string& line, SSHAttackDetector& detector)
{
    // Регулярные выражения для разбора строк SSH лога с временными метками
    static std::regex failed_password_regex(R"(\w+\s+\d+\s+\d+:\d+:\d+\s+\w+\s+sshd\[(\d+)\]:\s+Failed password for (invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+) port (\d+) ssh2)");
    static std::regex accepted_password_regex(R"(\w+\s+\d+\s+\d+:\d+:\d+\s+\w+\s+sshd\[(\d+)\]:\s+Accepted password for (\w+) from (\d+\.\d+\.\d+\.\d+) port (\d+) ssh2)");
    static std::regex accepted_pubkey_regex(R"(\w+\s+\d+\s+\d+:\d+:\d+\s+\w+\s+sshd\[(\d+)\]:\s+Accepted publickey for (\w+) from (\d+\.\d+\.\d+\.\d+) port (\d+) ssh2)");
    static std::regex invalid_user_regex(R"(\w+\s+\d+\s+\d+:\d+:\d+\s+\w+\s+sshd\[(\d+)\]:\s+Invalid user (\w+) from (\d+\.\d+\.\d+\.\d+) port (\d+))");

    std::smatch match;
    std::string ip, username;
    int port = 22;
    bool success = false;

    if (std::regex_search(line, match, failed_password_regex)) {
        // Неудачная попытка пароля
        username = match[3].str();
        ip = match[4].str();
        port = std::stoi(match[5].str());
        success = false;
    } else if (std::regex_search(line, match, accepted_password_regex) ||
               std::regex_search(line, match, accepted_pubkey_regex)) {
        // Успешная аутентификация
        username = match[2].str();
        ip = match[3].str();
        port = std::stoi(match[4].str());
        success = true;
    } else if (std::regex_search(line, match, invalid_user_regex)) {
        // Попытка с недействительным пользователем
        username = match[2].str();
        ip = match[3].str();
        port = std::stoi(match[4].str());
        success = false;
    }

    if (!username.empty() && !ip.empty()) {
        detector.addConnectionAttempt(ip, username, success, port);
    }
}

/**
 * @brief Main entry point for smssh tool
 * @param argc Argument count
 * @param argv Argument values
 * @return Exit code (0 for success, 1 for error)
 */
int main(int argc, char* argv[])
{
    if (argc == 1) {
        std::cout << "Используйте smssh help чтобы увидеть как использовать программу" << std::endl;
        return 0;
    }

    if (argc == 2 && strcmp(argv[1], "help") == 0) {
        help();
        return 0;
    }
    
    if (argc >= 2 && strcmp(argv[1], "analyze") == 0) {
        cmd_analyze(argc, argv);
        return 0;
    }
    
    if (argc >= 2 && strcmp(argv[1], "generate") == 0) {
        cmd_generate(argc, argv);
        return 0;
    }
    
    if (argc >= 2 && strcmp(argv[1], "check") == 0) {
        cmd_check(argc, argv);
        return 0;
    }
    
    if (argc >= 2 && strcmp(argv[1], "apply") == 0) {
        cmd_apply(argc, argv);
        return 0;
    }
    
    if (argc >= 2 && strcmp(argv[1], "show") == 0) {
        cmd_show(argc, argv);
        return 0;
    }

    if (argc >= 2 && strcmp(argv[1], "monitor") == 0) {
        cmd_monitor();
        return 0;
    }

    if (argc >= 3 && strcmp(argv[1], "parse-log") == 0) {
        cmd_parse_log(argv[2]);
        return 0;
    }

    if (argc >= 2 && strcmp(argv[1], "gen-key") == 0) {
        std::string key_name = (argc >= 3) ? argv[2] : "id_rsa";
        cmd_gen_key(key_name);
        return 0;
    }

    if (argc >= 2 && strcmp(argv[1], "post-config") == 0) {
        cmd_post_config();
        return 0;
    }

    std::stringstream ss;
    ss << "Error: unknown command: " << argv[1];
    LogError(ss.str());
    LogError("Use smssh help to see available commands");
    return 1;
}
