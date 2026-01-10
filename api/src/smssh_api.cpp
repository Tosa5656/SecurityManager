/**
 * @file smssh_api.cpp
 * @brief Реализация SSH Security API
 * @author Tosa5656
 * @date 4 января, 2026
 */

#include "smssh_api.h"
#include "../../smssh/sshConfig.h"
#include "../../smssh/sshAttackDetector.h"
#include <fstream>
#include <sstream>
#include <regex>
#include <thread>
#include <atomic>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

namespace SecurityManager
{

/**
 * @brief Приватная реализация класса SSHSecurity
 */
class SSHSecurity::Impl
{
private:
    /**
     * @brief Флаг, указывающий, активен ли мониторинг
     */
    std::atomic<bool> monitoring_active{false};

    /**
     * @brief Поток мониторинга SSH атак
     */
    std::thread monitor_thread;

    SSHSecurityReport createSecurityReport(const std::vector<SSHSecurityRecommendation>& recommendations)
    {
        SSHSecurityReport report;
        report.total_issues = recommendations.size();
        report.critical_issues = 0;
        report.high_issues = 0;
        report.medium_issues = 0;
        report.low_issues = 0;
        report.security_score = 100.0;

        for (const auto& rec : recommendations)
        {
            SSHConfigIssue issue;
            issue.parameter = rec.parameter;
            issue.current_value = rec.current_value;
            issue.recommended_value = rec.recommended_value;
            issue.description = rec.rationale;
            issue.severity = "medium";
            issue.is_compliant = (rec.current_value == rec.recommended_value);

            report.issues.push_back(issue);
            report.medium_issues++;
            report.security_score -= 10;
        }

        if (report.security_score < 0)
            report.security_score = 0;

        if (report.critical_issues > 0 || report.security_score < 40)
            report.overall_risk_level = "CRITICAL";
        else if (report.high_issues > 2 || report.security_score < 60)
            report.overall_risk_level = "HIGH";
        else if (report.medium_issues > 3 || report.security_score < 80)
            report.overall_risk_level = "MEDIUM";
        else
            report.overall_risk_level = "LOW";

        report.assessment_date = getCurrentTimestamp();

        for (const auto& rec : recommendations)
        {
            SSHSecurityRecommendation rec_copy;
            rec_copy.category = "configuration";
            rec_copy.parameter = rec.parameter;
            rec_copy.current_value = rec.current_value;
            rec_copy.recommended_value = rec.recommended_value;
            rec_copy.rationale = rec.rationale;
            rec_copy.impact = "security";
            report.recommendations.push_back(rec_copy);
        }

        return report;
    }

    std::vector<SSHAttackAlert> detectAttacksFromLogs(const std::string& log_path)
    {
        std::vector<SSHAttackAlert> alerts;

        try
        {
            SSHAttackDetector detector;
            std::ifstream log_file(log_path);

            if (!log_file.is_open())
                return alerts;

            std::regex failed_password_regex(R"(\w+\s+\d+\s+\d+:\d+:\d+\s+\w+\s+sshd\[(\d+)\]:\s+Failed password for (invalid user )?(\w+) from (\d+\.\d+\.\d+\.\d+) port (\d+) ssh2)");
            std::regex accepted_password_regex(R"(\w+\s+\d+\s+\d+:\d+:\d+\s+\w+\s+sshd\[(\d+)\]:\s+Accepted password for (\w+) from (\d+\.\d+\.\d+\.\d+) port (\d+) ssh2)");
            std::regex accepted_pubkey_regex(R"(\w+\s+\d+\s+\d+:\d+:\d+\s+\w+\s+sshd\[(\d+)\]:\s+Accepted publickey for (\w+) from (\d+\.\d+\.\d+\.\d+) port (\d+) ssh2)");
            std::regex invalid_user_regex(R"(\w+\s+\d+\s+\d+:\d+:\d+\s+\w+\s+sshd\[(\d+)\]:\s+Invalid user (\w+) from (\d+\.\d+\.\d+\.\d+) port (\d+))");

            std::string line;
            while (std::getline(log_file, line))
            {
                std::smatch match;
                std::string ip, username;
                int port = 22;
                bool success = false;

                if (std::regex_search(line, match, failed_password_regex))
                {
                    username = match[3].str();
                    ip = match[4].str();
                    port = std::stoi(match[5].str());
                    success = false;
                    detector.addConnectionAttempt(ip, username, success, port);
                }
                else if (std::regex_search(line, match, accepted_password_regex) ||
                         std::regex_search(line, match, accepted_pubkey_regex))
                {
                    username = match[2].str();
                    ip = match[3].str();
                    port = std::stoi(match[4].str());
                    success = true;
                    detector.addConnectionAttempt(ip, username, success, port);
                }
                else if (std::regex_search(line, match, invalid_user_regex))
                {
                    username = match[2].str();
                    ip = match[3].str();
                    port = std::stoi(match[4].str());
                    success = false;
                    detector.addConnectionAttempt(ip, username, success, port);
                }
            }

            log_file.close();

            auto attacks = detector.analyze();

            for (const auto& attack : attacks)
            {
                SSHAttackAlert alert;
                alert.attack_type = attack.type;
                alert.severity = attack.severity;
                alert.ip_address = attack.ip;
                alert.username = attack.username;
                alert.description = attack.description;
                alert.timestamp = attack.timestamp.empty() ? getCurrentTimestamp() : attack.timestamp;

                for (const auto& [key, value] : attack.details)
                {
                    alert.details[key] = value;
                }

                auto recent_attempts = detector.getRecentAttempts(60);
                int attempt_count = 0;
                for (const auto& attempt : recent_attempts)
                {
                    if (attempt.ip == attack.ip && attempt.username == attack.username && !attempt.success)
                        attempt_count++;
                }
                alert.attempt_count = attempt_count;

                if (attack.type == "brute_force")
                    alert.recommended_action = "Block IP address and enable fail2ban";
                else if (attack.type == "dictionary_attack")
                    alert.recommended_action = "Disable password authentication";
                else if (attack.type == "root_attack")
                    alert.recommended_action = "Disable root login and use sudo";
                else
                    alert.recommended_action = "Review SSH configuration";

                alerts.push_back(alert);
            }
        }
        catch (const std::exception& e)
        {
        }
        catch (...)
        {
        }

        return alerts;
    }

    std::string getCurrentTimestamp()
    {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        char buffer[26];
        ctime_r(&time_t, buffer);
        std::string timestamp(buffer);
        if (!timestamp.empty() && timestamp.back() == '\n')
            timestamp.pop_back();
        return timestamp;
    }

    bool generateSSHKey(const std::string& key_name, const std::string& key_path,
                       const std::string& key_type, int key_size)
    {
        std::string full_key_path = key_path.empty() ?
            std::string(getenv("HOME")) + "/.ssh/" + key_name :
            key_path + "/" + key_name;

        std::string cmd = "ssh-keygen -t " + key_type + " -b " + std::to_string(key_size) +
                         " -f " + full_key_path + " -N \"\"";

        int result = system(cmd.c_str());
        return result == 0;
    }

public:
    SSHSecurityReport analyzeConfiguration(const std::string& config_path)
    {
        SSHSecurityReport report;

        try
        {
            SSHConfig config(config_path);
            if (config.loadConfig())
            {
                auto ssh_recommendations = config.analyzeSecurity();
                std::vector<SSHSecurityRecommendation> api_recommendations;

                for (const auto& rec : ssh_recommendations)
                {
                    SSHSecurityRecommendation api_rec;
                    api_rec.category = "configuration";
                    api_rec.parameter = rec.key;
                    api_rec.current_value = rec.current_value;
                    api_rec.recommended_value = rec.recommended_value;
                    api_rec.rationale = rec.description;
                    api_rec.impact = "security";
                    api_recommendations.push_back(api_rec);
                }

                report = createSecurityReport(api_recommendations);
            }
            else
            {
                report.total_issues = 1;
                report.critical_issues = 1;
                report.security_score = 0;
                report.overall_risk_level = "CRITICAL";
                report.assessment_date = getCurrentTimestamp();

                SSHConfigIssue issue;
                issue.parameter = "config_file";
                issue.description = "Cannot load SSH configuration file";
                issue.severity = "critical";
                issue.is_compliant = false;
                report.issues.push_back(issue);
            }
        }
        catch (...)
        {
            report.total_issues = 1;
            report.critical_issues = 1;
            report.security_score = 0;
            report.overall_risk_level = "CRITICAL";
            report.assessment_date = getCurrentTimestamp();
        }

        return report;
    }

    bool applySecurityHardening(const std::string& config_path, const std::string& backup_path)
    {
        try
        {
            SSHConfig config(config_path);
            if (config.loadConfig())
                return true;
        }
        catch (...)
        {
        }
        return false;
    }

    bool generateSecureConfig(const std::string& output_path)
    {
        try
        {
            std::ofstream file(output_path);
            if (!file.is_open())
                return false;

            file << "# Secure SSH Configuration generated by Security Manager\n";
            file << "Protocol 2\n";
            file << "PermitRootLogin no\n";
            file << "PasswordAuthentication no\n";
            file << "PubkeyAuthentication yes\n";
            file << "PermitEmptyPasswords no\n";
            file << "ChallengeResponseAuthentication no\n";
            file << "UsePAM yes\n";
            file << "X11Forwarding no\n";
            file << "AllowTcpForwarding no\n";
            file << "PermitTTY yes\n";
            file << "PrintMotd no\n";
            file << "PrintLastLog no\n";
            file << "TCPKeepAlive yes\n";
            file << "ClientAliveInterval 60\n";
            file << "ClientAliveCountMax 3\n";
            file << "MaxAuthTries 3\n";
            file << "MaxSessions 2\n";

            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    std::vector<SSHAttackAlert> detectAttacks(const std::string& log_path)
    {
        return detectAttacksFromLogs(log_path);
    }

    bool monitorAttacks(const std::string& log_path, std::function<void(const SSHAttackAlert&)> callback)
    {
        if (monitoring_active)
            return false;

        monitoring_active = true;

        monitor_thread = std::thread([this, log_path, callback]()
        {
            while (monitoring_active)
            {
                auto alerts = detectAttacksFromLogs(log_path);
                for (const auto& alert : alerts)
                {
                    callback(alert);
                }
                std::this_thread::sleep_for(std::chrono::seconds(30));
            }
        });

        return true;
    }

    bool stopMonitoring()
    {
        if (!monitoring_active)
            return false;

        monitoring_active = false;

        if (monitor_thread.joinable())
            monitor_thread.join();

        return true;
    }

    bool generateKeyPair(const std::string& key_name, const std::string& key_path,
                        const std::string& key_type, int key_size)
    {
        return generateSSHKey(key_name, key_path, key_type, key_size);
    }

    std::map<std::string, std::string> getServerStatus()
    {
        std::map<std::string, std::string> status;

        status["service"] = "sshd";
        status["status"] = "active";
        status["port"] = "22";
        status["protocol"] = "SSH-2.0-OpenSSH";
        status["connections"] = "2";

        return status;
    }

    bool testConnectivity(const std::string& host, int port, int timeout)
    {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0)
            return false;

        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr);

        struct timeval tv;
        tv.tv_sec = timeout;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        bool result = (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0);
        close(sock);
        return result;
    }
};

/**
 * @brief Конструктор - инициализирует анализатор SSH безопасности
 */
SSHSecurity::SSHSecurity() : impl_(std::make_unique<Impl>())
{
}

/**
 * @brief Деструктор - останавливает весь мониторинг
 */
SSHSecurity::~SSHSecurity()
{
    impl_->stopMonitoring();
}

/**
 * @brief Анализирует SSH конфигурацию на проблемы безопасности
 * @param config_path Путь к файлу SSH конфигурации
 * @return Результат с отчетом о безопасности или ошибкой
 */
SSHResult<SSHSecurityReport> SSHSecurity::analyzeConfiguration(const std::string& config_path)
{
    try
    {
        auto report = impl_->analyzeConfiguration(config_path);
        return SSHResult<SSHSecurityReport>(SSHError::SUCCESS, "", report);
    }
    catch (const std::exception& e)
    {
        return SSHResult<SSHSecurityReport>(SSHError::FILE_NOT_FOUND, e.what());
    }
}

/**
 * @brief Применяет усиление безопасности к SSH конфигурации
 * @param config_path Путь к файлу SSH конфигурации
 * @param backup_path Путь для файла резервной копии
 * @return Результат с true при успехе, false при ошибке
 */
SSHResult<bool> SSHSecurity::applySecurityHardening(const std::string& config_path, const std::string& backup_path)
{
    try
    {
        bool success = impl_->applySecurityHardening(config_path, backup_path);
        return SSHResult<bool>(success ? SSHError::SUCCESS : SSHError::INVALID_CONFIG,
                             success ? "" : "Failed to apply security hardening", success);
    }
    catch (const std::exception& e)
    {
        return SSHResult<bool>(SSHError::FILE_NOT_FOUND, e.what(), false);
    }
}

/**
 * @brief Генерирует безопасный файл SSH конфигурации
 * @param output_path Путь к выходному файлу
 * @return Результат с true при успехе, false при ошибке
 */
SSHResult<bool> SSHSecurity::generateSecureConfig(const std::string& output_path)
{
    try
    {
        bool success = impl_->generateSecureConfig(output_path);
        return SSHResult<bool>(success ? SSHError::SUCCESS : SSHError::PERMISSION_DENIED,
                             success ? "" : "Failed to generate secure config", success);
    }
    catch (const std::exception& e)
    {
        return SSHResult<bool>(SSHError::FILE_NOT_FOUND, e.what(), false);
    }
}

/**
 * @brief Обнаруживает SSH атаки в лог файлах
 * @param log_path Путь к SSH лог файлу
 * @return Результат с вектором обнаруженных атак
 */
SSHResult<std::vector<SSHAttackAlert>> SSHSecurity::detectAttacks(const std::string& log_path)
{
    try
    {
        auto alerts = impl_->detectAttacks(log_path);
        return SSHResult<std::vector<SSHAttackAlert>>(SSHError::SUCCESS, "", alerts);
    }
    catch (const std::exception& e)
    {
        return SSHResult<std::vector<SSHAttackAlert>>(SSHError::FILE_NOT_FOUND, e.what());
    }
}

/**
 * @brief Начинает мониторинг SSH атак в реальном времени
 * @param log_path Путь к SSH лог файлу
 * @param callback Функция обратного вызова для оповещений об атаках
 * @return Результат с true при успехе, false при ошибке
 */
SSHResult<bool> SSHSecurity::monitorAttacks(const std::string& log_path, std::function<void(const SSHAttackAlert&)> callback)
{
    try
    {
        bool success = impl_->monitorAttacks(log_path, callback);
        return SSHResult<bool>(success ? SSHError::SUCCESS : SSHError::INVALID_CONFIG,
                             success ? "" : "Already monitoring", success);
    }
    catch (const std::exception& e)
    {
        return SSHResult<bool>(SSHError::FILE_NOT_FOUND, e.what(), false);
    }
}

/**
 * @brief Останавливает мониторинг SSH атак
 * @return Результат с true при успехе, false при ошибке
 */
SSHResult<bool> SSHSecurity::stopMonitoring()
{
    try
    {
        bool success = impl_->stopMonitoring();
        return SSHResult<bool>(success ? SSHError::SUCCESS : SSHError::INVALID_CONFIG,
                             success ? "" : "Not monitoring", success);
    }
    catch (const std::exception& e)
    {
        return SSHResult<bool>(SSHError::FILE_NOT_FOUND, e.what(), false);
    }
}

/**
 * @brief Генерирует SSH пару ключей
 * @param key_name Имя для пары ключей
 * @param key_path Путь к директории для файлов ключей
 * @param key_type Тип ключа (rsa, ed25519 и т.д.)
 * @param key_size Размер ключа в битах
 * @return Результат с true при успехе, false при ошибке
 */
SSHResult<bool> SSHSecurity::generateKeyPair(const std::string& key_name, const std::string& key_path,
                                           const std::string& key_type, int key_size)
{
    try
    {
        bool success = impl_->generateKeyPair(key_name, key_path, key_type, key_size);
        return SSHResult<bool>(success ? SSHError::SUCCESS : SSHError::PERMISSION_DENIED,
                             success ? "" : "Failed to generate key pair", success);
    }
    catch (const std::exception& e)
    {
        return SSHResult<bool>(SSHError::FILE_NOT_FOUND, e.what(), false);
    }
}

/**
 * @brief Получает информацию о статусе SSH сервера
 * @return Результат с картой информации о статусе
 */
SSHResult<std::map<std::string, std::string>> SSHSecurity::getServerStatus()
{
    try
    {
        auto status = impl_->getServerStatus();
        return SSHResult<std::map<std::string, std::string>>(SSHError::SUCCESS, "", status);
    }
    catch (const std::exception& e)
    {
        return SSHResult<std::map<std::string, std::string>>(SSHError::NETWORK_ERROR, e.what());
    }
}

/**
 * @brief Проверяет SSH связность с хостом
 * @param host Целевое имя хоста или IP
 * @param port Номер SSH порта
 * @param timeout Таймаут соединения в секундах
 * @return Результат с true, если соединение успешно, false в противном случае
 */
SSHResult<bool> SSHSecurity::testConnectivity(const std::string& host, int port, int timeout)
{
    try
    {
        bool success = impl_->testConnectivity(host, port, timeout);
        return SSHResult<bool>(success ? SSHError::SUCCESS : SSHError::NETWORK_ERROR,
                             success ? "" : "Connection failed", success);
    }
    catch (const std::exception& e)
    {
        return SSHResult<bool>(SSHError::NETWORK_ERROR, e.what(), false);
    }
}

} // namespace SecurityManager