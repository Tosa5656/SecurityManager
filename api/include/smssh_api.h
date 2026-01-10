#ifndef SMSSH_API_H
#define SMSSH_API_H

/**
 * @file smssh_api.h
 * @brief SSH Security API - Анализ SSH конфигурации и поиск атак
 * @author Tosa5656
 * @date 4 января, 2026
 */

#include <string>
#include <vector>
#include <memory>
#include <map>
#include <functional>

namespace SecurityManager
{
    /**
    * @brief Коды ошибок
    */
    enum class SSHError
    {
        SUCCESS = 0,
        FILE_NOT_FOUND = 1,
        PERMISSION_DENIED = 2,
        PARSE_ERROR = 3,
        INVALID_CONFIG = 4,
        NETWORK_ERROR = 5
    };

    /**
    * @brief Обвертка результатов SSH операций
    */
    template<typename T>
    struct SSHResult
    {
        SSHError code;
        std::string message;
        T data;

        SSHResult() : code(SSHError::SUCCESS) {}
        SSHResult(SSHError c, const std::string& msg) : code(c), message(msg) {}
        SSHResult(SSHError c, const std::string& msg, const T& d) : code(c), message(msg), data(d) {}

        bool success() const { return code == SSHError::SUCCESS; }
        operator bool() const { return success(); }
    };

    /**
    * @brief Проблема SSH конфигурации
    */
    struct SSHConfigIssue
    {
        std::string parameter;
        std::string current_value;
        std::string recommended_value;
        std::string description;
        std::string severity;  // critical, high, medium, low
        bool is_compliant;
    };

    /**
    * @brief Попытка SSH подключения
    */
    struct SSHConnectionAttempt
    {
        std::string timestamp;
        std::string ip_address;
        std::string username;
        std::string method;     // password, publickey
        bool success;
        int port;
        std::string client_version;
        std::string failure_reason;
    };

    /**
    * @brief Оповещение о SSH атаке
    */
    struct SSHAttackAlert {
        std::string attack_type;    // brute_force, dictionary, geo_anomaly и другие
        std::string severity;       // high, medium, low
        std::string ip_address;
        std::string username;
        std::string description;
        std::string timestamp;
        std::map<std::string, std::string> details;
        int attempt_count;
        std::string recommended_action;
    };

    /**
    * @brief Рекомендации по безопасности
    */
    struct SSHSecurityRecommendation
    {
        std::string category;       // authentication, encryption, network и другие
        std::string parameter;
        std::string current_value;
        std::string recommended_value;
        std::string rationale;
        std::string impact;         // security, compatibility, performance
    };

    /**
    * @brief РОтчет о безопасности SSH
    */
    struct SSHSecurityReport
    {
        int total_issues;
        int critical_issues;
        int high_issues;
        int medium_issues;
        int low_issues;
        double security_score;      // 0-100
        std::vector<SSHConfigIssue> issues;
        std::vector<SSHSecurityRecommendation> recommendations;
        std::string assessment_date;
        std::string overall_risk_level;
    };

    /**
    * @brief Класс менеджера безопасности SSH
    */
    class SSHSecurity
    {
    public:
        SSHSecurity();
        ~SSHSecurity();

        /**
        * @brief Проанализировать sshd конфигурацию
        * @param config_path Путь к sshd_config (по умолчанию: /etc/ssh/sshd_config)
        * @return Отчет об анализе безопасности файла
        */
        SSHResult<SSHSecurityReport> analyzeConfiguration(const std::string& config_path = "/etc/ssh/sshd_config");

        /**
        * @brief Применить рекомендации по усилению безопасности
        * @param config_path Путь к sshd_config
        * @param backup_path Путь к бекапу (опцианально)
        * @return Удача/Неудача
        */
        SSHResult<bool> applySecurityHardening(const std::string& config_path, const std::string& backup_path = "");

        /**
        * @brief Сгенерировать безопасный файл sshd_config
        * @param output_path Выходной файл
        * @return Удача/Неудача
        */
        SSHResult<bool> generateSecureConfig(const std::string& output_path);

        /**
        * @brief Поиск следов атак в лог файле
        * @param log_path Путь к логу SSH (по умолчанию: /var/log/auth.log)
        * @return std::vector с найденными атаками
        */
        SSHResult<std::vector<SSHAttackAlert>> detectAttacks(const std::string& log_path = "/var/log/auth.log");

        /**
        * @brief Поиск SSH атак в реально времени
        * @param log_path Путь к логу
        * @param callback Функция которая будет вызвана при обнаружении атаки
        * @return Удача/Неудача
        */
        SSHResult<bool> monitorAttacks(const std::string& log_path, std::function<void(const SSHAttackAlert&)> callback);

        /**
        * @brief Остановка мониторинга
        * @return Удача/Неудача
        */
        SSHResult<bool> stopMonitoring();

        /**
        * @brief Сгенерировать SSH ключам
        * @param key_name Имя для ключей
        * @param key_path Путь для сохранения ключей (по умолчанию: ~/.ssh)
        * @param key_type Тип ключей (rsa, ed25519, ecdsa)
        * @param key_size Размер ключей в битах (для RSA)
        * @return Удача/Неудача
        */
        SSHResult<bool> generateKeyPair(const std::string& key_name, const std::string& key_path = "", const std::string& key_type = "rsa", int key_size = 4096);

        /**
        * @brief Получить статус SSH сервера
        * @return Информация о сервере
        */
        SSHResult<std::map<std::string, std::string>> getServerStatus();

        /**
        * @brief Проверить SSH подключение
        * @param host Имя сервера
        * @param port SSH порт (по умолчанию: 22)
        * @param timeout Время без ответа
        * @return Удалось/Не удалось
        */
        SSHResult<bool> testConnectivity(const std::string& host, int port = 22, int timeout = 10);

    private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };
}

#endif