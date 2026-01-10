/**
 * @file sshAttackDetector.h
 * @brief Обнаружение и мониторинг атак SSH
 * @author Tosa5656
 * @date 4 января, 2026
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <memory>
#include <mutex>
#include <set>
#include "sshConfig.h"

/**
 * @brief Структура, представляющая попытку SSH соединения
 */
struct SSHConnection {
    std::string ip;        /**< IP адрес соединения */
    std::string username;  /**< Имя пользователя, использованное при попытке входа */
    std::string timestamp; /**< Временная метка соединения */
    bool success;          /**< Успешен ли вход */
    int port;              /**< Используемый SSH порт */
    std::string country;   /**< Country of origin (GeoIP) */
};

/**
 * @brief Structure representing a detected SSH attack alert
 */
struct AttackAlert {
    std::string type;       /**< Type of attack detected */
    std::string severity;   /**< Severity level: "critical", "high", "medium", "low" */
    std::string description;/**< Description of the attack */
    std::string ip;         /**< Attacker IP address */
    std::string username;   /**< Target username */
    std::string timestamp;  /**< Time of detection */
    std::map<std::string, std::string> details; /**< Additional attack details */
};

/**
 * @brief SSH attack detection and monitoring class
 */
class SSHAttackDetector {
private:
    struct ConnectionAttempt {
        std::string ip;
        std::string username;
        std::chrono::system_clock::time_point timestamp;
        bool success;
        int port;
    };
    
    std::vector<ConnectionAttempt> recent_attempts_;
    std::mutex attempts_mutex_;
    
    // Конфигурация
    int brute_force_threshold_;  // N попыток
    int brute_force_window_minutes_;  // M минут
    std::set<std::string> common_usernames_;
    std::set<std::string> existing_users_;
    std::set<std::string> normal_countries_;
    std::set<int> standard_ports_ = {22};
    std::map<std::string, std::chrono::system_clock::time_point> last_successful_login_;
    
    // GeoIP
    std::string getCountryFromIP(const std::string& ip);
    static void cleanupGeoIP();
    
    // Анализ времени
    bool isBusinessHours(const std::chrono::system_clock::time_point& time);
    
    // Управление пользователями
    void loadExistingUsers();
    bool userExists(const std::string& username);
    
    // Методы обнаружения
    std::vector<AttackAlert> detectBruteForce(const std::vector<ConnectionAttempt>& attempts);
    std::vector<AttackAlert> detectDictionaryAttack(const std::vector<ConnectionAttempt>& attempts);
    std::vector<AttackAlert> detectGeoIPAnomalies(const std::vector<ConnectionAttempt>& attempts);
    std::vector<AttackAlert> detectTimeAnomalies(const std::vector<ConnectionAttempt>& attempts);
    std::vector<AttackAlert> detectNonExistentUsers(const std::vector<ConnectionAttempt>& attempts);
    std::vector<AttackAlert> detectRootAttempts(const std::vector<ConnectionAttempt>& attempts);
    std::vector<AttackAlert> detectNonStandardPorts(const std::vector<ConnectionAttempt>& attempts);
    std::vector<AttackAlert> detectPostLoginAnomalies(const std::vector<ConnectionAttempt>& attempts);
    
public:
    SSHAttackDetector();
    ~SSHAttackDetector();
    
    bool loadConfig(const std::string& config_path = "");
    void setBruteForceThreshold(int attempts, int window_minutes);
    
    void addConnectionAttempt(const std::string& ip, const std::string& username, 
                             bool success, int port = 22);
    std::vector<AttackAlert> analyze();
    
    void clearOldAttempts(int minutes = 60);
    std::vector<ConnectionAttempt> getRecentAttempts(int minutes = 60);
};
