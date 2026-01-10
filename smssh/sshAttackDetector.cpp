/**
 * @file sshAttackDetector.cpp
 * @brief Реализация обнаружения SSH атак
 * @author Tosa5656
 * @date 4 января, 2026
 */

#include "sshAttackDetector.h"
#include "../logger/logger.h"
#include <algorithm>
#include <regex>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <map>
#include <set>
#include <vector>
#include <chrono>
#include <thread>
#include <mutex>
#include <maxminddb.h> // Для базы данных MaxMind GeoIP
#include <unistd.h> // Для access()

SSHAttackDetector::SSHAttackDetector() {
    brute_force_threshold_ = 5;
    brute_force_window_minutes_ = 10;
    standard_ports_ = {22};

    loadExistingUsers();
    normal_countries_ = {"US", "GB", "DE", "FR", "CA", "AU", "JP", "NL"}; // список стран, считающихся нормальными для соединений
    common_usernames_ = {
        "admin", "administrator", "root", "user", "guest", "test",
        "mysql", "postgres", "apache", "nginx", "www-data", "ftp",
        "backup", "git", "jenkins", "docker", "ubuntu", "centos",
        "debian", "fedora", "oracle", "system"
    };
}

SSHAttackDetector::~SSHAttackDetector() {
    // Очистить ресурсы базы данных GeoIP
    cleanupGeoIP();
}

// Статическая функция для очистки ресурсов GeoIP
void SSHAttackDetector::cleanupGeoIP() {
    static MMDB_s* mmdb = nullptr;
    static bool initialized = false;

    if (initialized && mmdb) {
        MMDB_close(mmdb);
        free(mmdb);
        mmdb = nullptr;
        initialized = false;
    }
}

bool SSHAttackDetector::loadConfig(const std::string& config_path) {
    // Загрузить конфигурацию из файла
    return true;
}

void SSHAttackDetector::setBruteForceThreshold(int attempts, int window_minutes) {
    brute_force_threshold_ = attempts;
    brute_force_window_minutes_ = window_minutes;
}

void SSHAttackDetector::addConnectionAttempt(const std::string& ip, const std::string& username,
                                           bool success, int port) {
    std::lock_guard<std::mutex> lock(attempts_mutex_);

    ConnectionAttempt attempt;
    attempt.ip = ip;
    attempt.username = username;
    attempt.success = success;
    attempt.port = port;
    attempt.timestamp = std::chrono::system_clock::now();

    recent_attempts_.push_back(attempt);

    // Ограничить размер списка недавних попыток
    if (recent_attempts_.size() > 10000) {
        recent_attempts_.erase(recent_attempts_.begin(),
                             recent_attempts_.begin() + 1000);
    }
}

std::vector<AttackAlert> SSHAttackDetector::analyze() {
    std::lock_guard<std::mutex> lock(attempts_mutex_);

    std::vector<AttackAlert> alerts;

    // Получить недавние попытки за последний час
    auto now = std::chrono::system_clock::now();
    auto one_hour_ago = now - std::chrono::hours(1);

    std::vector<ConnectionAttempt> recent;
    for (const auto& attempt : recent_attempts_) {
        if (attempt.timestamp > one_hour_ago) {
            recent.push_back(attempt);
        }
    }

    if (recent.empty()) {
        return alerts;
    }

    // Проверить на различные типы атак
    auto brute_force_alerts = detectBruteForce(recent);
    alerts.insert(alerts.end(), brute_force_alerts.begin(), brute_force_alerts.end());

    auto dict_alerts = detectDictionaryAttack(recent);
    alerts.insert(alerts.end(), dict_alerts.begin(), dict_alerts.end());

    auto geo_alerts = detectGeoIPAnomalies(recent);
    alerts.insert(alerts.end(), geo_alerts.begin(), geo_alerts.end());

    auto time_alerts = detectTimeAnomalies(recent);
    alerts.insert(alerts.end(), time_alerts.begin(), time_alerts.end());

    auto user_alerts = detectNonExistentUsers(recent);
    alerts.insert(alerts.end(), user_alerts.begin(), user_alerts.end());

    auto root_alerts = detectRootAttempts(recent);
    alerts.insert(alerts.end(), root_alerts.begin(), root_alerts.end());

    auto port_alerts = detectNonStandardPorts(recent);
    alerts.insert(alerts.end(), port_alerts.begin(), port_alerts.end());

    auto post_login_alerts = detectPostLoginAnomalies(recent);
    alerts.insert(alerts.end(), post_login_alerts.begin(), post_login_alerts.end());

    return alerts;
}

void SSHAttackDetector::clearOldAttempts(int minutes) {
    std::lock_guard<std::mutex> lock(attempts_mutex_);

    auto cutoff = std::chrono::system_clock::now() - std::chrono::minutes(minutes);

    recent_attempts_.erase(
        std::remove_if(recent_attempts_.begin(), recent_attempts_.end(),
            [cutoff](const ConnectionAttempt& attempt) {
                return attempt.timestamp < cutoff;
            }),
        recent_attempts_.end()
    );
}

std::vector<SSHAttackDetector::ConnectionAttempt> SSHAttackDetector::getRecentAttempts(int minutes) {
    std::lock_guard<std::mutex> lock(attempts_mutex_);

    auto cutoff = std::chrono::system_clock::now() - std::chrono::minutes(minutes);
    std::vector<ConnectionAttempt> recent;

    for (const auto& attempt : recent_attempts_) {
        if (attempt.timestamp > cutoff) {
            recent.push_back(attempt);
        }
    }

    return recent;
}

void SSHAttackDetector::loadExistingUsers() {
    // Загрузить существующих пользователей из /etc/passwd
    std::ifstream passwd_file("/etc/passwd");
    if (passwd_file.is_open()) {
        std::string line;
        while (std::getline(passwd_file, line)) {
            std::stringstream ss(line);
            std::string username;
            std::getline(ss, username, ':');
            if (!username.empty()) {
                existing_users_.insert(username);
            }
        }
        passwd_file.close();
    }
}

bool SSHAttackDetector::userExists(const std::string& username) {
    return existing_users_.count(username) > 0;
}

std::string SSHAttackDetector::getCountryFromIP(const std::string& ip) {
    // Проверить на локальные адреса
    static std::map<std::string, std::string> local_prefixes = {
        {"192.168.", "LOCAL"},
        {"10.", "LOCAL"},
        {"172.", "LOCAL"},
        {"127.", "LOCAL"},
        {"169.254.", "LOCAL"}  // Link-local
    };

    for (const auto& [prefix, country] : local_prefixes) {
        if (ip.find(prefix) == 0) {
            return country;
        }
    }

    // Проверить на зарезервированные адреса
    if (ip.find("0.") == 0 || ip.find("255.255.255.255") == 0) {
        return "RESERVED";
    }

    // Real GeoIP lookup using MaxMind GeoLite2
    static MMDB_s* mmdb = nullptr;
    static bool initialized = false;

    if (!initialized) {
        // Пути к базе данных GeoLite2 (проверить несколько возможных мест)
        std::vector<std::string> db_paths = {
            "/usr/share/GeoIP/GeoLite2-Country.mmdb",
            "/var/lib/GeoIP/GeoLite2-Country.mmdb",
            "/usr/local/share/GeoIP/GeoLite2-Country.mmdb",
            "./GeoLite2-Country.mmdb"
        };

        for (const auto& path : db_paths) {
            if (access(path.c_str(), F_OK) == 0) {
                mmdb = static_cast<MMDB_s*>(malloc(sizeof(MMDB_s)));
                if (!mmdb) {
                    LogError("Failed to allocate memory for GeoIP database");
                    return "UNKNOWN";
                }

                int status = MMDB_open(path.c_str(), MMDB_MODE_MMAP, mmdb);
                if (status == MMDB_SUCCESS) {
                    LogInfo("Loaded GeoIP database from: " + path);
                    initialized = true;
                    break;
                } else {
                    LogWarning("Failed to open GeoIP database at " + path + ": " +
                              MMDB_strerror(status));
                    free(mmdb);
                    mmdb = nullptr;
                }
            }
        }

        if (!initialized) {
            LogWarning("GeoIP database not found. Install GeoLite2-Country.mmdb or run: "
                      "wget https://git.io/GeoLite2-Country.mmdb -O /usr/share/GeoIP/GeoLite2-Country.mmdb");
            return "UNKNOWN";
        }
    }

    if (!mmdb) {
        return "UNKNOWN";
    }

    int gai_error, mmdb_error;
    MMDB_lookup_result_s result = MMDB_lookup_string(mmdb, ip.c_str(), &gai_error, &mmdb_error);

    if (gai_error != 0) {
        LogWarning("GeoIP lookup failed for IP " + ip + ": " + gai_strerror(gai_error));
        return "UNKNOWN";
    }

    if (mmdb_error != MMDB_SUCCESS) {
        LogWarning("GeoIP lookup error for IP " + ip + ": " + MMDB_strerror(mmdb_error));
        return "UNKNOWN";
    }

    if (!result.found_entry) {
        LogDebug("GeoIP entry not found for IP: " + ip);
        return "UNKNOWN";
    }

    MMDB_entry_data_s entry_data;
    int status = MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL);

    if (status == MMDB_SUCCESS && entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
        std::string country_code(reinterpret_cast<const char*>(entry_data.utf8_string),
                                entry_data.data_size);
        return country_code;
    }

    // Попытка получить registered_country если country не найден
    status = MMDB_get_value(&result.entry, &entry_data, "registered_country", "iso_code", NULL);
    if (status == MMDB_SUCCESS && entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
        std::string country_code(reinterpret_cast<const char*>(entry_data.utf8_string),
                                entry_data.data_size);
        return country_code;
    }

    LogDebug("Could not extract country code for IP: " + ip);
    return "UNKNOWN";
}

bool SSHAttackDetector::isBusinessHours(const std::chrono::system_clock::time_point& time) {
    auto tt = std::chrono::system_clock::to_time_t(time);
    auto tm = *std::localtime(&tt);

    // Рабочие часы: 9:00 - 18:00 в будни
    int hour = tm.tm_hour;
    int day = tm.tm_wday; // 0 = Воскресенье, 6 = Суббота

    return (day >= 1 && day <= 5) && (hour >= 9 && hour <= 17);
}

std::vector<AttackAlert> SSHAttackDetector::detectBruteForce(const std::vector<ConnectionAttempt>& attempts) {
    std::vector<AttackAlert> alerts;

    // Группируем по IP и временному окну
    std::map<std::string, std::vector<ConnectionAttempt>> ip_attempts;

    auto window_start = std::chrono::system_clock::now() -
                       std::chrono::minutes(brute_force_window_minutes_);

    for (const auto& attempt : attempts) {
        if (attempt.timestamp > window_start) {
            ip_attempts[attempt.ip].push_back(attempt);
        }
    }

    for (const auto& [ip, attempts_list] : ip_attempts) {
        size_t failed_count = 0;
        size_t total_attempts = attempts_list.size();

        // Подсчитываем неудачные попытки
        for (const auto& attempt : attempts_list) {
            if (!attempt.success) {
                failed_count++;
            }
        }

        // Расчет метрик brute force атаки
        double failure_rate = total_attempts > 0 ? static_cast<double>(failed_count) / total_attempts : 0.0;

        // Детекция на основе порогов
        bool is_brute_force = false;
        std::string reason;

        if (failed_count >= static_cast<size_t>(brute_force_threshold_)) {
            is_brute_force = true;
            reason = "High number of failed attempts";
        } else if (failure_rate > 0.8 && total_attempts >= 5) {
            is_brute_force = true;
            reason = "High failure rate with multiple attempts";
        } else if (total_attempts >= 10 && failed_count >= 8) {
            is_brute_force = true;
            reason = "Persistent failed attempts";

            // Проверяем распределение по времени (быстрые последовательные попытки)
            if (attempts_list.size() >= 3) {
                auto time_span = std::chrono::duration_cast<std::chrono::seconds>(
                    attempts_list.back().timestamp - attempts_list.front().timestamp).count();

                if (time_span < 60 && failed_count >= attempts_list.size() - 1) { // почти все неудачи
                    reason += " (rapid sequential attempts)";
                }
            }
        }

        if (is_brute_force) {
            AttackAlert alert;
            alert.type = "brute_force";
            alert.severity = "high";
            alert.ip = ip;
            alert.description = "Brute force attack detected: " + reason +
                              ". Failed: " + std::to_string(failed_count) +
                              "/" + std::to_string(total_attempts) +
                              " attempts in " + std::to_string(brute_force_window_minutes_) + " minutes";
            alert.timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            alert.details["failed_attempts"] = std::to_string(failed_count);
            alert.details["total_attempts"] = std::to_string(total_attempts);
            alert.details["failure_rate"] = std::to_string(failure_rate * 100) + "%";
            alert.details["time_window_minutes"] = std::to_string(brute_force_window_minutes_);
            alert.details["reason"] = reason;

            alerts.push_back(alert);
        }
    }

    return alerts;
}

std::vector<AttackAlert> SSHAttackDetector::detectDictionaryAttack(const std::vector<ConnectionAttempt>& attempts) {
    std::vector<AttackAlert> alerts;

    // Группируем по IP
    std::map<std::string, std::vector<ConnectionAttempt>> ip_attempts;

    for (const auto& attempt : attempts) {
        ip_attempts[attempt.ip].push_back(attempt);
    }

    for (const auto& [ip, attempts_list] : ip_attempts) {
        std::set<std::string> common_user_attempts;
        std::set<std::string> all_usernames;
        int failed_common_attempts = 0;
        int total_common_attempts = 0;

        // Анализируем попытки с распространенными логинами
        for (const auto& attempt : attempts_list) {
            all_usernames.insert(attempt.username);

            if (common_usernames_.count(attempt.username)) {
                total_common_attempts++;
                if (!attempt.success) {
                    failed_common_attempts++;
                }
                common_user_attempts.insert(attempt.username);
            }
        }

        // Детекция dictionary атаки
        bool is_dictionary_attack = false;
        std::string reason;

        // Критерий 1: много попыток с распространенными логинами
        if (total_common_attempts >= 5) {
            is_dictionary_attack = true;
            reason = "Multiple attempts with common usernames";
        }
        // Критерий 2: много разных распространенных логинов от одного IP
        else if (common_user_attempts.size() >= 3 && total_common_attempts >= 3) {
            is_dictionary_attack = true;
            reason = "Multiple different common usernames tried";
        }
        // Критерий 3: последовательные неудачные попытки с разными логинами
        else if (failed_common_attempts >= 3 && common_user_attempts.size() >= 2) {
            // Проверяем временную последовательность
            std::vector<ConnectionAttempt> sorted_attempts = attempts_list;
            std::sort(sorted_attempts.begin(), sorted_attempts.end(),
                     [](const ConnectionAttempt& a, const ConnectionAttempt& b) {
                         return a.timestamp < b.timestamp;
                     });

            int sequential_failures = 0;
            for (size_t i = 0; i < sorted_attempts.size() - 1; ++i) {
                if (!sorted_attempts[i].success &&
                    common_usernames_.count(sorted_attempts[i].username) &&
                    std::chrono::duration_cast<std::chrono::minutes>(
                        sorted_attempts[i+1].timestamp - sorted_attempts[i].timestamp).count() < 5) {
                    sequential_failures++;
                }
            }

            if (sequential_failures >= 2) {
                is_dictionary_attack = true;
                reason = "Sequential failed attempts with different common usernames";
            }
        }

        if (is_dictionary_attack) {
            AttackAlert alert;
            alert.type = "dictionary_attack";
            alert.severity = "medium";
            alert.ip = ip;
            alert.description = "Dictionary attack detected: " + reason +
                              ". Common usernames tried: " + std::to_string(common_user_attempts.size()) +
                              ", Total attempts: " + std::to_string(total_common_attempts);
            alert.timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            alert.details["common_usernames_tried"] = std::to_string(common_user_attempts.size());
            alert.details["total_common_attempts"] = std::to_string(total_common_attempts);
            alert.details["failed_common_attempts"] = std::to_string(failed_common_attempts);
            alert.details["reason"] = reason;

            std::string usernames_list;
            for (const auto& username : common_user_attempts) {
                if (!usernames_list.empty()) usernames_list += ", ";
                usernames_list += username;
            }
            alert.details["usernames"] = usernames_list;

            alerts.push_back(alert);
        }
    }

    return alerts;
}

std::vector<AttackAlert> SSHAttackDetector::detectGeoIPAnomalies(const std::vector<ConnectionAttempt>& attempts) {
    std::vector<AttackAlert> alerts;

    // Группируем по IP
    std::map<std::string, std::vector<ConnectionAttempt>> ip_attempts;

    for (const auto& attempt : attempts) {
        ip_attempts[attempt.ip].push_back(attempt);
    }

    // Анализируем паттерны подключений
    for (const auto& [ip, attempts_list] : ip_attempts) {
        std::string country = getCountryFromIP(ip);

        // Пропускаем локальные адреса
        if (country == "LOCAL") {
            continue;
        }

        int successful_connections = 0;
        int failed_connections = 0;
        std::set<int> ports_used;
        std::set<std::string> usernames_tried;

        for (const auto& attempt : attempts_list) {
            if (attempt.success) {
                successful_connections++;
            } else {
                failed_connections++;
            }
            ports_used.insert(attempt.port);
            usernames_tried.insert(attempt.username);
        }

        // Детекция гео-аномалий
        bool is_geo_anomaly = false;
        std::string reason;
        std::string severity = "low";

        // Критерий 1: много подключений из необычной страны
        if (normal_countries_.find(country) == normal_countries_.end()) {
            if (attempts_list.size() >= 3) {
                is_geo_anomaly = true;
                reason = "Multiple connections from unusual geographic location";
                severity = "medium";
            }
        }

        // Критерий 2: подозрительная активность из необычной страны
        if (normal_countries_.find(country) == normal_countries_.end()) {
            // Много неудачных попыток
            if (failed_connections >= 5 && successful_connections == 0) {
                is_geo_anomaly = true;
                reason = "Failed connection attempts from unusual geographic location";
                severity = "medium";
            }

            // Попытки на нестандартные порты
            bool has_non_standard_ports = false;
            for (int port : ports_used) {
                if (standard_ports_.find(port) == standard_ports_.end()) {
                    has_non_standard_ports = true;
                    break;
                }
            }

            if (has_non_standard_ports && attempts_list.size() >= 2) {
                is_geo_anomaly = true;
                reason = "Connection attempts to non-standard ports from unusual geographic location";
                severity = "high";
            }

            // Много разных пользователей
            if (usernames_tried.size() >= 3 && failed_connections >= 3) {
                is_geo_anomaly = true;
                reason = "Multiple usernames tried from unusual geographic location";
                severity = "high";
            }
        }

        // Критерий 3: необычное время подключения из необычной страны
        if (normal_countries_.find(country) == normal_countries_.end() && attempts_list.size() >= 2) {
            bool unusual_time = false;
            for (const auto& attempt : attempts_list) {
                if (!isBusinessHours(attempt.timestamp)) {
                    unusual_time = true;
                    break;
                }
            }

            if (unusual_time && successful_connections > 0) {
                is_geo_anomaly = true;
                reason = "Successful connections outside business hours from unusual geographic location";
                severity = "high";
            }
        }

        if (is_geo_anomaly) {
            AttackAlert alert;
            alert.type = "geo_ip_anomaly";
            alert.severity = severity;
            alert.ip = ip;
            alert.description = "GeoIP anomaly detected: " + reason +
                              " (Country: " + country + ", Connections: " +
                              std::to_string(attempts_list.size()) + ")";
            alert.timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            alert.details["country"] = country;
            alert.details["total_connections"] = std::to_string(attempts_list.size());
            alert.details["successful_connections"] = std::to_string(successful_connections);
            alert.details["failed_connections"] = std::to_string(failed_connections);
            alert.details["usernames_tried"] = std::to_string(usernames_tried.size());
            alert.details["ports_used"] = std::to_string(ports_used.size());
            alert.details["reason"] = reason;

            alerts.push_back(alert);
        }
    }

    return alerts;
}

std::vector<AttackAlert> SSHAttackDetector::detectTimeAnomalies(const std::vector<ConnectionAttempt>& attempts) {
    std::vector<AttackAlert> alerts;

    // Группируем по IP для анализа паттернов
    std::map<std::string, std::vector<ConnectionAttempt>> ip_attempts;

    for (const auto& attempt : attempts) {
        ip_attempts[attempt.ip].push_back(attempt);
    }

    for (const auto& [ip, attempts_list] : ip_attempts) {
        std::vector<ConnectionAttempt> successful_attempts;
        std::vector<ConnectionAttempt> failed_attempts;

        for (const auto& attempt : attempts_list) {
            if (attempt.success) {
                successful_attempts.push_back(attempt);
            } else {
                failed_attempts.push_back(attempt);
            }
        }

        // Детекция временных аномалий
        bool is_time_anomaly = false;
        std::string reason;
        std::string severity = "low";

        // Критерий 1: успешные подключения в нерабочее время
        int off_hours_success = 0;
        for (const auto& attempt : successful_attempts) {
            if (!isBusinessHours(attempt.timestamp)) {
                off_hours_success++;
            }
        }

        if (off_hours_success > 0) {
            // Проверяем, является ли это новым паттерном
            auto last_success = last_successful_login_.find(ip);
            bool is_new_pattern = (last_success == last_successful_login_.end() ||
                                 std::chrono::duration_cast<std::chrono::hours>(
                                     attempts_list.back().timestamp - last_success->second).count() > 24);

            if (is_new_pattern) {
                is_time_anomaly = true;
                reason = "Successful login outside business hours";
                severity = off_hours_success >= 2 ? "medium" : "low";
                last_successful_login_[ip] = attempts_list.back().timestamp;
            }
        }

        // Критерий 2: подозрительная активность ночью (много неудачных попыток)
        int night_attempts = 0;
        int night_failures = 0;
        for (const auto& attempt : attempts_list) {
            if (!isBusinessHours(attempt.timestamp)) {
                night_attempts++;
                if (!attempt.success) {
                    night_failures++;
                }
            }
        }

        if (night_failures >= 3 && night_attempts >= night_failures) {
            is_time_anomaly = true;
            reason = "Multiple failed attempts during off-hours";
            severity = "medium";
        }

        // Критерий 3: необычное время для первого подключения с этого IP
        if (successful_attempts.size() == 1 && !isBusinessHours(successful_attempts[0].timestamp)) {
            // Проверяем, что это первый успешный вход с этого IP
            auto last_success = last_successful_login_.find(ip);
            if (last_success == last_successful_login_.end()) {
                is_time_anomaly = true;
                reason = "First successful connection from this IP occurred outside business hours";
                severity = "low";
                last_successful_login_[ip] = successful_attempts[0].timestamp;
            }
        }

        // Критерий 4: регулярные неудачные попытки в нерабочее время
        if (failed_attempts.size() >= 5) {
            std::map<int, int> hour_attempts; // час -> количество попыток
            for (const auto& attempt : failed_attempts) {
                auto tt = std::chrono::system_clock::to_time_t(attempt.timestamp);
                auto tm = *std::localtime(&tt);
                hour_attempts[tm.tm_hour]++;
            }

            // Ищем часы с аномально высокой активностью
            for (const auto& [hour, count] : hour_attempts) {
                if (count >= 3 && (hour < 6 || hour > 22)) { // ночные часы
                    is_time_anomaly = true;
                    reason = "High activity during unusual hours (hour " + std::to_string(hour) + ")";
                    severity = "medium";
                    break;
                }
            }
        }

        if (is_time_anomaly) {
            AttackAlert alert;
            alert.type = "time_anomaly";
            alert.severity = severity;
            alert.ip = ip;
            alert.description = "Time anomaly detected: " + reason;
            alert.timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            alert.details["successful_connections"] = std::to_string(successful_attempts.size());
            alert.details["failed_connections"] = std::to_string(failed_attempts.size());
            alert.details["off_hours_success"] = std::to_string(off_hours_success);
            alert.details["reason"] = reason;

            if (!successful_attempts.empty()) {
                alert.username = successful_attempts.back().username;
                alert.details["last_username"] = alert.username;
            }

            alerts.push_back(alert);
        }
    }

    return alerts;
}

std::vector<AttackAlert> SSHAttackDetector::detectNonExistentUsers(const std::vector<ConnectionAttempt>& attempts) {
    std::vector<AttackAlert> alerts;

    // Группируем по IP и имени пользователя
    std::map<std::string, std::map<std::string, std::vector<ConnectionAttempt>>> ip_user_attempts;

    for (const auto& attempt : attempts) {
        ip_user_attempts[attempt.ip][attempt.username].push_back(attempt);
    }

    for (const auto& [ip, user_attempts] : ip_user_attempts) {
        for (const auto& [username, attempts_list] : user_attempts) {
            if (!userExists(username)) {
                // Пользователь не существует
                int failed_attempts = 0;
                int total_attempts = attempts_list.size();

                for (const auto& attempt : attempts_list) {
                    if (!attempt.success) {
                        failed_attempts++;
                    }
                }

                // Детекция подозрительной активности с несуществующими пользователями
                bool is_suspicious = false;
                std::string reason;
                std::string severity = "low";

                if (total_attempts >= 3) {
                    is_suspicious = true;
                    reason = "Multiple attempts with non-existent username";
                    severity = "medium";
                } else if (failed_attempts >= 2 && total_attempts >= 2) {
                    is_suspicious = true;
                    reason = "Failed attempts with non-existent username";
                    severity = "low";
                }

                // Проверяем, не является ли это опечаткой в распространенном имени
                if (!is_suspicious && total_attempts >= 2) {
                    for (const auto& common_user : common_usernames_) {
                        // Простая проверка на опечатку (разница в 1-2 символа)
                        size_t common_len = common_user.length();
                        size_t username_len = username.length();
                        size_t min_len = std::min(common_len, username_len);
                        size_t max_len = std::max(common_len, username_len);

                        if (max_len - min_len <= 2) {
                            // Подсчитываем различия
                            int differences = 0;
                            for (size_t i = 0; i < min_len; ++i) {
                                if (common_user[i] != username[i]) {
                                    differences++;
                                }
                            }
                            differences += (max_len - min_len);

                            if (differences <= 2) {
                                is_suspicious = true;
                                reason = "Possible typo in common username '" + common_user + "'";
                                severity = "low";
                                break;
                            }
                        }
                    }
                }

                if (is_suspicious) {
                    AttackAlert alert;
                    alert.type = "nonexistent_user";
                    alert.severity = severity;
                    alert.ip = ip;
                    alert.username = username;
                    alert.description = "Suspicious activity with non-existent user '" + username +
                                      "': " + reason + " (" + std::to_string(total_attempts) + " attempts)";
                    alert.timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
                    alert.details["total_attempts"] = std::to_string(total_attempts);
                    alert.details["failed_attempts"] = std::to_string(failed_attempts);
                    alert.details["reason"] = reason;

                    alerts.push_back(alert);
                }
            }
        }
    }

    return alerts;
}

std::vector<AttackAlert> SSHAttackDetector::detectRootAttempts(const std::vector<ConnectionAttempt>& attempts) {
    std::vector<AttackAlert> alerts;

    // Группируем по IP для комплексного анализа
    std::map<std::string, std::vector<ConnectionAttempt>> ip_attempts;

    for (const auto& attempt : attempts) {
        ip_attempts[attempt.ip].push_back(attempt);
    }

    for (const auto& [ip, attempts_list] : ip_attempts) {
        std::vector<ConnectionAttempt> root_attempts;
        std::set<std::string> other_usernames;

        for (const auto& attempt : attempts_list) {
            if (attempt.username == "root") {
                root_attempts.push_back(attempt);
            } else {
                other_usernames.insert(attempt.username);
            }
        }

        if (root_attempts.empty()) {
            continue;
        }

        int failed_root_attempts = 0;
        int successful_root_attempts = 0;

        for (const auto& attempt : root_attempts) {
            if (attempt.success) {
                successful_root_attempts++;
            } else {
                failed_root_attempts++;
            }
        }

        // Детекция атак на root
        bool is_root_attack = false;
        std::string reason;
        std::string severity = "medium";

        // Критерий 1: много неудачных попыток входа под root
        if (failed_root_attempts >= 3) {
            is_root_attack = true;
            reason = "Multiple failed root login attempts";
            severity = failed_root_attempts >= 5 ? "high" : "medium";
        }

        // Критерий 2: успешный вход под root из подозрительного источника
        if (successful_root_attempts > 0) {
            std::string country = getCountryFromIP(ip);
            if (normal_countries_.find(country) == normal_countries_.end() && country != "LOCAL") {
                is_root_attack = true;
                reason = "Successful root login from unusual geographic location";
                severity = "high";
            }
        }

        // Критерий 3: root + другие пользователи (dictionary attack на root)
        if (!other_usernames.empty() && failed_root_attempts >= 2) {
            is_root_attack = true;
            reason = "Root login attempts combined with other username attempts";
            severity = "high";
        }

        // Критерий 4: root попытки в нерабочее время
        bool off_hours_root = false;
        for (const auto& attempt : root_attempts) {
            if (!isBusinessHours(attempt.timestamp)) {
                off_hours_root = true;
                break;
            }
        }

        if (off_hours_root && failed_root_attempts >= 2) {
            is_root_attack = true;
            reason = "Root login attempts outside business hours";
            severity = "medium";
        }

        // Критерий 5: быстрые последовательные попытки root
        if (root_attempts.size() >= 3) {
            std::vector<ConnectionAttempt> sorted_root = root_attempts;
            std::sort(sorted_root.begin(), sorted_root.end(),
                     [](const ConnectionAttempt& a, const ConnectionAttempt& b) {
                         return a.timestamp < b.timestamp;
                     });

            int rapid_attempts = 0;
            for (size_t i = 1; i < sorted_root.size(); ++i) {
                auto time_diff = std::chrono::duration_cast<std::chrono::seconds>(
                    sorted_root[i].timestamp - sorted_root[i-1].timestamp).count();
                if (time_diff < 30) { // менее 30 секунд между попытками
                    rapid_attempts++;
                }
            }

            if (rapid_attempts >= 2) {
                is_root_attack = true;
                reason = "Rapid sequential root login attempts";
                severity = "high";
            }
        }

        if (is_root_attack) {
            AttackAlert alert;
            alert.type = "root_attack";
            alert.severity = severity;
            alert.ip = ip;
            alert.username = "root";
            alert.description = "Root account attack detected: " + reason +
                              " (Failed: " + std::to_string(failed_root_attempts) +
                              ", Successful: " + std::to_string(successful_root_attempts) + ")";
            alert.timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            alert.details["failed_root_attempts"] = std::to_string(failed_root_attempts);
            alert.details["successful_root_attempts"] = std::to_string(successful_root_attempts);
            alert.details["total_root_attempts"] = std::to_string(root_attempts.size());
            alert.details["other_usernames_tried"] = std::to_string(other_usernames.size());
            alert.details["reason"] = reason;

            alerts.push_back(alert);
        }
    }

    return alerts;
}

std::vector<AttackAlert> SSHAttackDetector::detectNonStandardPorts(const std::vector<ConnectionAttempt>& attempts) {
    std::vector<AttackAlert> alerts;

    // Группируем по IP и порту
    std::map<std::string, std::map<int, std::vector<ConnectionAttempt>>> ip_port_attempts;

    for (const auto& attempt : attempts) {
        ip_port_attempts[attempt.ip][attempt.port].push_back(attempt);
    }

    for (const auto& [ip, port_attempts] : ip_port_attempts) {
        for (const auto& [port, attempts_list] : port_attempts) {
            if (standard_ports_.find(port) == standard_ports_.end()) {
                // Не стандартный порт
                int successful_connections = 0;
                int failed_connections = 0;
                std::set<std::string> usernames_tried;

                for (const auto& attempt : attempts_list) {
                    if (attempt.success) {
                        successful_connections++;
                    } else {
                        failed_connections++;
                    }
                    usernames_tried.insert(attempt.username);
                }

                // Детекция подозрительной активности на нестандартных портах
                bool is_port_scan = false;
                std::string reason;
                std::string severity = "low";

                // Критерий 1: много попыток на нестандартный порт
                if (attempts_list.size() >= 3) {
                    is_port_scan = true;
                    reason = "Multiple connection attempts to non-standard port";
                    severity = "medium";
                }

                // Критерий 2: сканирование разных портов одним IP
                if (port_attempts.size() >= 3) { // этот IP пробовал 3+ разных порта
                    int non_standard_ports = 0;
                    for (const auto& [p, _] : port_attempts) {
                        if (standard_ports_.find(p) == standard_ports_.end()) {
                            non_standard_ports++;
                        }
                    }

                    if (non_standard_ports >= 2) {
                        is_port_scan = true;
                        reason = "Port scanning activity detected";
                        severity = "high";
                    }
                }

                // Критерий 3: успешное подключение к подозрительному порту
                if (successful_connections > 0) {
                    // Успешное подключение к нестандартному порту может быть легитимным
                    // но все равно подозрительно
                    is_port_scan = true;
                    reason = "Successful connection to non-standard port";
                    severity = "medium";
                }

                // Критерий 4: комбинация с другими подозрительными активностями
                std::string country = getCountryFromIP(ip);
                if (normal_countries_.find(country) == normal_countries_.end() && country != "LOCAL") {
                    if (attempts_list.size() >= 2) {
                        is_port_scan = true;
                        reason = "Non-standard port attempts from unusual geographic location";
                        severity = "high";
                    }
                }

                if (is_port_scan) {
                    AttackAlert alert;
                    alert.type = "non_standard_port";
                    alert.severity = severity;
                    alert.ip = ip;
                    alert.description = "Port scanning detected: " + reason +
                                      " (Port: " + std::to_string(port) +
                                      ", Attempts: " + std::to_string(attempts_list.size()) + ")";
                    alert.timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
                    alert.details["port"] = std::to_string(port);
                    alert.details["attempts_on_port"] = std::to_string(attempts_list.size());
                    alert.details["successful_connections"] = std::to_string(successful_connections);
                    alert.details["failed_connections"] = std::to_string(failed_connections);
                    alert.details["usernames_tried"] = std::to_string(usernames_tried.size());
                    alert.details["total_ports_scanned"] = std::to_string(port_attempts.size());
                    alert.details["reason"] = reason;

                    alerts.push_back(alert);
                }
            }
        }
    }

    return alerts;
}

std::vector<AttackAlert> SSHAttackDetector::detectPostLoginAnomalies(const std::vector<ConnectionAttempt>& attempts) {
    std::vector<AttackAlert> alerts;

    // Группируем по IP для анализа поведения после входа
    std::map<std::string, std::vector<ConnectionAttempt>> ip_attempts;

    for (const auto& attempt : attempts) {
        if (attempt.success) { // только успешные входы
            ip_attempts[attempt.ip].push_back(attempt);
        }
    }

    for (const auto& [ip, attempts_list] : ip_attempts) {
        if (attempts_list.size() < 2) {
            continue; // недостаточно данных для анализа
        }

        // Сортируем по времени
        std::vector<ConnectionAttempt> sorted_attempts = attempts_list;
        std::sort(sorted_attempts.begin(), sorted_attempts.end(),
                 [](const ConnectionAttempt& a, const ConnectionAttempt& b) {
                     return a.timestamp < b.timestamp;
                 });

        // Анализируем паттерны поведения после входа
        bool is_post_login_anomaly = false;
        std::string reason;
        std::string severity = "low";

        // Критерий 1: частые переподключения (возможное использование сессии)
        if (sorted_attempts.size() >= 3) {
            int short_sessions = 0;
            for (size_t i = 1; i < sorted_attempts.size(); ++i) {
                auto session_duration = std::chrono::duration_cast<std::chrono::minutes>(
                    sorted_attempts[i].timestamp - sorted_attempts[i-1].timestamp).count();

                if (session_duration < 5) { // сессия короче 5 минут
                    short_sessions++;
                }
            }

            if (short_sessions >= 2) {
                is_post_login_anomaly = true;
                reason = "Frequent short sessions detected";
                severity = "medium";
            }
        }

        // Критерий 2: подключения в необычное время после первого входа
        auto first_login = sorted_attempts.front().timestamp;
        bool has_unusual_timing = false;

        for (size_t i = 1; i < sorted_attempts.size(); ++i) {
            auto time_diff = std::chrono::duration_cast<std::chrono::hours>(
                sorted_attempts[i].timestamp - first_login).count();

            if (time_diff > 24) { // спустя сутки и более
                if (!isBusinessHours(sorted_attempts[i].timestamp)) {
                    has_unusual_timing = true;
                    break;
                }
            }
        }

        if (has_unusual_timing) {
            is_post_login_anomaly = true;
            reason = "Unusual timing pattern after initial login";
            severity = "low";
        }

        // Критерий 3: смена пользователей с одного IP (возможное использование сессии)
        std::set<std::string> usernames;
        for (const auto& attempt : attempts_list) {
            usernames.insert(attempt.username);
        }

        if (usernames.size() >= 3 && attempts_list.size() >= 5) {
            is_post_login_anomaly = true;
            reason = "Multiple different users from same IP after successful logins";
            severity = "high";
        }

        // Критерий 4: подозрительная геолокация с повторяющимися входами
        std::string country = getCountryFromIP(ip);
        if (normal_countries_.find(country) == normal_countries_.end() && country != "LOCAL") {
            if (attempts_list.size() >= 3) {
                is_post_login_anomaly = true;
                reason = "Multiple successful logins from unusual geographic location";
                severity = "medium";
            }
        }

        // Критерий 5: аномальная частота входов
        if (sorted_attempts.size() >= 5) {
            auto total_duration = std::chrono::duration_cast<std::chrono::hours>(
                sorted_attempts.back().timestamp - sorted_attempts.front().timestamp).count();

            if (total_duration > 0) {
                double avg_logins_per_hour = static_cast<double>(sorted_attempts.size()) / total_duration;

                if (avg_logins_per_hour > 2.0) { // более 2 входов в час
                    is_post_login_anomaly = true;
                    reason = "High frequency of logins from same IP";
                    severity = "medium";
                }
            }
        }

        if (is_post_login_anomaly) {
            AttackAlert alert;
            alert.type = "post_login_anomaly";
            alert.severity = severity;
            alert.ip = ip;
            alert.username = sorted_attempts.back().username; // последний пользователь
            alert.description = "Post-login anomaly detected: " + reason +
                              " (" + std::to_string(attempts_list.size()) + " successful logins)";
            alert.timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            alert.details["successful_logins"] = std::to_string(attempts_list.size());
            alert.details["unique_users"] = std::to_string(usernames.size());
            alert.details["country"] = getCountryFromIP(ip);
            alert.details["reason"] = reason;

            // Добавляем временные метрики
            if (!sorted_attempts.empty()) {
                auto first = sorted_attempts.front().timestamp;
                auto last = sorted_attempts.back().timestamp;
                auto duration_hours = std::chrono::duration_cast<std::chrono::hours>(last - first).count();
                alert.details["observation_period_hours"] = std::to_string(duration_hours);

                if (duration_hours > 0) {
                    double avg_per_hour = static_cast<double>(attempts_list.size()) / duration_hours;
                    alert.details["avg_logins_per_hour"] = std::to_string(avg_per_hour);
                }
            }

            alerts.push_back(alert);
        }
    }

    return alerts;
}