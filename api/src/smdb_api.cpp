/**
 * @file smdb_api.cpp
 * @brief Реализация MITRE ATT&CK Database API
 * @author Tosa5656
 * @date 4 января, 2026
 */

#include "smdb_api.h"
#include <algorithm>
#include <fstream>
#include <sstream>
#include <set>
#include <filesystem>
#include <regex>

namespace fs = std::filesystem;

namespace SecurityManager
{
    /**
    * @brief Реализация для класса AttackDatabase
    */
    class AttackDatabase::Impl
    {
    private:
        /**
        * @brief База атак
        */
        std::map<std::string, AttackInfo> attack_database;

        /**
        * @brief Путь к директории с документацией об атаках
        */
        std::string getDocsPath() {
            if (fs::exists("/usr/share/doc/security-manager/attacks")) {
                return "/usr/share/doc/security-manager/attacks";
            } else {
                return "doc/attacks";
            }
        }

        /**
        * @brief Извлекает заголовок из HTML файла
        */
        std::string getHtmlTitle(const std::string& filepath) {
            std::ifstream file(filepath);
            if (!file.is_open()) {
                return "";
            }

            std::string line;
            std::regex titleRegex("<title>([^<]+)</title>", std::regex_constants::icase);

            while (std::getline(file, line)) {
                std::smatch match;
                if (std::regex_search(line, match, titleRegex)) {
                    return match[1].str();
                }
            }
            return "";
        }

        /**
        * @brief Извлекает содержимое из HTML тега
        */
        std::string getHtmlContent(const std::string& filepath, const std::string& tag) {
            std::ifstream file(filepath);
            if (!file.is_open()) {
                return "";
            }

            std::string content;
            std::string line;
            bool inTag = false;
            std::regex startTagRegex("<" + tag + "[^>]*>", std::regex_constants::icase);
            std::regex endTagRegex("</" + tag + ">", std::regex_constants::icase);

            while (std::getline(file, line)) {
                if (!inTag) {
                    if (std::regex_search(line, startTagRegex)) {
                        inTag = true;
                        std::regex htmlTagRegex("<[^>]+>");
                        line = std::regex_replace(line, htmlTagRegex, "");
                    }
                } else {
                    if (std::regex_search(line, endTagRegex)) {
                        inTag = false;
                        std::regex htmlTagRegex("<[^>]+>");
                        line = std::regex_replace(line, htmlTagRegex, "");
                    } else {
                        std::regex htmlTagRegex("<[^>]+>");
                        line = std::regex_replace(line, htmlTagRegex, "");
                    }
                }

                if (inTag && !line.empty()) {
                    line.erase(line.begin(), std::find_if(line.begin(), line.end(), [](unsigned char ch) {
                        return !std::isspace(ch);
                    }));
                    line.erase(std::find_if(line.rbegin(), line.rend(), [](unsigned char ch) {
                        return !std::isspace(ch);
                    }).base(), line.end());

                    if (!line.empty()) {
                        if (!content.empty()) {
                            content += " ";
                        }
                        content += line;
                    }
                }
            }

            return content;
        }

        /**
        * @brief Инициализирует базу данных атак, парся HTML файлы
        */
        void initializeDatabase()
        {
            std::string docsPath = getDocsPath();

            if (fs::exists(docsPath))
            {
                for (const auto& entry : fs::directory_iterator(docsPath))
                {
                    if (entry.path().extension() == ".html")
                    {
                        std::string filepath = entry.path().string();
                        std::string filename = entry.path().stem().string();

                        AttackInfo info;
                        info.id = filename;
                        info.title = getHtmlTitle(filepath);
                        info.description = getHtmlContent(filepath, "p");
                        info.mitre_url = "https://attack.mitre.org/techniques/" + filename + "/";
                        info.tactic = "Various";
                        info.platform = "Multiple";
                        info.data_sources = "See MITRE ATT&CK for details";

                        std::ifstream file(filepath);
                        if (file.is_open())
                        {
                            std::string line;
                            bool inProtection = false;

                            while (std::getline(file, line))
                            {
                                if (line.find("Security Manager") != std::string::npos ||
                                    line.find("Защита") != std::string::npos)
                                {
                                    inProtection = true;
                                }

                                if (inProtection && line.find("<li>") != std::string::npos)
                                {
                                    std::regex htmlTagRegex("<[^>]+>");
                                    std::string cleanLine = std::regex_replace(line, htmlTagRegex, "");
                                    if (!cleanLine.empty())
                                    {
                                        std::regex toolRegex("(sm\\w+)");
                                        std::smatch toolMatch;
                                        if (std::regex_search(cleanLine, toolMatch, toolRegex))
                                            info.protection_tools.push_back(toolMatch[1].str() + " " + cleanLine);
                                        info.recommendations.push_back(cleanLine);
                                    }
                                }

                                if (inProtection && (line.find("</h2>") != std::string::npos ||
                                                     line.find("</h3>") != std::string::npos))
                                {
                                    inProtection = false;
                                }
                            }
                            file.close();
                        }

                        info.requires_privileges = false;
                        info.impact = "See MITRE ATT&CK for details";
                        info.difficulty = "Medium";

                        attack_database[filename] = info;
                    }
                }
            }

            if (attack_database.empty())
            {
                AttackInfo t1110;
            t1110.id = "T1110";
            t1110.title = "Brute Force";
            t1110.description = "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.";
            t1110.mitre_url = "https://attack.mitre.org/techniques/T1110/";
            t1110.tactic = "Credential Access";
            t1110.platform = "Linux, Windows, macOS";
            t1110.data_sources = "Authentication logs, Process monitoring";
            t1110.tags = {"credential-access", "brute-force", "password"};
            t1110.protection_tools = {"smssh monitor", "smssh parse-log /var/log/auth.log"};
            t1110.recommendations = {
                "Use strong passwords (12+ characters)",
                "Implement account lockout policies",
                "Enable multi-factor authentication",
                "Use password managers",
                "Monitor for unusual login attempts"
            };
            t1110.requires_privileges = false;
            t1110.impact = "Account compromise, data theft";
            t1110.difficulty = "Low";
            attack_database["T1110"] = t1110;

            AttackInfo t1078;
            t1078.id = "T1078";
            t1078.title = "Valid Accounts";
            t1078.description = "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.";
            t1078.mitre_url = "https://attack.mitre.org/techniques/T1078/";
            t1078.tactic = "Initial Access, Persistence, Privilege Escalation, Defense Evasion";
            t1078.platform = "Linux, Windows, macOS, Network";
            t1078.data_sources = "Authentication logs, Process monitoring, API monitoring";
            t1078.tags = {"credential-access", "persistence", "lateral-movement"};
            t1078.protection_tools = {"smpass add-password", "smssh apply /etc/ssh/sshd_config", "smlog search 'Accepted' /var/log/auth.log"};
            t1078.recommendations = {
                "Regular password rotation",
                "Implement least privilege principle",
                "Monitor account usage patterns",
                "Use MFA wherever possible",
                "Regular credential audits"
            };
            t1078.requires_privileges = false;
            t1078.impact = "Full system compromise, data exfiltration";
            t1078.difficulty = "Medium";
            attack_database["T1078"] = t1078;

            AttackInfo t1046;
            t1046.id = "T1046";
            t1046.title = "Network Service Scanning";
            t1046.description = "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices.";
            t1046.mitre_url = "https://attack.mitre.org/techniques/T1046/";
            t1046.tactic = "Discovery";
            t1046.platform = "Linux, Windows, macOS, Network";
            t1046.data_sources = "Network protocol analysis, Packet capture, Netflow/Enclave netflow";
            t1046.tags = {"discovery", "reconnaissance", "network-scanning"};
            t1046.protection_tools = {"smnet scan", "smnet connection", "smnet stats"};
            t1046.recommendations = {
                "Use network segmentation",
                "Implement firewall rules",
                "Disable unnecessary services",
                "Use IDS/IPS systems",
                "Regular network scanning audits"
            };
            t1046.requires_privileges = false;
            t1046.impact = "Information disclosure, attack surface mapping";
            t1046.difficulty = "Low";
            attack_database["T1046"] = t1046;

            AttackInfo t1021;
            t1021.id = "T1021";
            t1021.title = "Remote Services";
            t1021.description = "Adversaries may use Valid Accounts to log into a service that accepts remote connections, such as telnet, SSH, and VNC.";
            t1021.mitre_url = "https://attack.mitre.org/techniques/T1021/";
            t1021.tactic = "Lateral Movement";
            t1021.platform = "Linux, Windows, macOS, Network";
            t1021.data_sources = "Authentication logs, Netflow/Enclave netflow, Process monitoring";
            t1021.tags = {"lateral-movement", "remote-access", "credential-access"};
            t1021.protection_tools = {"smssh monitor", "smssh parse-log /var/log/auth.log", "smnet connection"};
            t1021.recommendations = {
                "Disable remote access where not needed",
                "Use key-based authentication instead of passwords",
                "Implement network segmentation",
                "Monitor remote access logs",
                "Regular access reviews"
            };
            t1021.requires_privileges = false;
            t1021.impact = "Lateral movement, privilege escalation";
            t1021.difficulty = "Medium";
            attack_database["T1021"] = t1021;

            AttackInfo t1059;
            t1059.id = "T1059";
            t1059.title = "Command and Scripting Interpreter";
            t1059.description = "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.";
            t1059.mitre_url = "https://attack.mitre.org/techniques/T1059/";
            t1059.tactic = "Execution";
            t1059.platform = "Linux, Windows, macOS";
            t1059.data_sources = "Process monitoring, File monitoring, Process command-line parameters";
            t1059.tags = {"execution", "command-injection", "scripting"};
            t1059.protection_tools = {"smlog monitor", "smlog search 'exec|bash|python' /var/log/syslog"};
            t1059.recommendations = {
                "Input validation and sanitization",
                "Disable dangerous PHP functions",
                "Use parameterized queries",
                "Implement WAF rules",
                "Monitor command execution logs"
            };
            t1059.requires_privileges = false;
            t1059.impact = "Arbitrary code execution, system compromise";
            t1059.difficulty = "Medium";
            attack_database["T1059"] = t1059;

            AttackInfo t1190;
            t1190.id = "T1190";
            t1190.title = "Exploit Public-Facing Application";
            t1190.description = "Adversaries may attempt to exploit a weakness in an Internet-facing host or system.";
            t1190.mitre_url = "https://attack.mitre.org/techniques/T1190/";
            t1190.tactic = "Initial Access";
            t1190.platform = "Linux, Windows, macOS, Network";
            t1190.data_sources = "Application logs, Web logs, Network protocol analysis";
            t1190.tags = {"initial-access", "exploit", "vulnerability"};
            t1190.protection_tools = {"smnet connection", "smlog search 'error|exploit' /var/log/apache2/access.log"};
            t1190.recommendations = {"Regular security updates", "Web application firewall", "Input validation", "Regular vulnerability scanning"};
            t1190.requires_privileges = false;
            t1190.impact = "System compromise, data breach";
            t1190.difficulty = "High";
            attack_database["T1190"] = t1190;

                std::vector<std::string> attack_ids = {"T1133", "T1095", "T1071", "T1573", "T1003", "T1082", "T1016"};
                for (const auto& id : attack_ids) {
                    AttackInfo info;
                    info.id = id;
                    info.title = "Attack Technique " + id;
                    info.description = "Description for " + id;
                    info.mitre_url = "https://attack.mitre.org/techniques/" + id + "/";
                    info.tactic = "Various";
                    info.platform = "Multiple";
                    info.protection_tools = {"Check Security Manager documentation"};
                    info.recommendations = {"Follow security best practices"};
                    info.requires_privileges = false;
                    info.impact = "Various";
                    info.difficulty = "Medium";
                    attack_database[id] = info;
                }
            }
        }

        std::vector<AttackSearchResult> performSearch(const std::string& keyword, const std::string& tactic_filter, const std::string& platform_filter)
        {
            std::vector<AttackSearchResult> results;
            std::string lower_keyword = keyword;
            std::transform(lower_keyword.begin(), lower_keyword.end(), lower_keyword.begin(), ::tolower);

            for (const auto& [id, attack] : attack_database)
            {
                if (!tactic_filter.empty() && attack.tactic.find(tactic_filter) == std::string::npos)
                    continue;
                if (!platform_filter.empty() && attack.platform.find(platform_filter) == std::string::npos)
                    continue;
                std::vector<std::string> search_fields = { attack.title, attack.description, attack.tactic, attack.platform };

                std::vector<std::string> matched_keywords;
                bool found = false;

                for (const auto& field : search_fields)
                {
                    std::string lower_field = field;
                    std::transform(lower_field.begin(), lower_field.end(), lower_field.begin(), ::tolower);

                    if (lower_field.find(lower_keyword) != std::string::npos)
                    {
                        found = true;
                        matched_keywords.push_back(field);
                    }
                }

                if (found)
                {
                    AttackSearchResult result;
                    result.attack_id = id;
                    result.title = attack.title;
                    result.relevance_score = "High";
                    result.matched_keywords = matched_keywords;
                    results.push_back(result);
                }
            }

            return results;
        }

    public:
        Impl() { initializeDatabase(); }

        std::vector<AttackSearchResult> searchAttacks(const std::string& keyword, const std::string& tactic, const std::string& platform)
        {
            return performSearch(keyword, tactic, platform);
        }

        AttackInfo getAttackInfo(const std::string& attack_id)
        {
            auto it = attack_database.find(attack_id);
            if (it != attack_database.end())
                return it->second;
            return AttackInfo();
        }

        ProtectionGuidance getProtectionGuidance(const std::string& attack_id)
        {
            ProtectionGuidance guidance;
            guidance.attack_id = attack_id;

            auto attack = getAttackInfo(attack_id);
            if (!attack.id.empty())
            {
                guidance.detection_methods = {"Log analysis", "Network monitoring", "System monitoring"};
                guidance.prevention_steps = attack.recommendations;
                guidance.response_actions = {"Isolate affected systems", "Change credentials", "Update systems"};
                guidance.risk_level = "Medium";
                guidance.sm_tools_command = !attack.protection_tools.empty() ? attack.protection_tools[0] : "Check documentation";
            }

            return guidance;
        }

        std::vector<std::string> getAttacksByTactic(const std::string& tactic)
        {
            std::vector<std::string> results;
            for (const auto& [id, attack] : attack_database)
            {
                if (attack.tactic.find(tactic) != std::string::npos)
                    results.push_back(id);
            }
            return results;
        }

        std::vector<std::string> getAttacksByPlatform(const std::string& platform)
        {
            std::vector<std::string> results;
            for (const auto& [id, attack] : attack_database)
            {
                if (attack.platform.find(platform) != std::string::npos)
                    results.push_back(id);
            }
            return results;
        }

        std::vector<std::string> listAllAttacks()
        {
            std::vector<std::string> attacks;
            for (const auto& [id, _] : attack_database)
                attacks.push_back(id);
            std::sort(attacks.begin(), attacks.end());
            return attacks;
        }

        DatabaseStats getDatabaseStats()
        {
            DatabaseStats stats;
            stats.total_attacks = attack_database.size();
            stats.last_updated = "2026-01-04";
            stats.version = "1.0";

            std::set<std::string> tactics;
            std::set<std::string> platforms;

            for (const auto& [_, attack] : attack_database)
            {
                std::stringstream ss(attack.tactic);
                std::string tactic;
                while (std::getline(ss, tactic, ','))
                    tactics.insert(tactic);

                std::stringstream ss2(attack.platform);
                std::string platform;
                while (std::getline(ss2, platform, ','))
                    platforms.insert(platform);
            }

            stats.tactics_count = tactics.size();
            stats.available_tactics.assign(tactics.begin(), tactics.end());
            stats.platforms.assign(platforms.begin(), platforms.end());

            return stats;
        }

        bool exportAttackInfo(const std::string& attack_id, const std::string& format, const std::string& output_file)
        {
            auto attack = getAttackInfo(attack_id);
            if (attack.id.empty())
                return false;

            try
            {
                std::ofstream file(output_file);
                if (!file.is_open())
                    return false;

                if (format == "json")
                {
                    file << "{\n";
                    file << "  \"id\": \"" << attack.id << "\",\n";
                    file << "  \"title\": \"" << attack.title << "\",\n";
                    file << "  \"description\": \"" << attack.description << "\",\n";
                    file << "  \"tactic\": \"" << attack.tactic << "\",\n";
                    file << "  \"platform\": \"" << attack.platform << "\",\n";
                    file << "  \"mitre_url\": \"" << attack.mitre_url << "\"\n";
                    file << "}\n";
                }
                else if (format == "html")
                {
                    file << "<!DOCTYPE html><html><head><title>" << attack.title << "</title></head><body>\n";
                    file << "<h1>" << attack.title << "</h1>\n";
                    file << "<p><strong>ID:</strong> " << attack.id << "</p>\n";
                    file << "<p><strong>Description:</strong> " << attack.description << "</p>\n";
                    file << "<p><strong>MITRE URL:</strong> <a href='" << attack.mitre_url << "'>" << attack.mitre_url << "</a></p>\n";
                    file << "</body></html>\n";
                }
                else // txt
                {
                    file << "Attack ID: " << attack.id << "\n";
                    file << "Title: " << attack.title << "\n";
                    file << "Description: " << attack.description << "\n";
                    file << "Tactic: " << attack.tactic << "\n";
                    file << "Platform: " << attack.platform << "\n";
                    file << "MITRE URL: " << attack.mitre_url << "\n";
                }

                return true;
            }
            catch (...)
            {
                return false;
            }
        }

        std::vector<std::string> getRelatedAttacks(const std::string& attack_id)
        {
            auto attack = getAttackInfo(attack_id);
            if (attack.id.empty())
                return {};

            return getAttacksByTactic(attack.tactic);
        }

        std::vector<std::string> getMitigationStrategies(const std::string& attack_id)
        {
            auto attack = getAttackInfo(attack_id);
            return attack.recommendations;
        }
    };

    /**
    * @brief Конструктор, который инциализирует основную базу
    */
    AttackDatabase::AttackDatabase() : impl_(std::make_unique<Impl>()) {}

    /**
    * @brief Деструктор
    */
    AttackDatabase::~AttackDatabase() = default;

    /**
    * @brief Поиск атак по ключевому слову, тактике, платформе
    * @param keyword Ключевое слово
    * @param tactic Тактика
    * @param platform Платформа
    * @return std::vector с нейденными атаками
    */
    DatabaseResult<std::vector<AttackSearchResult>> AttackDatabase::searchAttacks(const std::string& keyword, const std::string& tactic, const std::string& platform)
    {
        try
        {
            auto results = impl_->searchAttacks(keyword, tactic, platform);
            return DatabaseResult<std::vector<AttackSearchResult>>(DatabaseError::SUCCESS, "", results);
        }
        catch (const std::exception& e)
        {
            return DatabaseResult<std::vector<AttackSearchResult>>(DatabaseError::PARSE_ERROR, e.what());
        }
    }

    /**
    * @brief Получить информацию об атаке
    * @param attack_id ID атаки (например T1110)
    * @return Информация об атаке
    */
    DatabaseResult<AttackInfo> AttackDatabase::getAttackInfo(const std::string& attack_id)
    {
        try
        {
            auto info = impl_->getAttackInfo(attack_id);
            if (info.id.empty())
                return DatabaseResult<AttackInfo>(DatabaseError::ATTACK_NOT_FOUND, "Attack not found");
            return DatabaseResult<AttackInfo>(DatabaseError::SUCCESS, "", info);
        }
        catch (const std::exception& e)
        {
            return DatabaseResult<AttackInfo>(DatabaseError::PARSE_ERROR, e.what());
        }
    }

    /**
    * @brief Получить рекомендации по защите от атаки
    * @param attack_id ID атаки
    * @return Рекомендации по защите от атаки
    */
    DatabaseResult<ProtectionGuidance> AttackDatabase::getProtectionGuidance(const std::string& attack_id)
    {
        try
        {
            auto guidance = impl_->getProtectionGuidance(attack_id);
            return DatabaseResult<ProtectionGuidance>(DatabaseError::SUCCESS, "", guidance);
        }
        catch (const std::exception& e)
        {
            return DatabaseResult<ProtectionGuidance>(DatabaseError::PARSE_ERROR, e.what());
        }
    }

    /**
    * @brief Получить все атаки с заданой тактикой
    * @param tactic Тактики
    * @return std::vector с атаками с заданой тактикой
    */
    DatabaseResult<std::vector<std::string>> AttackDatabase::getAttacksByTactic(const std::string& tactic)
    {
        try
        {
            auto attacks = impl_->getAttacksByTactic(tactic);
            return DatabaseResult<std::vector<std::string>>(DatabaseError::SUCCESS, "", attacks);
        }
        catch (const std::exception& e)
        {
            return DatabaseResult<std::vector<std::string>>(DatabaseError::PARSE_ERROR, e.what());
        }
    }

    /**
    * @brief Получить все атаки с заданой платформой
    * @param platform Платформа
    * @return std::vector с атаками с заданой тактикой
    */
    DatabaseResult<std::vector<std::string>> AttackDatabase::getAttacksByPlatform(const std::string& platform)
    {
        try
        {
            auto attacks = impl_->getAttacksByPlatform(platform);
            return DatabaseResult<std::vector<std::string>>(DatabaseError::SUCCESS, "", attacks);
        }
        catch (const std::exception& e)
        {
            return DatabaseResult<std::vector<std::string>>(DatabaseError::PARSE_ERROR, e.what());
        }
    }

    /**
    * @brief Список всех атак в базе даннных
    * @return std::vector со всеми атаками
    */
    DatabaseResult<std::vector<std::string>> AttackDatabase::listAllAttacks()
    {
        try
        {
            auto attacks = impl_->listAllAttacks();
            return DatabaseResult<std::vector<std::string>>(DatabaseError::SUCCESS, "", attacks);
        }
        catch (const std::exception& e)
        {
            return DatabaseResult<std::vector<std::string>>(DatabaseError::PARSE_ERROR, e.what());
        }
    }

    /**
    * @brief Получить статистику базы данных
    * @return Статистика базы данных
    */
    DatabaseResult<DatabaseStats> AttackDatabase::getDatabaseStats()
    {
        try
        {
            auto stats = impl_->getDatabaseStats();
            return DatabaseResult<DatabaseStats>(DatabaseError::SUCCESS, "", stats);
        }
        catch (const std::exception& e)
        {
            return DatabaseResult<DatabaseStats>(DatabaseError::PARSE_ERROR, e.what());
        }
    }

    /**
    * @brief Экспорт информации об атаке в файл
    * @param attack_id ID атаки
    * @param format Формат экспорта (json, html)
    * @param output_file Выходной формат
    * @return Удача/Неудача
    */
    DatabaseResult<bool> AttackDatabase::exportAttackInfo(const std::string& attack_id, const std::string& format, const std::string& output_file)
    {
        try
        {
            bool success = impl_->exportAttackInfo(attack_id, format, output_file);
            return DatabaseResult<bool>(success ? DatabaseError::SUCCESS : DatabaseError::FILE_NOT_FOUND, success ? "" : "Export failed", success);
        }
        catch (const std::exception& e)
        {
            return DatabaseResult<bool>(DatabaseError::FILE_NOT_FOUND, e.what(), false);
        }
    }

    /**
    * @brief Получить атаки похожие заданой
    * @param attack_id ID атаки
    * @return std::vector с ID похожих атак
    */
    DatabaseResult<std::vector<std::string>> AttackDatabase::getRelatedAttacks(const std::string& attack_id)
    {
        try
        {
            auto attacks = impl_->getRelatedAttacks(attack_id);
            return DatabaseResult<std::vector<std::string>>(DatabaseError::SUCCESS, "", attacks);
        }
        catch (const std::exception& e)
        {
            return DatabaseResult<std::vector<std::string>>(DatabaseError::PARSE_ERROR, e.what());
        }
    }

    /**
    * @brief Получить стратегии по смягчению урона атаки
    * @param attack_id ID атаки
    * @return std::vector со стратегиями смягчения
    */
    DatabaseResult<std::vector<std::string>> AttackDatabase::getMitigationStrategies(const std::string& attack_id)
    {
        try
        {
            auto strategies = impl_->getMitigationStrategies(attack_id);
            return DatabaseResult<std::vector<std::string>>(DatabaseError::SUCCESS, "", strategies);
        }
        catch (const std::exception& e)
        {
            return DatabaseResult<std::vector<std::string>>(DatabaseError::PARSE_ERROR, e.what());
        }
    }
}