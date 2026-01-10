/**
 * @file smssh_config.h
 * @brief Константы конфигурации безопасности SSH
 * @author Tosa5656
 * @date 4 января, 2026
 */

#pragma once

#include <string>
#include <map>
#include <vector>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <cstdlib>

namespace fs = std::filesystem;

class SSHConfigManager {
private:
    std::string config_path_;
    std::map<std::string, std::string> config_;
    
    std::string getDefaultConfigPath() {
        const char* home = std::getenv("HOME");
        if (home) {
            std::stringstream ss;
            ss << home << "/.sm/smssh.conf";
            return ss.str();
        }
        return "/etc/smssh.conf";
    }
    
    void loadDefaults() {
        config_["ssh_log_path"] = "/var/log/auth.log";
        config_["brute_force_threshold"] = "5";
        config_["brute_force_window_minutes"] = "10";
        config_["enable_geoip"] = "false";
        config_["enable_notifications"] = "true";
        config_["telegram_bot_token"] = "";
        config_["telegram_chat_id"] = "";
        config_["enable_system_notify"] = "true";
        config_["monitor_port"] = "22";
    }
    
public:
    SSHConfigManager() : config_path_(getDefaultConfigPath()) {
        loadDefaults();
        load();
    }
    
    SSHConfigManager(const std::string& path) : config_path_(path) {
        loadDefaults();
        load();
    }
    
    bool load() {
        if (!fs::exists(config_path_)) {
            save();
            return false;
        }
        
        std::ifstream file(config_path_);
        if (!file.is_open()) {
            return false;
        }
        
        std::string line;
        while (std::getline(file, line)) {
            // Пропустить комментарии и пустые строки
            if (line.empty() || line[0] == '#') {
                continue;
            }
            
            size_t pos = line.find('=');
            if (pos != std::string::npos) {
                std::string key = line.substr(0, pos);
                std::string value = line.substr(pos + 1);
                
                // Обрезать пробелы
                key.erase(0, key.find_first_not_of(" \t"));
                key.erase(key.find_last_not_of(" \t") + 1);
                value.erase(0, value.find_first_not_of(" \t"));
                value.erase(value.find_last_not_of(" \t") + 1);
                
                config_[key] = value;
            }
        }
        
        file.close();
        return true;
    }
    
    bool save() {
        // Создать директорию если она не существует
        fs::path config_dir = fs::path(config_path_).parent_path();
        if (!config_dir.empty() && !fs::exists(config_dir)) {
            fs::create_directories(config_dir);
        }
        
        std::ofstream file(config_path_);
        if (!file.is_open()) {
            return false;
        }
        
        file << "# SSH Security Manager Configuration\n";
        file << "# Generated automatically\n\n";
        
        for (const auto& [key, value] : config_) {
            file << key << " = " << value << "\n";
        }
        
        file.close();
        return true;
    }
    
    std::string get(const std::string& key) const {
        auto it = config_.find(key);
        return (it != config_.end()) ? it->second : "";
    }
    
    void set(const std::string& key, const std::string& value) {
        config_[key] = value;
    }
    
    int getInt(const std::string& key, int default_value = 0) const {
        std::string value = get(key);
        if (value.empty()) {
            return default_value;
        }
        try {
            return std::stoi(value);
        } catch (...) {
            return default_value;
        }
    }
    
    bool getBool(const std::string& key, bool default_value = false) const {
        std::string value = get(key);
        if (value.empty()) {
            return default_value;
        }
        return (value == "true" || value == "1" || value == "yes");
    }
    
    std::string getConfigPath() const {
        return config_path_;
    }
};
