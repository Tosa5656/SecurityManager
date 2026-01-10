/**
 * @file sshConfig.cpp
 * @brief Реализация управления конфигурацией SSH
 * @author Tosa5656
 * @date 4 января, 2026
 */

#include "sshConfig.h"
#include <regex>

SSHConfig::SSHConfig() : config_path_("/etc/ssh/sshd_config") {
    loadConfig();
}

SSHConfig::SSHConfig(const std::string& configPath) : config_path_(configPath) {
    loadConfig();
}

bool SSHConfig::loadConfig() {
    settings_.clear();
    original_lines_.clear();
    last_error_.clear();
    
    if (!fs::exists(config_path_)) {
        last_error_ = "Config file not found: " + config_path_;
        return false;
    }
    
    original_lines_ = readLines(config_path_);
    parseConfig();
    return true;
}

void SSHConfig::parseConfig() {
    for (const auto& line : original_lines_) {
        if (isComment(line)) {
            continue;
        }
        
        auto [key, value] = parseLine(line);
        if (!key.empty()) {
            settings_[key] = value;
        }
    }
}

std::pair<std::string, std::string> SSHConfig::parseLine(const std::string& line) {
    std::string trimmed = trim(line);
    if (trimmed.empty() || trimmed[0] == '#') {
        return {"", ""};
    }
    
    size_t space_pos = trimmed.find_first_of(" \t");
    if (space_pos == std::string::npos) {
        return {trimmed, ""};
    }
    
    std::string key = trimmed.substr(0, space_pos);
    std::string value = trim(trimmed.substr(space_pos));
    
    return {key, value};
}

std::string SSHConfig::trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t");
    if (first == std::string::npos) {
        return "";
    }
    size_t last = str.find_last_not_of(" \t");
    return str.substr(first, last - first + 1);
}

bool SSHConfig::isComment(const std::string& line) {
    std::string trimmed = trim(line);
    return trimmed.empty() || trimmed[0] == '#';
}

std::vector<std::string> SSHConfig::readLines(const std::string& path) {
    std::vector<std::string> lines;
    std::ifstream file(path);
    
    if (!file.is_open()) {
        return lines;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        lines.push_back(line);
    }
    
    file.close();
    return lines;
}

bool SSHConfig::writeLines(const std::string& path, const std::vector<std::string>& lines) {
    std::ofstream file(path);
    
    if (!file.is_open()) {
        last_error_ = "Cannot write to file: " + path;
        return false;
    }
    
    for (const auto& line : lines) {
        file << line << "\n";
    }
    
    file.close();
    return true;
}

bool SSHConfig::saveConfig(const std::string& outputPath) {
    std::string path = outputPath.empty() ? config_path_ : outputPath;
    std::vector<std::string> lines;
    
    // Копировать комментарии и пустые строки, обновить настройки
    for (const auto& original_line : original_lines_) {
        if (isComment(original_line) || trim(original_line).empty()) {
            lines.push_back(original_line);
            continue;
        }
        
        auto [key, _] = parseLine(original_line);
        if (key.empty()) {
            lines.push_back(original_line);
            continue;
        }
        
        if (settings_.count(key)) {
            lines.push_back(key + " " + settings_.at(key));
        } else {
            lines.push_back(original_line);
        }
    }
    
    // Добавить новые настройки, которых не было в оригинальном файле
    for (const auto& [key, value] : settings_) {
        bool found = false;
        for (const auto& line : original_lines_) {
            auto [line_key, _] = parseLine(line);
            if (line_key == key) {
                found = true;
                break;
            }
        }
        if (!found) {
            lines.push_back(key + " " + value);
        }
    }
    
    return writeLines(path, lines);
}

std::map<std::string, std::string> SSHConfig::getCurrentSettings() const {
    return settings_;
}

std::string SSHConfig::getSetting(const std::string& key) const {
    auto it = settings_.find(key);
    return (it != settings_.end()) ? it->second : "";
}

bool SSHConfig::hasSetting(const std::string& key) const {
    return settings_.count(key) > 0;
}

bool SSHConfig::setSetting(const std::string& key, const std::string& value) {
    settings_[key] = value;
    return true;
}

void SSHConfig::removeSetting(const std::string& key) {
    settings_.erase(key);
}

std::map<std::string, std::string> SSHConfig::getSecureDefaults() const {
    return {
        {"Protocol", "2"},
        {"PermitRootLogin", "no"},
        {"PasswordAuthentication", "no"},
        {"PubkeyAuthentication", "yes"},
        {"PermitEmptyPasswords", "no"},
        {"ChallengeResponseAuthentication", "no"},
        {"UsePAM", "yes"},
        {"X11Forwarding", "no"},
        {"AllowTcpForwarding", "no"},
        {"ClientAliveInterval", "300"},
        {"ClientAliveCountMax", "2"},
        {"MaxAuthTries", "3"},
        {"MaxSessions", "2"},
        {"LoginGraceTime", "60"},
        {"Banner", "/etc/issue.net"},
        {"PermitTunnel", "no"},
        {"AllowAgentForwarding", "no"}
    };
}

std::vector<SSHSecurityRecommendation> SSHConfig::getRecommendations() const {
    std::vector<SSHSecurityRecommendation> recommendations;
    auto secure_defaults = getSecureDefaults();
    
    // Проверить Protocol
    std::string protocol = getSetting("Protocol");
    if (protocol != "2") {
        SSHSecurityRecommendation rec;
        rec.key = "Protocol";
        rec.current_value = protocol.empty() ? "not set" : protocol;
        rec.recommended_value = "2";
        rec.description = "SSH Protocol 1 is insecure. Use Protocol 2 only.";
        rec.severity = "critical";
        rec.is_set = !protocol.empty();
        recommendations.push_back(rec);
    }
    
    // Проверить PermitRootLogin
    std::string permit_root = getSetting("PermitRootLogin");
    if (permit_root != "no" && permit_root != "prohibit-password") {
        SSHSecurityRecommendation rec;
        rec.key = "PermitRootLogin";
        rec.current_value = permit_root.empty() ? "yes (default)" : permit_root;
        rec.recommended_value = "no";
        rec.description = "Disable direct root login. Use sudo instead.";
        rec.severity = "high";
        rec.is_set = !permit_root.empty();
        recommendations.push_back(rec);
    }
    
    // Проверить PasswordAuthentication
    std::string password_auth = getSetting("PasswordAuthentication");
    if (password_auth != "no") {
        SSHSecurityRecommendation rec;
        rec.key = "PasswordAuthentication";
        rec.current_value = password_auth.empty() ? "yes (default)" : password_auth;
        rec.recommended_value = "no";
        rec.description = "Disable password authentication. Use key-based authentication only.";
        rec.severity = "high";
        rec.is_set = !password_auth.empty();
        recommendations.push_back(rec);
    }
    
    // Проверить PubkeyAuthentication
    std::string pubkey_auth = getSetting("PubkeyAuthentication");
    if (pubkey_auth != "yes") {
        SSHSecurityRecommendation rec;
        rec.key = "PubkeyAuthentication";
        rec.current_value = pubkey_auth.empty() ? "yes (default)" : pubkey_auth;
        rec.recommended_value = "yes";
        rec.description = "Enable public key authentication.";
        rec.severity = "medium";
        rec.is_set = !pubkey_auth.empty();
        recommendations.push_back(rec);
    }
    
    // Проверить MaxAuthTries
    std::string max_auth = getSetting("MaxAuthTries");
    int max_auth_int = 6; // по умолчанию
    if (!max_auth.empty()) {
        try {
            max_auth_int = std::stoi(max_auth);
        } catch (...) {
            max_auth_int = 6;
        }
    }
    if (max_auth_int > 3) {
        SSHSecurityRecommendation rec;
        rec.key = "MaxAuthTries";
        rec.current_value = max_auth.empty() ? "6 (default)" : max_auth;
        rec.recommended_value = "3";
        rec.description = "Limit authentication attempts to prevent brute force attacks.";
        rec.severity = "medium";
        rec.is_set = !max_auth.empty();
        recommendations.push_back(rec);
    }
    
    // Проверить X11Forwarding
    std::string x11 = getSetting("X11Forwarding");
    if (x11 == "yes") {
        SSHSecurityRecommendation rec;
        rec.key = "X11Forwarding";
        rec.current_value = x11;
        rec.recommended_value = "no";
        rec.description = "Disable X11 forwarding unless needed.";
        rec.severity = "low";
        rec.is_set = true;
        recommendations.push_back(rec);
    }
    
    // Проверить PermitEmptyPasswords
    std::string empty_pass = getSetting("PermitEmptyPasswords");
    if (empty_pass != "no" && !empty_pass.empty()) {
        SSHSecurityRecommendation rec;
        rec.key = "PermitEmptyPasswords";
        rec.current_value = empty_pass;
        rec.recommended_value = "no";
        rec.description = "Never allow empty passwords.";
        rec.severity = "critical";
        rec.is_set = true;
        recommendations.push_back(rec);
    }
    
    return recommendations;
}

std::vector<SSHSecurityRecommendation> SSHConfig::analyzeSecurity() {
    return getRecommendations();
}

std::string SSHConfig::generateSecureConfig() {
    std::stringstream ss;
    auto secure_defaults = getSecureDefaults();
    
    ss << "# Secure SSH Configuration\n";
    ss << "# Generated by smssh\n\n";
    
    for (const auto& [key, value] : secure_defaults) {
        ss << key << " " << value << "\n";
    }
    
    return ss.str();
}
