#include "SystemLogger.h"
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <cstring>
#include <ctime>

// =============== CONSTRUCTORS AND DESTRUCTOR ===============

SystemLogger::SystemLogger() : config_path_("/etc/smlog/smlog.conf"), is_running_(false), monitoring_active_(false), has_journal_support_(false)
{

}

SystemLogger::SystemLogger(const std::string& configPath) : config_path_(configPath), is_running_(false), monitoring_active_(false), has_journal_support_(false)
{

}

SystemLogger::~SystemLogger()
{
    stopMonitoring();
    if (save_config())
        std::cout << "Конфигурация сохранена\n";
}

// =============== PUBLIC METHODS ===============

bool SystemLogger::initialize()
{
    try
    {
        distribution_ = detectDistribution();
        has_journal_support_ = init_journal_support();

        if (!load_config())
        {
            std::cout << "Используется конфигурация по умолчанию\n";
            setup_default_config();
        }

        setup_log_paths();

        is_running_ = true;
        last_error_.clear();

        std::cout << "SystemLogger инициализирован для " << distribution_;
        if (has_journal_support_)
            std::cout << " (с поддержкой journald)";
        std::cout << std::endl;

        return true;

    }
    catch (const std::exception& e)
    {
        last_error_ = "Ошибка инициализации: " + std::string(e.what());
        std::cerr << last_error_ << std::endl;
        return false;
    }
}

void SystemLogger::startMonitoring()
{
    if (monitoring_active_)
    {
        std::cout << "Мониторинг уже запущен\n";
        return;
    }

    monitoring_active_ = true;
    monitor_thread_ = std::thread(&SystemLogger::monitor_loop, this);
    std::cout << "Мониторинг логов запущен\n";
}

void SystemLogger::stopMonitoring()
{
    if (!monitoring_active_)
        return;

    monitoring_active_ = false;
    monitor_cv_.notify_all();

    if (monitor_thread_.joinable())
        monitor_thread_.join();

    std::cout << "Мониторинг логов остановлен\n";
}

// =============== ФАЙЛОВЫЕ ЛОГИ ===============

std::vector<std::string> SystemLogger::readLog(const std::string& logPath, int lines)
{
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    try
    {
        if (!file_exists(logPath))
        {
            last_error_ = "Файл не найден: " + logPath;
            return {};
        }
        
        auto lines_vec = read_lines(logPath);
        
        // Возвращаем последние N строк
        if (lines > 0 && lines_vec.size() > static_cast<size_t>(lines))
            lines_vec.erase(lines_vec.begin(), lines_vec.end() - lines);
        
        return lines_vec;
        
    }
    catch (const std::exception& e)
    {
        last_error_ = "Ошибка чтения лога: " + std::string(e.what());
        return {};
    }
}

std::vector<std::string> SystemLogger::searchLog(const std::string& logPath, const std::string& keyword, const std::string& timeFrom, const std::string& timeTo) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    std::vector<std::string> results;
    
    try
    {
        if (!file_exists(logPath))
        {
            last_error_ = "Файл не найден: " + logPath;
            return {};
        }
        
        auto lines = read_lines(logPath);
        
        for (const auto& line : lines)
        {
            if (line.find(keyword) == std::string::npos)
                continue;
            
            // Проверяем временной диапазон
            if (!timeFrom.empty() || !timeTo.empty())
            {
                auto entry = parse_log_line(line);
                if (!entry)
                    continue;
                
                if (!is_time_in_range(entry->timestamp, timeFrom, timeTo))
                    continue;
            }
            
            results.push_back(line);
        }
        
        return results;
        
    }
    catch (const std::exception& e)
    {
        last_error_ = "Ошибка поиска: " + std::string(e.what());
        return {};
    }
}

std::vector<std::string> SystemLogger::tailLog(const std::string& logPath, int lines)
{
    return readLog(logPath, lines);
}

// =============== SYSTEMD JOURNAL ===============

std::vector<std::string> SystemLogger::readJournal(const std::string& unit, int lines)
{
    if (!has_journal_support_)
    {
        last_error_ = "Systemd journal не поддерживается";
        return {};
    }
    
    std::vector<std::string> args = {"journalctl", "--no-pager", "-o", "cat"};
    
    if (!unit.empty())
    {
        args.push_back("-u");
        args.push_back(unit);
    }
    
    if (lines > 0)
    {
        args.push_back("-n");
        args.push_back(std::to_string(lines));
    }
    
    return execute_journalctl_command(args);
}

std::vector<std::string> SystemLogger::searchJournal(const std::string& keyword, const std::string& unit, const std::string& timeFrom, const std::string& timeTo, const std::string& priority) {
    if (!has_journal_support_)
    {
        last_error_ = "Systemd journal не поддерживается";
        return {};
    }
    
    std::vector<std::string> args = {"journalctl", "--no-pager", "-o", "cat"};
    
    if (!unit.empty())
    {
        args.push_back("-u");
        args.push_back(unit);
    }
    
    if (!timeFrom.empty())
    {
        args.push_back("--since");
        args.push_back(timeFrom);
    }
    
    if (!timeTo.empty())
    {
        args.push_back("--until");
        args.push_back(timeTo);
    }
    
    if (!priority.empty())
    {
        args.push_back("-p");
        args.push_back(priority);
    }
    
    if (!keyword.empty())
    {
        args.push_back("--grep");
        args.push_back(keyword);
    }
    
    return execute_journalctl_command(args);
}

std::vector<std::string> SystemLogger::getJournalUnits()
{
    if (!has_journal_support_)
        return {};
    
    auto lines = execute_journalctl_command({"journalctl", "--no-pager",  "-F", "_SYSTEMD_UNIT"});
    
    std::vector<std::string> units;
    for (const auto& line : lines)
    {
        if (!line.empty() && line != "_SYSTEMD_UNIT")
            units.push_back(line);
    }
    
    std::sort(units.begin(), units.end());
    return units;
}

std::map<std::string, int> SystemLogger::getJournalStats()
{
    std::map<std::string, int> stats;
    
    if (!has_journal_support_)
        return stats;
    
    // Получаем статистику по приоритетам
    std::vector<std::string> priorities = {"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"};
    
    for (const auto& priority : priorities)
    {
        auto result = execute_journalctl_command({"journalctl", "--no-pager", "-p", priority, "-o", "cat"});
        if (!result.empty())
            stats[priority] = result.size();
    }
    
    return stats;
}

bool SystemLogger::clearJournal(const std::string& unit)
{
    if (!has_journal_support_)
    {
        last_error_ = "Systemd journal не поддерживается";
        return false;
    }
    
    std::vector<std::string> args = {"journalctl", "--vacuum-size=200M"};
    
    if (!unit.empty())
    {
        args.push_back("--unit");
        args.push_back(unit);
    }
    
    auto result = execute_journalctl_command(args);
    return !result.empty();
}

// =============== АНАЛИЗ ЛОГОВ ===============

std::map<std::string, int> SystemLogger::countByLevel(const std::string& logPath, const std::string& timeRange)
{
    std::map<std::string, int> counts;
    
    try
    {
        auto lines = readLog(logPath, 0);
        
        for (const auto& line : lines)
        {
            auto level = extract_level_from_line(line);
            if (!level.empty())
                counts[level]++;
        }
        
        return counts;
        
    }
    catch (const std::exception& e)
    {
        last_error_ = "Ошибка анализа уровней: " + std::string(e.what());
        return {};
    }
}

std::map<std::string, int> SystemLogger::findTopIPs(const std::string& logPath, int topN)
{
    std::map<std::string, int> ip_counts;
    
    try
    {
        auto lines = readLog(logPath, 0);
        
        for (const auto& line : lines)
        {
            auto ip = extract_ip_from_line(line);
            if (!ip.empty())
                ip_counts[ip]++;
        }
        
        // Сортируем по количеству
        std::vector<std::pair<std::string, int>> sorted(ip_counts.begin(), ip_counts.end());
        std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
        
        // Берем топ N
        std::map<std::string, int> result;
        int count = 0;
        for (const auto& [ip, cnt] : sorted)
        {
            if (count++ >= topN) break;
            result[ip] = cnt;
        }
        
        return result;
        
    }
    catch (const std::exception& e)
    {
        last_error_ = "Ошибка поиска IP: " + std::string(e.what());
        return {};
    }
}

std::map<std::string, int> SystemLogger::findTopUsers(const std::string& logPath, int topN)
{
    std::map<std::string, int> user_counts;
    
    try
    {
        auto lines = readLog(logPath, 0);
        
        for (const auto& line : lines)
        {
            auto user = extract_user_from_line(line);
            if (!user.empty())
                user_counts[user]++;
        }
        
        // Сортируем по количеству
        std::vector<std::pair<std::string, int>> sorted(user_counts.begin(), user_counts.end());
        std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
        
        // Берем топ N (исключая пустые имена)
        std::map<std::string, int> result;
        int count = 0;
        for (const auto& [user, cnt] : sorted)
        {
            if (user.empty() || user == " ") continue;
            if (count++ >= topN) break;
            result[user] = cnt;
        }
        
        return result;
        
    }
    catch (const std::exception& e)
    {
        last_error_ = "Ошибка поиска пользователей: " + std::string(e.what());
        return {};
    }
}

// =============== МОНИТОРИНГ И ПРАВИЛА ===============

void SystemLogger::addWatchRule(const std::string& ruleName, const std::string& pattern, const std::string& action, bool checkJournal)
{
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    WatchRule rule;
    rule.name = ruleName;
    rule.pattern = pattern;
    rule.action = action;
    rule.created = std::chrono::system_clock::now();
    rule.enabled = true;
    rule.check_journal = checkJournal;
    
    watch_rules_[ruleName] = rule;
    
    std::cout << "Добавлено правило: " << rule.toString() << std::endl;
}

void SystemLogger::removeWatchRule(const std::string& ruleName)
{
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    if (watch_rules_.erase(ruleName) > 0)
        std::cout << "Правило удалено: " << ruleName << std::endl;
}

std::vector<std::string> SystemLogger::listWatchRules() const
{
    std::vector<std::string> rules;
    
    for (const auto& [name, rule] : watch_rules_)
        rules.push_back(rule.toString());
    
    return rules;
}

// =============== УПРАВЛЕНИЕ ЛОГАМИ ===============

bool SystemLogger::rotateLog(const std::string& logPath)
{
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    try
    {
        if (!file_exists(logPath))
        {
            last_error_ = "Файл не найден: " + logPath;
            return false;
        }
        
        // Создаем имя для архива
        auto now = std::chrono::system_clock::now();
        auto timestamp = std::chrono::system_clock::to_time_t(now);
        char time_buf[20];
        std::strftime(time_buf, sizeof(time_buf), "%Y%m%d_%H%M%S", std::localtime(&timestamp));
        
        std::string archivePath = logPath + "." + time_buf;
        
        // Переименовываем текущий лог
        fs::rename(logPath, archivePath);
        
        // Создаем новый пустой файл
        std::ofstream newFile(logPath);
        newFile.close();
        
        // Устанавливаем правильные права
        chmod(logPath.c_str(), 0640);
        
        std::cout << "Лог ротирован: " << logPath << " -> " << archivePath << std::endl;
        return true;
        
    }
    catch (const std::exception& e)
    {
        last_error_ = "Ошибка ротации: " + std::string(e.what());
        return false;
    }
}

bool SystemLogger::compressLog(const std::string& logPath)
{
    if (!file_exists(logPath))
    {
        last_error_ = "Файл не найден: " + logPath;
        return false;
    }
    
    std::string cmd = "gzip " + logPath;
    if (system(cmd.c_str()) != 0)
    {
        last_error_ = "Ошибка сжатия: " + logPath;
        return false;
    }
    
    return true;
}

void SystemLogger::cleanOldLogs(const std::string& logDir, int daysToKeep) {
    try
    {
        if (!fs::exists(logDir))
            return;
        
        auto now = std::chrono::system_clock::now();
        int removed = 0;
        
        for (const auto& entry : fs::directory_iterator(logDir))
        {
            if (!fs::is_regular_file(entry.path()))
                continue;
            
            std::string filename = entry.path().filename().string();
            
            // Проверяем, является ли файл архивным логом
            if (filename.find(".gz") == std::string::npos &&
                filename.find(".bak") == std::string::npos &&
                filename.find(".old") == std::string::npos &&
                filename.find(".log.") == std::string::npos)
                continue;
            
            // Проверяем возраст файла
            auto ftime = fs::last_write_time(entry.path());
            auto file_time = std::chrono::file_clock::to_sys(ftime);
            auto age = std::chrono::duration_cast<std::chrono::hours>(now - file_time);
            
            if (age > std::chrono::hours(24 * daysToKeep))
            {
                fs::remove(entry.path());
                removed++;
            }
        }
        
        if (removed > 0)
            std::cout << "Удалено " << removed << " старых логов в " << logDir << std::endl;
        
    }
    catch (const std::exception& e)
    {
        last_error_ = "Ошибка очистки логов: " + std::string(e.what());
    }
}

// =============== ОТЧЕТЫ ===============

std::string SystemLogger::generateDailyReport()
{
    std::stringstream report;
    
    report << "=== ЕЖЕДНЕВНЫЙ ОТЧЕТ О ЛОГАХ ===\n";
    report << "Время: " << get_current_time() << "\n";
    report << "Дистрибутив: " << distribution_ << "\n";
    report << "Поддержка journald: " << (has_journal_support_ ? "да" : "нет") << "\n\n";
    
    // Статистика по основным логам
    report << "СТАТИСТИКА ЛОГОВ:\n";
    for (const auto& [name, path] : log_paths_)
    {
        if (file_exists(path))
        {
            auto size = fs::file_size(path);
            auto lines = read_lines(path, 10000);
            
            report << "  " << std::left << std::setw(15) << name 
                   << ": " << std::setw(10) << lines.size() << " записей, "
                   << std::setw(10) << size << " байт\n";
        }
    }
    
    // SSH статистика
    std::string auth_log;
    if (log_paths_.count("auth"))
        auth_log = log_paths_["auth"];
    else if (log_paths_.count("secure"))
        auth_log = log_paths_["secure"];
    
    if (!auth_log.empty() && file_exists(auth_log))
    {
        auto failed = searchLog(auth_log, "Failed password");
        auto accepted = searchLog(auth_log, "Accepted");
        
        report << "\nSSH СТАТИСТИКА:\n";
        report << "  Успешных входов: " << accepted.size() << "\n";
        report << "  Неудачных попыток: " << failed.size() << "\n";
        
        if (!failed.empty())
        {
            auto top_ips = findTopIPs(auth_log, 5);
            report << "  Топ IP с ошибками:\n";
            for (const auto& [ip, count] : top_ips)\
            {
                report << "    " << ip << ": " << count << " попыток\n";
            }
        }
    }
    
    return report.str();
}

std::string SystemLogger::generateSecurityReport() {
    std::stringstream report;
    
    report << "=== ОТЧЕТ БЕЗОПАСНОСТИ ===\n";
    report << "Время: " << get_current_time() << "\n\n";
    
    // Проверяем auth.log/secure
    std::string auth_log;
    if (log_paths_.count("auth")) {
        auth_log = log_paths_["auth"];
    } else if (log_paths_.count("secure")) {
        auth_log = log_paths_["secure"];
    }
    
    if (!auth_log.empty() && file_exists(auth_log)) {
        report << "АУТЕНТИФИКАЦИЯ:\n";
        
        // Неудачные попытки
        auto failed = searchLog(auth_log, "Failed password");
        auto invalid = searchLog(auth_log, "Invalid user");
        
        report << "  Неудачных попыток: " << failed.size() << "\n";
        report << "  Несуществующих пользователей: " << invalid.size() << "\n";
        
        // Root логины
        auto root_logins = searchLog(auth_log, "Accepted.*root");
        report << "  Входов под root: " << root_logins.size() << "\n";
        
        // Подозрительные активности
        auto sudo_events = searchLog(auth_log, "sudo:");
        report << "  Sudo команд: " << sudo_events.size() << "\n";
    }
    
    // Проверяем syslog на ошибки
    if (log_paths_.count("syslog") && file_exists(log_paths_["syslog"])) {
        auto syslog_errors = searchLog(log_paths_["syslog"], "error", 
                                      "today 00:00", "");
        report << "\nСИСТЕМНЫЕ ОШИБКИ:\n";
        report << "  Ошибок в syslog: " << syslog_errors.size() << "\n";
    }
    
    // Journal статистика
    if (has_journal_support_) {
        auto stats = getJournalStats();
        report << "\nJOURNAL СТАТИСТИКА:\n";
        for (const auto& [level, count] : stats) {
            if (count > 0) {
                report << "  " << std::left << std::setw(10) << level 
                       << ": " << count << "\n";
            }
        }
    }
    
    report << "\nАКТИВНЫЕ ПРАВИЛА МОНИТОРИНГА: " << watch_rules_.size() << "\n";
    
    return report.str();
}

std::string SystemLogger::generateSystemReport() {
    std::stringstream report;
    
    report << "=== СИСТЕМНЫЙ ОТЧЕТ ===\n";
    report << "Время генерации: " << get_current_time() << "\n";
    report << "Статус мониторинга: " << (monitoring_active_ ? "активен" : "остановлен") << "\n";
    report << "Активных правил: " << watch_rules_.size() << "\n\n";
    
    report << "ДОСТУПНЫЕ ЛОГИ:\n";
    for (const auto& [name, path] : log_paths_) {
        if (file_exists(path)) {
            report << "  " << std::left << std::setw(15) << name 
                   << ": " << path << "\n";
        }
    }
    
    return report.str();
}

std::string SystemLogger::generateJournalReport() {
    std::stringstream report;
    
    if (!has_journal_support_) {
        report << "Systemd journal не поддерживается в этой системе\n";
        return report.str();
    }
    
    report << "=== ОТЧЕТ SYSTEMD JOURNAL ===\n";
    report << "Время: " << get_current_time() << "\n\n";
    
    // Статистика
    auto stats = getJournalStats();
    if (!stats.empty()) {
        report << "СТАТИСТИКА ПО УРОВНЯМ:\n";
        for (const auto& [priority, count] : stats) {
            report << "  " << std::left << std::setw(10) << priority 
                   << ": " << count << " записей\n";
        }
        report << "\n";
    }
    
    // Популярные юниты
    auto units = getJournalUnits();
    report << "ДОСТУПНЫЕ СИСТЕМНЫЕ ЮНИТЫ: " << units.size() << "\n";
    
    // Последние ошибки
    report << "\nПОСЛЕДНИЕ КРИТИЧЕСКИЕ СООБЩЕНИЯ:\n";
    auto critical = searchJournal("", "", "1 hour ago", "", "crit..emerg");
    for (size_t i = 0; i < std::min(critical.size(), size_t(5)); ++i) {
        report << "  " << critical[i] << "\n";
    }
    
    return report.str();
}

std::string SystemLogger::generateFullReport() {
    std::stringstream report;
    
    report << generateDailyReport() << "\n";
    report << generateSecurityReport() << "\n";
    
    if (has_journal_support_) {
        report << generateJournalReport() << "\n";
    }
    
    return report.str();
}

// =============== УТИЛИТЫ ===============

std::string SystemLogger::detectDistribution() {
    // Проверяем /etc/os-release
    if (file_exists("/etc/os-release")) {
        auto lines = read_lines("/etc/os-release");
        
        for (const auto& line : lines) {
            if (line.find("ID=") == 0) {
                std::string id = line.substr(3);
                // Убираем кавычки
                if (id.front() == '"' || id.front() == '\'') {
                    id = id.substr(1, id.length() - 2);
                }
                
                if (id == "ubuntu") return "Ubuntu";
                if (id == "debian") return "Debian";
                if (id == "arch") return "Arch Linux";
                if (id == "fedora") return "Fedora";
                if (id == "centos") return "CentOS";
                if (id == "rhel") return "RHEL";
                if (id.find("astra") != std::string::npos) return "Astra Linux";
                return id;
            }
        }
    }
    
    // Альтернативные проверки
    if (file_exists("/etc/arch-release")) return "Arch Linux";
    if (file_exists("/etc/debian_version")) return "Debian";
    if (file_exists("/etc/fedora-release")) return "Fedora";
    if (file_exists("/etc/redhat-release")) return "RedHat";
    
    return "Unknown";
}

std::vector<std::string> SystemLogger::getAvailableLogs() {
    std::vector<std::string> logs;
    
    for (const auto& [name, path] : log_paths_) {
        if (file_exists(path)) {
            logs.push_back(name + " -> " + path);
        }
    }
    
    // Добавляем journal если доступен
    if (has_journal_support_) {
        logs.push_back("journal -> systemd journal (через journalctl)");
    }
    
    return logs;
}

std::map<std::string, std::string> SystemLogger::getLogStats() {
    std::map<std::string, std::string> stats;
    
    for (const auto& [name, path] : log_paths_) {
        if (file_exists(path)) {
            try {
                auto size = fs::file_size(path);
                auto ftime = fs::last_write_time(path);
                auto file_time = std::chrono::file_clock::to_sys(ftime);
                
                std::stringstream stat;
                stat << "размер: " << size << " байт, ";
                stat << "изменен: " << format_time(file_time);
                
                stats[name] = stat.str();
            } catch (...) {
                stats[name] = "ошибка чтения";
            }
        } else {
            stats[name] = "файл не найден";
        }
    }
    
    if (has_journal_support_) {
        auto journal_stats = getJournalStats();
        int total = 0;
        for (const auto& [_, count] : journal_stats) {
            total += count;
        }
        stats["journal"] = "записей: " + std::to_string(total);
    }
    
    return stats;
}

// =============== СТАТИЧЕСКИЕ МЕТОДЫ ===============

std::vector<std::string> SystemLogger::getSystemLogPaths() {
    std::vector<std::string> paths;
    
    // Проверяем стандартные пути
    std::vector<std::string> common_paths = {
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/kern.log",
        "/var/log/boot.log",
        "/var/log/dmesg",
        "/var/log/cron",
        "/var/log/apt/history.log",
        "/var/log/pacman.log",
        "/var/log/audit/audit.log",
        "/var/log/ufw.log",
        "/var/log/fail2ban.log"
    };
    
    for (const auto& path : common_paths) {
        struct stat buffer;
        if (stat(path.c_str(), &buffer) == 0) {
            paths.push_back(path);
        }
    }
    
    return paths;
}

bool SystemLogger::isLogFile(const std::string& path) {
    // Проверяем расширение
    if (path.length() > 4) {
        std::string ext = path.substr(path.length() - 4);
        if (ext == ".log" || ext == ".LOG") {
            return true;
        }
    }
    
    // Проверяем путь
    if (path.find("/var/log/") == 0) {
        return true;
    }
    
    return false;
}

// =============== ПРИВАТНЫЕ МЕТОДЫ - ФАЙЛЫ ===============

bool SystemLogger::file_exists(const std::string& path) {
    struct stat buffer;
    return (stat(path.c_str(), &buffer) == 0);
}

std::vector<std::string> SystemLogger::read_lines(const std::string& path, int max_lines) {
    std::vector<std::string> lines;
    std::ifstream file(path);
    
    if (!file.is_open()) {
        throw std::runtime_error("Не удалось открыть файл: " + path);
    }
    
    std::string line;
    int count = 0;
    
    while (std::getline(file, line)) {
        if (max_lines > 0 && count >= max_lines) {
            break;
        }
        lines.push_back(line);
        count++;
    }
    
    return lines;
}

bool SystemLogger::write_lines(const std::string& path, const std::vector<std::string>& lines) {
    std::ofstream file(path, std::ios::app);
    
    if (!file.is_open()) {
        return false;
    }
    
    for (const auto& line : lines) {
        file << line << "\n";
    }
    
    return true;
}

std::string SystemLogger::get_file_hash(const std::string& path) {
    // Упрощенная реализация хэша
    if (!file_exists(path)) {
        return "";
    }
    
    try {
        auto content = read_lines(path, 1000);
        std::string combined;
        for (const auto& line : content) {
            combined += line;
        }
        
        std::hash<std::string> hasher;
        return std::to_string(hasher(combined));
    } catch (...) {
        return "";
    }
}

std::string SystemLogger::get_file_size_human(const std::string& path) {
    if (!file_exists(path)) {
        return "0B";
    }
    
    try {
        auto size = fs::file_size(path);
        
        const char* units[] = {"B", "KB", "MB", "GB"};
        int unit_index = 0;
        double size_d = static_cast<double>(size);
        
        while (size_d >= 1024 && unit_index < 3) {
            size_d /= 1024;
            unit_index++;
        }
        
        std::stringstream ss;
        ss << std::fixed << std::setprecision(1) << size_d << units[unit_index];
        return ss.str();
    } catch (...) {
        return "?B";
    }
}

// =============== ПРИВАТНЫЕ МЕТОДЫ - ПАРСИНГ ===============

std::optional<SystemLogger::LogEntry> SystemLogger::parse_log_line(const std::string& line) {
    if (line.empty()) {
        return std::nullopt;
    }
    
    LogEntry entry;
    entry.raw_line = line;
    
    try {
        // Пример формата: "Jan 15 10:30:45 hostname service[pid]: message"
        std::regex syslog_regex(R"(^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+)\[(\d+)\]:\s+(.+)$)");
        std::smatch match;
        
        if (std::regex_search(line, match, syslog_regex) && match.size() == 6) {
            entry.timestamp = match[1].str();
            entry.hostname = match[2].str();
            entry.service = match[3].str();
            entry.pid = match[4].str();
            entry.message = match[5].str();
            return entry;
        }
    } catch (...) {
        // Не удалось распарсить как syslog
    }
    
    // Простой парсинг для других форматов
    if (line.length() > 15) {
        entry.timestamp = line.substr(0, 15);
    }
    
    size_t first_space = line.find(' ', 16);
    if (first_space != std::string::npos) {
        size_t second_space = line.find(' ', first_space + 1);
        if (second_space != std::string::npos) {
            entry.hostname = line.substr(first_space + 1, second_space - first_space - 1);
        }
    }
    
    entry.message = line;
    return entry;
}

std::optional<SystemLogger::JournalEntry> SystemLogger::parse_journal_json(const std::string& json_line) {
    // Упрощенный парсинг JSON
    JournalEntry entry;
    entry.raw_json = json_line;
    
    // Извлекаем основные поля с помощью простого поиска
    auto extract_field = [&](const std::string& field) -> std::string {
        size_t pos = json_line.find("\"" + field + "\":\"");
        if (pos == std::string::npos) return "";
        
        pos += field.length() + 4; // Длина field + ":"
        size_t end = json_line.find("\"", pos);
        if (end == std::string::npos) return "";
        
        return json_line.substr(pos, end - pos);
    };
    
    entry.message = extract_field("MESSAGE");
    entry.unit = extract_field("_SYSTEMD_UNIT");
    entry.priority = extract_field("PRIORITY");
    entry.hostname = extract_field("_HOSTNAME");
    entry.syslog_identifier = extract_field("SYSLOG_IDENTIFIER");
    entry.pid = extract_field("_PID");
    
    // Обрабатываем timestamp
    std::string ts_str = extract_field("__REALTIME_TIMESTAMP");
    if (!ts_str.empty()) {
        try {
            long long microseconds = std::stoll(ts_str);
            auto time_point = std::chrono::system_clock::time_point(
                std::chrono::microseconds(microseconds));
            entry.timestamp = format_time(time_point);
        } catch (...) {
            entry.timestamp = ts_str;
        }
    }
    
    if (entry.message.empty() && entry.unit.empty()) {
        return std::nullopt;
    }
    
    return entry;
}

std::string SystemLogger::extract_ip_from_line(const std::string& line) {
    // Регулярное выражение для IPv4
    std::regex ipv4_regex(R"((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))");
    std::smatch match;
    
    if (std::regex_search(line, match, ipv4_regex)) {
        // Проверяем валидность IP
        std::string ip = match[1].str();
        std::regex valid_ip(R"(^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)");
        if (std::regex_match(ip, valid_ip)) {
            return ip;
        }
    }
    
    return "";
}

std::string SystemLogger::extract_user_from_line(const std::string& line) {
    // Ищем паттерны с пользователями
    std::vector<std::regex> patterns = {
        std::regex(R"(user\s+(\S+))", std::regex::icase),
        std::regex(R"(for\s+(\S+)\s+from)", std::regex::icase),
        std::regex(R"(USER=(\S+))", std::regex::icase),
        std::regex(R"(uid=(\d+)\s*\((\S+)\))"),
        std::regex(R"(Accepted\s+(?:password|publickey)\s+for\s+(\S+))")
    };
    
    std::smatch match;
    for (const auto& pattern : patterns) {
        if (std::regex_search(line, match, pattern)) {
            // Возвращаем первую группу захвата
            for (size_t i = 1; i < match.size(); ++i) {
                if (match[i].matched) {
                    std::string user = match[i].str();
                    // Фильтруем нежелательные значения
                    if (user != "from" && user != "invalid" && !user.empty()) {
                        return user;
                    }
                }
            }
        }
    }
    
    return "";
}

std::string SystemLogger::extract_level_from_line(const std::string& line) {
    std::vector<std::pair<std::string, std::regex>> level_patterns = {
        {"EMERGENCY", std::regex(R"(\bemerg(?:ency)?\b)", std::regex::icase)},
        {"ALERT", std::regex(R"(\balert\b)", std::regex::icase)},
        {"CRITICAL", std::regex(R"(\bcrit(?:ical)?\b)", std::regex::icase)},
        {"ERROR", std::regex(R"(\berr(?:or)?\b)", std::regex::icase)},
        {"WARNING", std::regex(R"(\bwarn(?:ing)?\b)", std::regex::icase)},
        {"NOTICE", std::regex(R"(\bnotice\b)", std::regex::icase)},
        {"INFO", std::regex(R"(\binfo\b)", std::regex::icase)},
        {"DEBUG", std::regex(R"(\bdebug\b)", std::regex::icase)}
    };
    
    std::smatch match;
    for (const auto& [level, pattern] : level_patterns) {
        if (std::regex_search(line, match, pattern)) {
            return level;
        }
    }
    
    // Проверяем по ключевым словам
    if (line.find("Failed") != std::string::npos || 
        line.find("failed") != std::string::npos) {
        return "ERROR";
    }
    
    if (line.find("Accepted") != std::string::npos || 
        line.find("success") != std::string::npos ||
        line.find("Success") != std::string::npos) {
        return "INFO";
    }
    
    return "UNKNOWN";
}

// =============== ПРИВАТНЫЕ МЕТОДЫ - JOURNALD ===============

bool SystemLogger::init_journal_support() {
    // Проверяем наличие journalctl
    if (system("which journalctl > /dev/null 2>&1") != 0) {
        return false;
    }
    
    // Проверяем, что journal существует
    if (!fs::exists("/var/log/journal/") && !fs::exists("/run/log/journal/")) {
        return false;
    }
    
    // Проверяем, что можем читать journal
    auto test_output = execute_journalctl_command({"journalctl", "--no-pager", "-n", "1"});
    return !test_output.empty();
}

std::vector<std::string> SystemLogger::execute_journalctl_command(const std::vector<std::string>& args) {
    std::vector<std::string> result;
    
    // Собираем команду
    std::string cmd;
    for (const auto& arg : args) {
        cmd += arg + " ";
    }
    
    // Исполняем через pipe
    std::array<char, 4096> buffer;
    FILE* pipe = popen(cmd.c_str(), "r");
    
    if (!pipe) {
        last_error_ = "Ошибка выполнения journalctl";
        return {};
    }
    
    // Читаем вывод
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        std::string line(buffer.data());
        // Убираем символ новой строки
        if (!line.empty() && line.back() == '\n') {
            line.pop_back();
        }
        result.push_back(line);
    }
    
    pclose(pipe);
    return result;
}

std::vector<SystemLogger::JournalEntry> SystemLogger::read_journal_entries(int max_entries, 
                                                                          const std::string& cursor) {
    std::vector<JournalEntry> entries;
    
    std::vector<std::string> args = {"journalctl", "--no-pager", "-o", "json"};
    
    if (!cursor.empty()) {
        args.push_back("--cursor");
        args.push_back(cursor);
    }
    
    if (max_entries > 0) {
        args.push_back("-n");
        args.push_back(std::to_string(max_entries));
    }
    
    auto json_lines = execute_journalctl_command(args);
    
    for (const auto& json_line : json_lines) {
        if (auto entry = parse_journal_json(json_line)) {
            entries.push_back(entry.value());
        }
    }
    
    return entries;
}

std::string SystemLogger::get_journal_cursor() {
    if (!has_journal_support_) {
        return "";
    }
    
    // Получаем последний курсор
    auto output = execute_journalctl_command({"journalctl", "--no-pager", "-n", "1", "-o", "json"});
    if (output.empty()) {
        return "";
    }
    
    // Ищем курсор в JSON
    std::string json = output[0];
    size_t pos = json.find("\"__CURSOR\":\"");
    if (pos == std::string::npos) {
        return "";
    }
    
    pos += 12; // Длина "__CURSOR":""
    size_t end = json.find("\"", pos);
    if (end == std::string::npos) {
        return "";
    }
    
    return json.substr(pos, end - pos);
}

// =============== ПРИВАТНЫЕ МЕТОДЫ - УТИЛИТЫ ВРЕМЕНИ ===============

std::string SystemLogger::get_current_time() {
    auto now = std::chrono::system_clock::now();
    return format_time(now);
}

std::string SystemLogger::format_time(const std::chrono::system_clock::time_point& tp) {
    auto time_t = std::chrono::system_clock::to_time_t(tp);
    std::tm tm = *std::localtime(&time_t);
    
    std::stringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

bool SystemLogger::is_time_in_range(const std::string& timestamp, 
                                   const std::string& from, 
                                   const std::string& to) {
    // Упрощенная реализация - сравниваем строки
    if (!from.empty() && timestamp < from) {
        return false;
    }
    
    if (!to.empty() && timestamp > to) {
        return false;
    }
    
    return true;
}

std::string SystemLogger::parse_relative_time(const std::string& rel_time) {
    // Пример: "2 hours ago", "yesterday", "today"
    if (rel_time == "today") {
        auto now = std::chrono::system_clock::now();
        auto today = std::chrono::floor<std::chrono::days>(now);
        return format_time(today);
    }
    
    if (rel_time == "yesterday") {
        auto now = std::chrono::system_clock::now();
        auto yesterday = std::chrono::floor<std::chrono::days>(now) - std::chrono::days(1);
        return format_time(yesterday);
    }
    
    // Для простоты возвращаем как есть
    return rel_time;
}

// =============== ПРИВАТНЫЕ МЕТОДЫ - ОБРАБОТКА ПРАВИЛ ===============

void SystemLogger::check_rules_for_file_line(const std::string& logPath, const std::string& line) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    for (const auto& [name, rule] : watch_rules_) {
        if (!rule.enabled) continue;
        
        if (line.find(rule.pattern) != std::string::npos) {
            execute_rule_action(rule, logPath, line);
        }
    }
}

void SystemLogger::check_rules_for_journal_entry(const JournalEntry& entry) {
    std::lock_guard<std::mutex> lock(log_mutex_);
    
    for (const auto& [name, rule] : watch_rules_) {
        if (!rule.enabled || !rule.check_journal) continue;
        
        if (entry.message.find(rule.pattern) != std::string::npos) {
            std::string source = "journal:" + entry.unit;
            execute_rule_action(rule, source, entry.toString());
        }
    }
}

void SystemLogger::execute_rule_action(const WatchRule& rule, 
                                      const std::string& source, 
                                      const std::string& message) {
    std::cout << "⚡ СРАБОТАЛО ПРАВИЛО: " << rule.name << std::endl;
    std::cout << "   Источник: " << source << std::endl;
    std::cout << "   Сообщение: " << message << std::endl;
    std::cout << "   Действие: " << rule.action << std::endl;
    std::cout << std::string(50, '-') << std::endl;
    
    // Здесь можно добавить реальные действия:
    // - Отправка email
    // - Выполнение скрипта
    // - Блокировка IP
    // - Уведомление в Telegram/Slack
}

// =============== ПРИВАТНЫЕ МЕТОДЫ - МОНИТОРИНГ ===============

void SystemLogger::monitor_loop() {
    // Инициализируем размеры файлов
    last_file_sizes_ = std::map<std::string, size_t>();
    for (const auto& [name, path] : log_paths_) {
        if (file_exists(path)) {
            try {
                last_file_sizes_[path] = fs::file_size(path);
            } catch (...) {
                last_file_sizes_[path] = 0;
            }
        }
    }
    
    // Получаем начальный курсор для journal
    if (has_journal_support_) {
        journal_cursors_["default"] = get_journal_cursor();
    }
    
    while (monitoring_active_) {
        try {
            check_file_log_changes();
            
            if (has_journal_support_) {
                check_journal_changes();
            }
            
            // Ждем 1 секунду между проверками
            std::unique_lock<std::mutex> lock(log_mutex_);
            monitor_cv_.wait_for(lock, std::chrono::seconds(1),
                               [this] { return !monitoring_active_; });
            
        } catch (const std::exception& e) {
            last_error_ = "Ошибка в мониторинге: " + std::string(e.what());
            std::cerr << last_error_ << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }
}

void SystemLogger::check_file_log_changes() {
    for (const auto& [name, path] : log_paths_) {
        if (!file_exists(path)) {
            continue;
        }
        
        try {
            size_t current_size = fs::file_size(path);
            auto it = last_file_sizes_.find(path);
            
            if (it != last_file_sizes_.end()) {
                size_t last_size = it->second;
                
                if (current_size > last_size) {
                    // Читаем новые строки
                    std::ifstream file(path);
                    if (file.is_open()) {
                        file.seekg(last_size);
                        
                        std::string line;
                        while (std::getline(file, line)) {
                            check_rules_for_file_line(path, line);
                        }
                    }
                }
            }
            
            // Обновляем размер
            last_file_sizes_[path] = current_size;
            
        } catch (...) {
            // Игнорируем ошибки доступа к файлу
        }
    }
}

void SystemLogger::check_journal_changes() {
    if (!has_journal_support_) {
        return;
    }
    
    // Читаем новые записи с последнего курсора
    std::string cursor = journal_cursors_["default"];
    auto entries = read_journal_entries(100, cursor);
    
    for (const auto& entry : entries) {
        check_rules_for_journal_entry(entry);
    }
    
    // Обновляем курсор
    if (!entries.empty()) {
        journal_cursors_["default"] = get_journal_cursor();
    }
}

// =============== ПРИВАТНЫЕ МЕТОДЫ - КОНФИГУРАЦИЯ ===============

bool SystemLogger::load_config() {
    if (!file_exists(config_path_)) {
        return false;
    }
    
    try {
        auto lines = read_lines(config_path_);
        
        for (const auto& line : lines) {
            // Простой парсинг конфига формата key=value
            size_t equals_pos = line.find('=');
            if (equals_pos != std::string::npos && line[0] != '#') {
                std::string key = line.substr(0, equals_pos);
                std::string value = line.substr(equals_pos + 1);
                
                // Обрабатываем правила
                if (key.find("rule.") == 0) {
                    // Формат: rule.name.pattern=value или rule.name.action=value
                    // Для простоты пропускаем в этой реализации
                }
            }
        }
        
        return true;
        
    } catch (...) {
        return false;
    }
}

bool SystemLogger::save_config() {
    try {
        std::ofstream config_file(config_path_);
        
        if (!config_file.is_open()) {
            return false;
        }
        
        config_file << "# Конфигурация SystemLogger\n";
        config_file << "# Создано: " << get_current_time() << "\n\n";
        
        config_file << "[Paths]\n";
        for (const auto& [name, path] : log_paths_) {
            config_file << name << "=" << path << "\n";
        }
        
        config_file << "\n[Rules]\n";
        for (const auto& [name, rule] : watch_rules_) {
            config_file << "rule." << name << ".pattern=" << rule.pattern << "\n";
            config_file << "rule." << name << ".action=" << rule.action << "\n";
            config_file << "rule." << name << ".journal=" << (rule.check_journal ? "true" : "false") << "\n";
        }
        
        config_file.close();
        return true;
        
    } catch (...) {
        return false;
    }
}

void SystemLogger::setup_default_config() {
    // Настраиваем пути к логам в зависимости от дистрибутива
    log_paths_.clear();
    
    if (distribution_ == "Ubuntu" || distribution_ == "Debian" || 
        distribution_.find("Astra") != std::string::npos) {
        log_paths_["auth"] = "/var/log/auth.log";
        log_paths_["syslog"] = "/var/log/syslog";
        log_paths_["kern"] = "/var/log/kern.log";
        log_paths_["boot"] = "/var/log/boot.log";
        
        if (distribution_ == "Ubuntu") {
            log_paths_["ufw"] = "/var/log/ufw.log";
            log_paths_["apt"] = "/var/log/apt/history.log";
        }
        
    } else if (distribution_ == "Fedora" || distribution_ == "CentOS" || 
               distribution_ == "RHEL") {
        log_paths_["secure"] = "/var/log/secure";
        log_paths_["messages"] = "/var/log/messages";
        log_paths_["audit"] = "/var/log/audit/audit.log";
        log_paths_["cron"] = "/var/log/cron";
        
    } else if (distribution_ == "Arch Linux") {
        log_paths_["pacman"] = "/var/log/pacman.log";
        if (file_exists("/var/log/auth.log")) {
            log_paths_["auth"] = "/var/log/auth.log";
        }
    }
    
    // Общие логи
    std::vector<std::pair<std::string, std::string>> common_logs = {
        {"dmesg", "/var/log/dmesg"},
        {"wtmp", "/var/log/wtmp"},
        {"btmp", "/var/log/btmp"},
        {"lastlog", "/var/log/lastlog"},
        {"faillog", "/var/log/faillog"}
    };
    
    for (const auto& [name, path] : common_logs) {
        if (file_exists(path)) {
            log_paths_[name] = path;
        }
    }
}

void SystemLogger::setup_log_paths() {
    // Проверяем существование логов и добавляем их
    std::vector<std::pair<std::string, std::string>> possible_logs = {
        {"auth", "/var/log/auth.log"},
        {"secure", "/var/log/secure"},
        {"syslog", "/var/log/syslog"},
        {"messages", "/var/log/messages"},
        {"kern", "/var/log/kern.log"},
        {"boot", "/var/log/boot.log"},
        {"cron", "/var/log/cron"},
        {"apt", "/var/log/apt/history.log"},
        {"pacman", "/var/log/pacman.log"},
        {"audit", "/var/log/audit/audit.log"},
        {"ufw", "/var/log/ufw.log"},
        {"fail2ban", "/var/log/fail2ban.log"},
        {"nginx", "/var/log/nginx/access.log"},
        {"apache", "/var/log/apache2/access.log"},
        {"mysql", "/var/log/mysql/error.log"}
    };
    
    for (const auto& [name, path] : possible_logs) {
        if (file_exists(path)) {
            log_paths_[name] = path;
        }
    }
}

std::string SystemLogger::get_log_path_for_service(const std::string& service) {
    auto it = log_paths_.find(service);
    if (it != log_paths_.end()) {
        return it->second;
    }
    
    // Пробуем найти по стандартным путям
    std::vector<std::string> possible_paths = {
        "/var/log/" + service + ".log",
        "/var/log/" + service + "/access.log",
        "/var/log/" + service + "/error.log",
        "/var/log/" + service
    };
    
    for (const auto& path : possible_paths) {
        if (file_exists(path)) {
            log_paths_[service] = path;
            return path;
        }
    }
    
    return "";
}
