/**
 * @file smlog_api.cpp
 * @brief Реализация для System Log Analyzer API
 * @author Tosa5656
 * @date 4 января, 2026
 */

#include "smlog_api.h"
#include "../../smlog/SystemLogger.h"
#include <fstream>
#include <sstream>
#include <regex>
#include <algorithm>
#include <chrono>
#include <thread>
#include <set>
#include <map>

namespace SecurityManager
{
    /**
    * @brief Реализация для LogAnalyzer
    */
    class LogAnalyzer::Impl
    {
    private:
        /**
        * @brief Активные мониторинги логов
        */
        std::map<std::string, std::thread> monitor_threads;

        /**
        * @brief Статус мониторинга для логов
        */
        std::map<std::string, bool> monitoring_active;

        LogEntry parseSyslogLine(const std::string& line)
        {
            LogEntry entry;
            entry.raw_line = line;

            std::regex syslog_regex(R"((\w+\s+\d+\s+\d+:\d+:\d+)\s+(\w+)\s+([^:\[]+)(?:\[(\d+)\])?:\s*(.*))");
            std::smatch match;

            if (std::regex_match(line, match, syslog_regex))
            {
                entry.timestamp = match[1].str();
                entry.hostname = match[2].str();
                entry.process_name = match[3].str();

                if (match[4].matched)
                    entry.process_id = std::stoi(match[4].str());

                entry.message = match[5].str();

                std::string lower_message = entry.message;
                std::transform(lower_message.begin(), lower_message.end(), lower_message.begin(), ::tolower);

                if (lower_message.find("error") != std::string::npos || lower_message.find("failed") != std::string::npos)
                {
                    entry.level = "ERROR";
                    entry.priority = 3;
                }
                else if (lower_message.find("warning") != std::string::npos || lower_message.find("warn") != std::string::npos)
                {
                    entry.level = "WARNING";
                    entry.priority = 4;
                }
                else if (lower_message.find("debug") != std::string::npos)
                {
                    entry.level = "DEBUG";
                    entry.priority = 7;
                }
                else
                {
                    entry.level = "INFO";
                    entry.priority = 6;
                }

                if (entry.process_name == "sshd")
                {
                    entry.source = "ssh";
                    entry.facility = "auth";
                }
                else if (entry.process_name == "kernel")
                {
                    entry.source = "kernel";
                    entry.facility = "kern";
                }
                else if (entry.process_name.find("systemd") != std::string::npos)
                {
                    entry.source = "systemd";
                    entry.facility = "daemon";
                }
                else
                {
                    entry.source = "system";
                    entry.facility = "syslog";
                }
            }
            else
            {
                entry.level = "INFO";
                entry.source = "unknown";
                entry.message = line;
                entry.facility = "unknown";
                entry.priority = 6;
            }

            return entry;
        }

        bool matchesFilter(const LogEntry& entry, const LogFilter& filter)
        {
            if (!filter.level.empty() && entry.level != filter.level)
                return false;

            if (!filter.source.empty() && entry.source != filter.source)
                return false;

            if (!filter.keyword.empty())
            {
                std::string lower_message = entry.message;
                std::string lower_keyword = filter.keyword;
                std::transform(lower_message.begin(), lower_message.end(), lower_message.begin(), ::tolower);
                std::transform(lower_keyword.begin(), lower_keyword.end(), lower_keyword.begin(), ::tolower);

                if (lower_message.find(lower_keyword) == std::string::npos)
                    return false;
            }

            if (filter.min_priority != -1 && entry.priority < filter.min_priority)
                return false;

            if (filter.max_priority != -1 && entry.priority > filter.max_priority)
                return false;

            return true;
        }

    public:
        std::vector<LogEntry> readLogFile(const std::string& filepath, const LogFilter& filter, size_t max_lines)
        {
            std::vector<LogEntry> entries;

            std::ifstream file(filepath);
            if (!file.is_open())
                throw std::runtime_error("Cannot open log file: " + filepath);

            std::string line;
            size_t line_count = 0;

            while (std::getline(file, line))
            {
                if (line.empty())
                    continue;

                auto entry = parseSyslogLine(line);

                if (!matchesFilter(entry, filter))
                    continue;

                entries.push_back(entry);
                line_count++;

                if (max_lines > 0 && line_count >= max_lines)
                    break;
            }

            return entries;
        }

        std::vector<LogEntry> searchLogFile(const std::string& filepath, const std::string& keyword, const LogFilter& filter)
        {
            LogFilter search_filter = filter;
            search_filter.keyword = keyword;
            return readLogFile(filepath, search_filter, 0);
        }

        LogStats getLogStats(const std::string& filepath)
        {
            LogStats stats = {0};

            try
            {
                auto entries = readLogFile(filepath, {}, 0);
                stats.total_entries = entries.size();

                if (!entries.empty())
                {
                    stats.time_range_start = entries.front().timestamp;
                    stats.time_range_end = entries.back().timestamp;
                }

                std::set<std::string> unique_sources;

                for (const auto& entry : entries)
                {
                    unique_sources.insert(entry.source);

                    if (entry.level == "ERROR")
                        stats.error_count++;
                    else if (entry.level == "WARNING")
                        stats.warning_count++;
                    else if (entry.level == "INFO")
                        stats.info_count++;
                }

                stats.sources.assign(unique_sources.begin(), unique_sources.end());

            }
            catch (...)
            {
                
            }

            return stats;
        }

        bool monitorLogFile(const std::string& filepath, std::function<void(const LogEntry&)> callback)
        {
            if (monitoring_active[filepath])
                return false;

            monitoring_active[filepath] = true;

            monitor_threads[filepath] = std::thread([this, filepath, callback]()
            {
                std::ifstream file(filepath);
                if (!file.is_open())
                    return;

                file.seekg(0, std::ios::end);
                std::streampos last_pos = file.tellg();

                while (monitoring_active[filepath])
                {
                    file.seekg(0, std::ios::end);
                    std::streampos current_pos = file.tellg();

                    if (current_pos > last_pos)
                    {
                        file.seekg(last_pos);
                        std::string line;
                        while (std::getline(file, line))
                        {
                            if (line.empty())
                                continue;

                            auto entry = parseSyslogLine(line);
                            callback(entry);
                        }
                        last_pos = current_pos;
                    }

                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
            });

            return true;
        }

        bool stopMonitoring(const std::string& filepath)
        {
            if (!monitoring_active[filepath])
                return false;

            monitoring_active[filepath] = false;

            if (monitor_threads[filepath].joinable())
                monitor_threads[filepath].join();

            monitor_threads.erase(filepath);
            return true;
        }

        void stopAllMonitoring()
        {
            for (const auto& [filepath, _] : monitoring_active)
                stopMonitoring(filepath);
        }

        std::vector<LogEntry> readJournal(const std::string& unit, const LogFilter& filter, size_t max_lines)
        {
            std::vector<LogEntry> entries;

            try
            {
                SystemLogger logger;
                if (!logger.initialize())
                    return entries;

                if (!logger.hasJournalSupport())
                    return entries;

                auto journal_entries = logger.readJournal(unit, max_lines > 0 ? max_lines : 100);
                std::regex journal_regex(R"((\S+\s+\S+)\s+(\S+)\[(\d+)\]:\s*(.*))");

                for (const auto& journal_line : journal_entries)
                {
                    LogEntry entry;
                    entry.raw_line = journal_line;
                    std::smatch match;

                    if (std::regex_match(journal_line, match, journal_regex))
                    {
                        entry.timestamp = match[1].str();
                        entry.process_name = match[2].str();
                        entry.source = unit.empty() ? "systemd" : unit;

                        try
                        {
                            entry.priority = std::stoi(match[3].str());
                        }
                        catch (...)
                        {
                            entry.priority = 6;
                        }

                        entry.message = match[4].str();

                        if (entry.priority <= 2)
                            entry.level = "CRITICAL";
                        else if (entry.priority <= 3)
                            entry.level = "ERROR";
                        else if (entry.priority <= 4)
                            entry.level = "WARNING";
                        else if (entry.priority <= 6)
                            entry.level = "INFO";
                        else
                            entry.level = "DEBUG";

                        entry.facility = "daemon";
                    }
                    else
                    {
                        entry.timestamp = "unknown";
                        entry.level = "INFO";
                        entry.source = unit.empty() ? "systemd" : unit;
                        entry.message = journal_line;
                        entry.facility = "daemon";
                        entry.priority = 6;
                        entry.process_name = "unknown";
                    }

                    if (matchesFilter(entry, filter))
                        entries.push_back(entry);
                }
            }
            catch (...)
            {
            }

            return entries;
        }

        bool exportLogs(const std::vector<LogEntry>& entries, const std::string& format, const std::string& output_file)
        {
            try
            {
                std::ofstream file(output_file);
                if (!file.is_open())
                    return false;

                if (format == "json")
                {
                    file << "[\n";
                    for (size_t i = 0; i < entries.size(); ++i)
                    {
                        const auto& entry = entries[i];
                        file << "  {\n";
                        file << "    \"timestamp\": \"" << entry.timestamp << "\",\n";
                        file << "    \"level\": \"" << entry.level << "\",\n";
                        file << "    \"source\": \"" << entry.source << "\",\n";
                        file << "    \"message\": \"" << entry.message << "\"\n";
                        file << "  }";
                        if (i < entries.size() - 1)
                            file << ",";
                        file << "\n";
                    }
                    file << "]\n";
                }
                else if (format == "csv")
                {
                    file << "timestamp,level,source,message\n";
                    for (const auto& entry : entries)
                    {
                        file << "\"" << entry.timestamp << "\",";
                        file << "\"" << entry.level << "\",";
                        file << "\"" << entry.source << "\",";
                        file << "\"" << entry.message << "\"\n";
                    }
                }
                else
                {
                    for (const auto& entry : entries)
                    {
                        file << "[" << entry.timestamp << "] " << entry.level << " "
                            << entry.source << ": " << entry.message << "\n";
                    }
                }

                return true;
            }
            catch (...)
            {
                return false;
            }
        }
    };

    /**
    * @brief Конструктор
    */
    LogAnalyzer::LogAnalyzer() : impl_(std::make_unique<Impl>()) {}

    /**
    * @brief Деструктор
    */
    LogAnalyzer::~LogAnalyzer() { impl_->stopAllMonitoring(); }

    /**
    * @brief Прочитать лог
    * @param filepath Путь к логу
    * @param max_entries Количество строк к чтению (0 = все)
    * @param filter Фильтры(опционально)
    * @return std::vector с лог строками
    */
    LogResult<std::vector<LogEntry>> LogAnalyzer::readLogFile(const std::string& filepath, const LogFilter& filter, size_t max_lines)
    {
        try
        {
            auto entries = impl_->readLogFile(filepath, filter, max_lines);
            return LogResult<std::vector<LogEntry>>(LogError::SUCCESS, "", entries);
        }
        catch (const std::exception& e)
         {
            return LogResult<std::vector<LogEntry>>(LogError::FILE_NOT_FOUND, e.what());
        }
    }

    /**
    * @brief Поиск лог строк по критериям
    * @param filepath Путь к логу
    * @param keyword Ключевое слово
    * @param filter Фильтры
    * @return std::vector с лог строками
    */
    LogResult<std::vector<LogEntry>> LogAnalyzer::searchLogFile(const std::string& filepath, const std::string& keyword, const LogFilter& filter)
    {
        try
        {
            auto entries = impl_->searchLogFile(filepath, keyword, filter);
            return LogResult<std::vector<LogEntry>>(LogError::SUCCESS, "", entries);
        }
        catch (const std::exception& e)
        {
            return LogResult<std::vector<LogEntry>>(LogError::FILE_NOT_FOUND, e.what());
        }
    }

    /**
    * @brief Получить статистику лога
    * @param filepath Путь к логу
    * @return Статистика лога
    */
    LogResult<LogStats> LogAnalyzer::getLogStats(const std::string& filepath)
    {
        try
        {
            auto stats = impl_->getLogStats(filepath);
            return LogResult<LogStats>(LogError::SUCCESS, "", stats);
        }
        catch (const std::exception& e)
        {
            return LogResult<LogStats>(LogError::FILE_NOT_FOUND, e.what());
        }
    }

    /**
    * @brief Начать мониторинг лога
    * @param filepath Путь к логу
    * @param callback Вызываемая функция при новой лог строке
    * @return Удачно/Неудачно
    */
    LogResult<bool> LogAnalyzer::monitorLogFile(const std::string& filepath, std::function<void(const LogEntry&)> callback)
    {
        try
        {
            bool success = impl_->monitorLogFile(filepath, callback);
            return LogResult<bool>(success ? LogError::SUCCESS : LogError::INVALID_ARGUMENT, success ? "" : "Already monitoring this file", success);
        }
        catch (const std::exception& e)
        {
            return LogResult<bool>(LogError::FILE_NOT_FOUND, e.what(), false);
        }
    }

    /**
    * @brief Остановить мониторинг лога
    * @param filepath Путь к логу
    * @return Удача/Неудача
    */
    LogResult<bool> LogAnalyzer::stopMonitoring(const std::string& filepath)
    {
        try
        {
            bool success = impl_->stopMonitoring(filepath);
            return LogResult<bool>(success ? LogError::SUCCESS : LogError::INVALID_ARGUMENT, success ? "" : "Not monitoring this file", success);
        }
        catch (const std::exception& e)
        {
            return LogResult<bool>(LogError::FILE_NOT_FOUND, e.what(), false);
        }
    }

    /**
    * @brief Остановить мониторинг всех логов
    * @return Удача/Неудача
    */
    LogResult<bool> LogAnalyzer::stopAllMonitoring()
    {
        try
        {
            impl_->stopAllMonitoring();
            return LogResult<bool>(LogError::SUCCESS, "", true);
        }
        catch (const std::exception& e)
        {
            return LogResult<bool>(LogError::PARSE_ERROR, e.what(), false);
        }
    }

    /**
    * @brief Прочитать systemd лог
    * @param unit systemd юнит (если нужны все то оставить пустым)
    * @param max_entries Максимальное количество лог строк
    * @return std::vector с лог строками
    */
    LogResult<std::vector<LogEntry>> LogAnalyzer::readJournal(const std::string& unit, const LogFilter& filter, size_t max_lines)
    {
        try
        {
            auto entries = impl_->readJournal(unit, filter, max_lines);
            return LogResult<std::vector<LogEntry>>(LogError::SUCCESS, "", entries);
        }
        catch (const std::exception& e)
        {
            return LogResult<std::vector<LogEntry>>(LogError::PARSE_ERROR, e.what());
        }
    }

    /**
    * @brief Экспорт лог строк в файл
    * @param entries Лог строки
    * @param output_file Выходной файл
    * @param format Формат экспорта
    * @return Удача/Неудача
    */
    LogResult<bool> LogAnalyzer::exportLogs(const std::vector<LogEntry>& entries, const std::string& format, const std::string& output_file)
    {
        try
        {
            bool success = impl_->exportLogs(entries, format, output_file);
            return LogResult<bool>(success ? LogError::SUCCESS : LogError::INVALID_ARGUMENT, success ? "" : "Export failed", success);
        }
        catch (const std::exception& e)
        {
            return LogResult<bool>(LogError::FILE_NOT_FOUND, e.what(), false);
        }
    }
}