#ifndef SMLOG_API_H
#define SMLOG_API_H

/**
 * @file smlog_api.h
 * @brief Log Analysis API - Взаимодействие с логами системы
 * @author Tosa5656
 * @date 4 января, 2026
 */

#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace SecurityManager
{
    /**
    * @brief Коды ошибок
    */
    enum class LogError {
        SUCCESS = 0,
        FILE_NOT_FOUND = 1,
        PERMISSION_DENIED = 2,
        PARSE_ERROR = 3,
        INVALID_ARGUMENT = 4
    };

    /**
    * @brief Обвертка результатов запросов
    */
    template<typename T>
    struct LogResult
    {
        LogError code;
        std::string message;
        T data;

        LogResult() : code(LogError::SUCCESS) {}
        LogResult(LogError c, const std::string& msg) : code(c), message(msg) {}
        LogResult(LogError c, const std::string& msg, const T& d) : code(c), message(msg), data(d) {}

        bool success() const { return code == LogError::SUCCESS; }
        operator bool() const { return success(); }
    };

    /**
    * @brief Структура лога
    */
    struct LogEntry
    {
        std::string timestamp;
        std::string level;      // INFO, WARNING, ERROR, DEBUG
        std::string source;     // systemd, sshd, kernel и другие
        std::string message;
        std::string raw_line;   // Оригинальная строка

        // Метаданные
        std::string facility;
        int priority;
        std::string hostname;
        std::string process_name;
        int process_id;
    };

    /**
    * @brief Критерии фильтра логов
    */
    struct LogFilter
    {
        std::string start_time;     // ISO формат: 2026-01-01T00:00:00
        std::string end_time;       // ISO формат: 2026-01-01T23:59:59
        std::string level;          // Фильтр по уровню(INFO, WARNING, ERROR, DEBUG)
        std::string source;         // Фильтр по отправителю (sshd, kernel и другие)
        std::string keyword;        // По ключевому слову
        int min_priority = -1;      // Минимальная важность (0-7)
        int max_priority = -1;      // Максимальная важность (0-7)
    };

    /**
    * @brief Статистика лога
    */
    struct LogStats
    {
        unsigned long total_entries;
        unsigned long error_count;
        unsigned long warning_count;
        unsigned long info_count;
        std::string time_range_start;
        std::string time_range_end;
        std::vector<std::string> sources;  // Уникальные источники
    };

    /**
    * @brief Класс анализатора логов
    */
    class LogAnalyzer
    {
    public:
        LogAnalyzer();
        ~LogAnalyzer();

        /**
        * @brief Прочитать лог файл с фильтрами
        * @param filepath Путь к логу
        * @param filter Фильтры
        * @param max_lines Количество строчек к чтению (0 = все)
        * @return std::vector c лог строками
        */
        LogResult<std::vector<LogEntry>> readLogFile(const std::string& filepath, const LogFilter& filter = {}, size_t max_lines = 0);

        /**
        * @brief Поиск в лог файле
        * @param filepath Путь к логу
        * @param keyword Ключевое слово(поддерживает regex)
        * @param filter Фильтры(опционально)
        * @return std::vector с лог строками подходящими условию
        */
        LogResult<std::vector<LogEntry>> searchLogFile(const std::string& filepath, const std::string& keyword, const LogFilter& filter = {});

        /**
        * @brief Получить статистику по логу
        * @param filepath Путь к логу
        * @return Статистика по логу
        */
        LogResult<LogStats> getLogStats(const std::string& filepath);

        /**
        * @brief Мониторинга лога
        * @param filepath Путь к логу
        * @param callback Функция которая будет вызвана при новой лог строке
        * @return Удача/Неудача
        */
        LogResult<bool> monitorLogFile(const std::string& filepath, std::function<void(const LogEntry&)> callback);

        /**
        * @brief Остановка мониторинга лога
        * @param filepath Путь к логу
        * @return Удача/Неудача
        */
        LogResult<bool> stopMonitoring(const std::string& filepath);

        /**
        * @brief Парс systemd журнала
        * @param unit Имя юнита (опционально)
        * @param filter Фильтры
        * @param max_lines Максимальное количество строк (0 = все)
        * @return std::vector с лог строками
        */
        LogResult<std::vector<LogEntry>> readJournal(const std::string& unit = "", const LogFilter& filter = {}, size_t max_lines = 100);

        /**
        * @brief Экспорт лога
        * @param entries Лог строки для экспорта
        * @param format Формат экспорта (json, csv, txt)
        * @param output_file Выходной файл
        * @return Удача/Неудача
        */
        LogResult<bool> exportLogs(const std::vector<LogEntry>& entries, const std::string& format, const std::string& output_file);

        /**
        * @brief Остановка мониторинга всех логов
        * @return Удача/Неудача
        */
        LogResult<bool> stopAllMonitoring();
    private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };
}

#endif