/**
 * @file SystemLogger.h
 * @brief Продвинутая система логирования и мониторинга системы
 * @author Tosa5656
 * @date 4 января, 2026
 */

#ifndef SYSTEMLOGGER_H
#define SYSTEMLOGGER_H

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <fstream>
#include <sstream>
#include <iostream>
#include <filesystem>
#include <memory>
#include <optional>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <regex>
#include <algorithm>
#include <iomanip>
#include <cstdlib>
#include <array>
#include <functional>

namespace fs = std::filesystem;

/**
 * @brief Продвинутый системный логгер, поддерживающий множественные источники логов
 *
 * Предоставляет всесторонние возможности логирования включая файловые логи,
 * журнал systemd, мониторинг в реальном времени и анализ логов.
 */
class SystemLogger
{
public:
    /**
     * @brief Конструктор по умолчанию
     */
    SystemLogger();

    /**
     * @brief Конструктор с путем к файлу конфигурации
     * @param configPath Путь к файлу конфигурации
     */
    explicit SystemLogger(const std::string& configPath);

    /**
     * @brief Деструктор
     */
    ~SystemLogger();

    /**
     * @brief Инициализировать логгер с настройками по умолчанию
     * @return True если инициализация успешна
     */
    bool initialize();

    /**
     * @brief Начать мониторинг логов в реальном времени
     */
    void startMonitoring();

    /**
     * @brief Остановить мониторинг логов в реальном времени
     */
    void stopMonitoring();
    
    // Операции с файловыми логами
    /**
     * @brief Прочитать строки из файла лога
     * @param logPath Путь к файлу лога
     * @param lines Количество строк для чтения (по умолчанию 100)
     * @return Вектор строк лога
     */
    std::vector<std::string> readLog(const std::string& logPath, int lines = 100);

    /**
     * @brief Поиск в файле лога по ключевым словам в диапазоне времени
     * @param logPath Путь к файлу лога
     * @param keyword Ключевое слово для поиска
     * @param timeFrom Фильтр времени начала (опционально)
     * @param timeTo Фильтр времени окончания (опционально)
     * @return Вектор соответствующих строк лога
     */
    std::vector<std::string> searchLog(const std::string& logPath,
                                       const std::string& keyword,
                                       const std::string& timeFrom = "",
                                       const std::string& timeTo = "");

    /**
     * @brief Получить последние N строк из файла лога (функциональность tail)
     * @param logPath Путь к файлу лога
     * @param lines Количество строк для получения (по умолчанию 50)
     * @return Вектор последних строк лога
     */
    std::vector<std::string> tailLog(const std::string& logPath,
                                     int lines = 50);
    
    // Операции с журналом systemd
    /**
     * @brief Прочитать записи из журнала systemd
     * @param unit Имя юнита systemd (опционально)
     * @param lines Количество строк для чтения (по умолчанию 100)
     * @return Вектор записей журнала
     */
    std::vector<std::string> readJournal(const std::string& unit = "",
                                         int lines = 100);

    /**
     * @brief Поиск в журнале systemd по ключевым словам
     * @param keyword Ключевое слово для поиска
     * @param unit Имя юнита systemd (опционально)
     * @param timeFrom Фильтр времени начала (опционально)
     * @param timeTo Фильтр времени окончания (опционально)
     * @param priority Фильтр приоритета (опционально)
     * @return Вектор соответствующих записей журнала
     */
    std::vector<std::string> searchJournal(const std::string& keyword,
                                           const std::string& unit = "",
                                           const std::string& timeFrom = "",
                                           const std::string& timeTo = "",
                                           const std::string& priority = "");

    /**
     * @brief Получить список доступных юнитов systemd
     * @return Вектор имен юнитов
     */
    std::vector<std::string> getJournalUnits();

    /**
     * @brief Получить статистику журнала systemd
     * @return Карта с статистикой
     */
    std::map<std::string, int> getJournalStats();

    /**
     * @brief Очистить журнал systemd
     * @param unit Имя юнита для очистки (опционально)
     * @return True если успешно очищено
     */
    bool clearJournal(const std::string& unit = "");
    
    // Анализ логов
    /**
     * @brief Подсчитать записи по уровням логирования
     * @param logPath Путь к файлу лога
     * @param timeRange Диапазон времени (по умолчанию "today")
     * @return Карта уровень -> количество
     */
    std::map<std::string, int> countByLevel(const std::string& logPath,
                                           const std::string& timeRange = "today");

    /**
     * @brief Найти топ IP адресов по частоте появления
     * @param logPath Путь к файлу лога
     * @param topN Количество топ записей (по умолчанию 10)
     * @return Карта IP -> количество
     */
    std::map<std::string, int> findTopIPs(const std::string& logPath,
                                         int topN = 10);

    /**
     * @brief Найти топ пользователей по частоте появления
     * @param logPath Путь к файлу лога
     * @param topN Количество топ записей (по умолчанию 10)
     * @return Карта пользователь -> количество
     */
    std::map<std::string, int> findTopUsers(const std::string& logPath,
                                           int topN = 10);
    
    // Мониторинг и правила
    /**
     * @brief Добавить правило наблюдения за логами
     * @param ruleName Имя правила
     * @param pattern Шаблон для поиска
     * @param action Действие при срабатывании
     * @param checkJournal Проверять ли journal (по умолчанию true)
     */
    void addWatchRule(const std::string& ruleName,
                     const std::string& pattern,
                     const std::string& action,
                     bool checkJournal = true);

    /**
     * @brief Удалить правило наблюдения
     * @param ruleName Имя правила для удаления
     */
    void removeWatchRule(const std::string& ruleName);

    /**
     * @brief Получить список всех правил наблюдения
     * @return Вектор имен правил
     */
    std::vector<std::string> listWatchRules() const;
    
    // Управление ротацией и очисткой
    /**
     * @brief Повернуть (ротировать) файл лога
     * @param logPath Путь к файлу лога
     * @return True если успешно ротировано
     */
    bool rotateLog(const std::string& logPath);

    /**
     * @brief Сжать файл лога
     * @param logPath Путь к файлу лога
     * @return True если успешно сжато
     */
    bool compressLog(const std::string& logPath);

    /**
     * @brief Очистить старые логи
     * @param logDir Директория с логами
     * @param daysToKeep Количество дней для хранения (по умолчанию 30)
     */
    void cleanOldLogs(const std::string& logDir, int daysToKeep = 30);
    
    // Отчеты
    /**
     * @brief Сгенерировать ежедневный отчет
     * @return Строка с отчетом
     */
    std::string generateDailyReport();

    /**
     * @brief Сгенерировать отчет по безопасности
     * @return Строка с отчетом
     */
    std::string generateSecurityReport();

    /**
     * @brief Сгенерировать системный отчет
     * @return Строка с отчетом
     */
    std::string generateSystemReport();

    /**
     * @brief Сгенерировать отчет по журналу systemd
     * @return Строка с отчетом
     */
    std::string generateJournalReport();

    /**
     * @brief Сгенерировать полный отчет
     * @return Строка с отчетом
     */
    std::string generateFullReport();
    
    // Утилиты
    /**
     * @brief Определить дистрибутив Linux
     * @return Название дистрибутива
     */
    std::string detectDistribution();
    /**
     * @brief Получить список доступных файлов логов
     * @return Вектор путей к файлам логов
     */
    std::vector<std::string> getAvailableLogs();
    /**
     * @brief Получить статистику логов
     * @return Карта с статистикой
     */
    std::map<std::string, std::string> getLogStats();
    bool hasJournalSupport() const
    {
        return has_journal_support_;
    }

    /**
     * @brief Проверить, запущен ли логгер
     * @return True если запущен
     */
    bool isRunning() const
    {
        return is_running_;
    }

    /**
     * @brief Проверить, активен ли мониторинг
     * @return True если активен
     */
    bool isMonitoring() const
    {
        return monitoring_active_;
    }

    /**
     * @brief Получить последнюю ошибку
     * @return Сообщение об ошибке
     */
    std::string getLastError() const
    {
        return last_error_;
    }

    /**
     * @brief Получить путь к конфигурации
     * @return Путь к файлу конфигурации
     */
    std::string getConfigPath() const
    {
        return config_path_;
    }

    /**
     * @brief Получить название дистрибутива
     * @return Название дистрибутива
     */
    std::string getDistribution() const
    {
        return distribution_;
    }
    
    // Статические утилиты
    /**
     * @brief Получить стандартные пути к системным логам
     * @return Вектор путей к файлам логов
     */
    static std::vector<std::string> getSystemLogPaths();

    /**
     * @brief Проверить, является ли файл лог-файлом
     * @param path Путь к файлу для проверки
     * @return True если является лог-файлом
     */
    static bool isLogFile(const std::string& path);

private:
    // Структуры данных
    struct LogEntry {
        std::string timestamp;
        std::string hostname;
        std::string service;
        std::string pid;
        std::string level;
        std::string message;
        std::string raw_line;
        
        std::string toString() const
        {
            return timestamp + " " + hostname + " " + service + ": " + message;
        }
    };
    
    struct JournalEntry {
        std::string timestamp;
        std::string hostname;
        std::string unit;
        std::string priority;
        std::string message;
        std::string pid;
        std::string syslog_identifier;
        std::string raw_json;
        
        std::string toString() const
        {
            return timestamp + " " + unit + "[" + priority + "]: " + message;
        }
    };
    
    struct WatchRule {
        std::string name;
        std::string pattern;
        std::string action;
        std::chrono::system_clock::time_point created;
        bool enabled;
        bool check_journal;
        
        std::string toString() const
        {
            return name + ": '" + pattern + "' -> " + action +
                   " [journal: " + (check_journal ? "yes" : "no") + "]";
        }
    };
    
    // Приватные методы - файловые операции
    /**
     * @brief Проверить существование файла
     * @param path Путь к файлу
     * @return True если файл существует
     */
    bool file_exists(const std::string& path);

    /**
     * @brief Прочитать строки из файла
     * @param path Путь к файлу
     * @param max_lines Максимальное количество строк (0 = все)
     * @return Вектор строк
     */
    std::vector<std::string> read_lines(const std::string& path, int max_lines = 0);

    /**
     * @brief Записать строки в файл
     * @param path Путь к файлу
     * @param lines Вектор строк для записи
     * @return True если успешно записано
     */
    bool write_lines(const std::string& path, const std::vector<std::string>& lines);

    /**
     * @brief Получить хеш файла
     * @param path Путь к файлу
     * @return Хеш файла
     */
    std::string get_file_hash(const std::string& path);

    /**
     * @brief Получить размер файла в человеко-читаемом формате
     * @param path Путь к файлу
     * @return Размер файла
     */
    std::string get_file_size_human(const std::string& path);
    
    // Приватные методы - парсинг
    std::optional<LogEntry> parse_log_line(const std::string& line);
    std::optional<JournalEntry> parse_journal_json(const std::string& json_line);
    std::string extract_ip_from_line(const std::string& line);
    std::string extract_user_from_line(const std::string& line);
    std::string extract_level_from_line(const std::string& line);
    
    // Приватные методы - journald операции
    bool init_journal_support();
    std::vector<std::string> execute_journalctl_command(const std::vector<std::string>& args);
    std::vector<JournalEntry> read_journal_entries(int max_entries = 100, 
                                                  const std::string& cursor = "");
    std::string get_journal_cursor();
    
    // Приватные методы - утилиты времени
    std::string get_current_time();
    std::string format_time(const std::chrono::system_clock::time_point& tp);
    bool is_time_in_range(const std::string& timestamp, 
                         const std::string& from, 
                         const std::string& to);
    std::string parse_relative_time(const std::string& rel_time);
    
    // Приватные методы - обработка правил
    void check_rules_for_file_line(const std::string& logPath, const std::string& line);
    void check_rules_for_journal_entry(const JournalEntry& entry);
    void execute_rule_action(const WatchRule& rule, 
                            const std::string& source, 
                            const std::string& message);
    
    // Приватные методы - мониторинг
    void monitor_loop();
    void check_file_log_changes();
    void check_journal_changes();
    
    // Приватные методы - конфигурация
    bool load_config();
    bool save_config();
    void setup_default_config();
    void setup_log_paths();
    std::string get_log_path_for_service(const std::string& service);
    
    // Члены класса
    std::string config_path_;
    std::string last_error_;
    std::string distribution_;
    bool is_running_;
    bool monitoring_active_;
    bool has_journal_support_;
    
    std::map<std::string, WatchRule> watch_rules_;
    std::map<std::string, size_t> last_file_sizes_;
    std::map<std::string, std::string> log_paths_;
    std::map<std::string, std::string> journal_cursors_;
    
    std::thread monitor_thread_;
    std::mutex log_mutex_;
    std::condition_variable monitor_cv_;
    
    // Callback для алертов
    std::function<void(const std::string& rule, 
                      const std::string& source, 
                      const std::string& message)> alert_callback_;
};

#endif