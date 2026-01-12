/**
 * @file smlog.cpp
 * @brief Инструмент командной строки для анализа системных логов
 * @author Tosa5656
 * @date 4 января, 2026
 */

#include "SystemLogger.h"
#include "../logger/logger.h"
#include <iostream>
#include <cstring>
#include <csignal>
#include <cstring>
#include <chrono>
#include <thread>
#include <sstream>

SystemLogger* g_logger = nullptr;  ///< Глобальный экземпляр логгера

/**
 * @brief Отобразить справочную информацию
 */
void help()
{
    std::cout << "smlog usage:" << std::endl;
    std::cout << "smlog help - показать этот раздел" << std::endl;
    std::cout << "smlog list - показать доступные лог файлы" << std::endl;
    std::cout << "smlog read <path> [lines] - прочитать лог файл (по умолчанию: 100 строк)" << std::endl;
    std::cout << "smlog search <path> <keyword> - поиск по ключевому слову в лог файле" << std::endl;
    std::cout << "smlog journal [unit] [lines] - прочитать systemd journal (по умолчанию: 100 строк)" << std::endl;
    std::cout << "smlog top-ips <path> [count] - показать топ IP адресов (по умолчанию: 10)" << std::endl;
    std::cout << "smlog top-users <path> [count] - показать ток ползователей (по умолчанию: 10)" << std::endl;
    std::cout << "smlog report [type] - сгенерировать отчет (security, daily, system, journal, full)" << std::endl;
    std::cout << "smlog monitor - начать мониторинг логов (Ctrl+C для выхода)" << std::endl;
}

/**
 * @brief Обработчик сигналов для корректного завершения
 * @param sig Номер сигнала
 */
void signalHandler(int sig)
{
    if (g_logger)
        g_logger->stopMonitoring();
    exit(0);
}

/**
 * @brief Команда для отображения списка доступных файлов логов
 * @param logger Экземпляр логгера
 */
void cmd_list(SystemLogger& logger)
{
    auto logs = logger.getAvailableLogs();
    LogInfo("Доступные файлы логов:");
    for (const auto& log : logs)
        LogInfo("  " + log);
}

/**
 * @brief Команда для чтения файла лога
 * @param logger Экземпляр логгера
 * @param argc Количество аргументов
 * @param argv Массив аргументов
 */
void cmd_read(SystemLogger& logger, int argc, char* argv[])
{
    if (argc < 3)
    {
        LogError("Ошибка: требуется путь к логу");
        LogError("Использование: smlog read <путь> [строки]");
        return;
    }

    std::string path = argv[2];
    int lines = 100;

    if (argc >= 4)
    {
        try
        {
            lines = std::stoi(argv[3]);
        }
        catch (...)
        {
            LogError("Ошибка: некорректное количество строк");
            return;
        }
    }

    auto log_lines = logger.readLog(path, lines);
    if (log_lines.empty() && !logger.getLastError().empty())
    {
        LogError("Ошибка: " + logger.getLastError());
        return;
    }

    for (const auto& line : log_lines)
        std::cout << line << std::endl;
}

/**
 * @brief Команда для поиска в файле лога
 * @param logger Экземпляр логгера
 * @param argc Количество аргументов
 * @param argv Массив аргументов
 */
void cmd_search(SystemLogger& logger, int argc, char* argv[])
{
    if (argc < 4)
    {
        LogError("Ошибка: требуется путь к логу и ключевое слово");
        LogError("Использование: smlog search <путь> <ключевое_слово>");
        return;
    }

    std::string path = argv[2];
    std::string keyword = argv[3];
    
    auto results = logger.searchLog(path, keyword);
    if (results.empty() && !logger.getLastError().empty()) {
        LogError("Ошибка: " + logger.getLastError());
        return;
    }
    
    std::stringstream ss;
    ss << "Найдено " << results.size() << " совпадений:";
    LogInfo(ss.str());
    // Вывод результатов поиска в stdout (может быть перенаправлен)
    for (const auto& line : results)
        std::cout << line << std::endl;
}

/**
 * @brief Команда для чтения журнала systemd
 * @param logger Экземпляр логгера
 * @param argc Количество аргументов
 * @param argv Массив аргументов
 */
void cmd_journal(SystemLogger& logger, int argc, char* argv[])
{
    if (!logger.hasJournalSupport())
    {
        LogError("Ошибка: systemd journal не поддерживается на этой системе");
        return;
    }
    
    std::string unit = "";
    int lines = 100;
    
    if (argc >= 3)
    {
        unit = argv[2];
    }
    
    if (argc >= 4)
    {
        try
        {
            lines = std::stoi(argv[3]);
        }
        catch (...)
        {
            LogError("Ошибка: некорректное количество строк");
            return;
        }
    }
    
    auto journal = logger.readJournal(unit, lines);
    if (journal.empty() && !logger.getLastError().empty())
    {
        LogError("Ошибка: " + logger.getLastError());
        return;
    }
    
    // Вывод записей журнала в stdout (может быть перенаправлен)
    for (const auto& entry : journal)
    {
        std::cout << entry << std::endl;
    }
}

/**
 * @brief Команда для отображения топ IP адресов
 * @param logger Экземпляр логгера
 * @param argc Количество аргументов
 * @param argv Массив аргументов
 */
void cmd_top_ips(SystemLogger& logger, int argc, char* argv[])
{
    if (argc < 3)
    {
        LogError("Ошибка: требуется путь к логу");
        LogError("Использование: smlog top-ips <path> [count]");
        return;
    }
    
    std::string path = argv[2];
    int count = 10;
    
    if (argc >= 4) {
        try
        {
            count = std::stoi(argv[3]);
        }
        catch (...)
        {
            LogError("Error: invalid count");
            return;
        }
    }
    
    auto top_ips = logger.findTopIPs(path, count);
    if (top_ips.empty() && !logger.getLastError().empty())
    {
        LogError("Ошибка: " + logger.getLastError());
        return;
    }
    
    std::stringstream ss;
    ss << "Топ " << count << " IP адресов:";
    LogInfo(ss.str());
    for (const auto& [ip, cnt] : top_ips)
    {
        ss.str("");
        ss << "  " << ip << ": " << cnt << " событий";
        LogInfo(ss.str());
    }
}

/**
 * @brief Команда для отображения топ пользователей
 * @param logger Экземпляр логгера
 * @param argc Количество аргументов
 * @param argv Массив аргументов
 */
void cmd_top_users(SystemLogger& logger, int argc, char* argv[])
{
    if (argc < 3)
    {
        LogError("Ошибка: требуется путь к лог файлу");
        LogError("Использование: smlog top-users <path> [count]");
        return;
    }
    
    std::string path = argv[2];
    int count = 10;
    
    if (argc >= 4)
    {
        try
        {
            count = std::stoi(argv[3]);
        }
        catch (...)
        {
            LogError("Ошибка: неверное количество");
            return;
        }
    }
    
    auto top_users = logger.findTopUsers(path, count);
    if (top_users.empty() && !logger.getLastError().empty())
    {
        LogError("Ошибка: " + logger.getLastError());
        return;
    }
    
    std::stringstream ss;
    ss << "Топ " << count << " пользователей:";
    LogInfo(ss.str());
    for (const auto& [user, cnt] : top_users)
    {
        ss.str("");
        ss << "  " << user << ": " << cnt << " событий";
        LogInfo(ss.str());
    }
}

/**
 * @brief Команда для генерации отчета
 * @param logger Экземпляр логгера
 * @param argc Количество аргументов
 * @param argv Массив аргументов
 */
void cmd_report(SystemLogger& logger, int argc, char* argv[])
{
    std::string type = "security";
    
    if (argc >= 3)
    {
        type = argv[2];
    }
    
    std::string report;
    
    if (type == "security") 
        report = logger.generateSecurityReport();
    else if (type == "daily")
        report = logger.generateDailyReport();
    else if (type == "system")
        report = logger.generateSystemReport();
    else if (type == "journal")
        report = logger.generateJournalReport();
    else if (type == "full")
        report = logger.generateFullReport();
    else
    {
        std::stringstream ss;
        ss << "Ошибка: неизвестные тип отчета: " << type;
        LogError(ss.str());
        LogError("Доступные типы: security, daily, system, journal, full");
        return;
    }
    
    // Вывод отчета в stdout (может быть перенаправлен)
    std::cout << report << std::endl;
}

void cmd_monitor(SystemLogger& logger)
{
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    g_logger = &logger;
    
    LogInfo("Запуск мониторинга логов (Ctrl+C для остановки)...");
    
    logger.startMonitoring();
    
    // Ожидать прерывания
    while (logger.isMonitoring())
        std::this_thread::sleep_for(std::chrono::seconds(1));
}

/**
 * @brief Main entry point for smlog tool
 * @param argc Argument count
 * @param argv Argument values
 * @return Exit code (0 for success, 1 for error)
 */
int main(int argc, char* argv[])
{
    SystemLogger logger;
    
    if (!logger.initialize())
    {
        LogError("Ошибка: не удаласть инициализация: " + logger.getLastError());
        return 1;
    }
    
    if (argc == 1)
    {
        std::cout << "Используй smlog help чтобы посмотреть помощь по использованию программы" << std::endl;
        return 0;
    }

    if (argc == 2 && strcmp(argv[1], "help") == 0)
    {
        help();
        return 0;
    }
    
    if (argc >= 2 && strcmp(argv[1], "list") == 0)
    {
        cmd_list(logger);
        return 0;
    }
    
    if (argc >= 2 && strcmp(argv[1], "read") == 0)
    {
        cmd_read(logger, argc, argv);
        return 0;
    }
    
    if (argc >= 2 && strcmp(argv[1], "search") == 0)
    {
        cmd_search(logger, argc, argv);
        return 0;
    }
    
    if (argc >= 2 && strcmp(argv[1], "journal") == 0)
    {
        cmd_journal(logger, argc, argv);
        return 0;
    }
    
    if (argc >= 2 && strcmp(argv[1], "top-ips") == 0)
    {
        cmd_top_ips(logger, argc, argv);
        return 0;
    }
    
    if (argc >= 2 && strcmp(argv[1], "top-users") == 0)
    {
        cmd_top_users(logger, argc, argv);
        return 0;
    }
    
    if (argc >= 2 && strcmp(argv[1], "report") == 0)
    {
        cmd_report(logger, argc, argv);
        return 0;
    }
    
    if (argc >= 2 && strcmp(argv[1], "monitor") == 0)
    {
        cmd_monitor(logger);
        return 0;
    }
    
    std::stringstream ss;
    ss << "Ошибка: неизвестная команда: " << argv[1];
    LogError(ss.str());
    LogError("Используй smlog help чтобы посмотреть помощь по использованию программы");
    return 1;
}