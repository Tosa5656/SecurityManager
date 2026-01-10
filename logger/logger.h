/**
 * @file logger.h
 * @brief Потокобезопасная система логирования для Security Manager
 * @author Tosa5656
 * @date 4 января, 2026
 */

#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <cstdlib>

namespace fs = std::filesystem;

/**
 * @brief Потокобезопасный синглтон класс логгера
 *
 * Предоставляет функциональность логирования с поддержкой вывода в консоль и файл.
 * Использует паттерн синглтон для обеспечения единственного экземпляра логгера.
 */
class Logger {
private:
    static Logger* instance_;  ///< Singleton instance
    static std::mutex mutex_;  ///< Mutex for thread-safe singleton creation

    std::ofstream log_file_;      ///< Log file stream
    std::string log_file_path_;   ///< Path to log file
    bool log_to_file_;           ///< Whether to log to file
    bool log_to_console_;        ///< Whether to log to console
    std::mutex log_mutex_;       ///< Mutex for thread-safe logging

    /**
     * @brief Приватный конструктор для паттерна синглтон
     */
    Logger() : log_to_file_(true), log_to_console_(true)
    {
        const char* home = std::getenv("HOME");
        if (home)
        {
            fs::path log_dir = fs::path(home) / ".sm" / "logs";
            fs::create_directories(log_dir);
            log_file_path_ = (log_dir / "security_manager.log").string();
        }
        else
        {
            log_file_path_ = "/tmp/security_manager.log";
        }

        log_file_.open(log_file_path_, std::ios::app);
    }

    /**
     * @brief Деструктор - закрывает файл лога
     */
    ~Logger()
    {
        if (log_file_.is_open())
            log_file_.close();
    }

    Logger(const Logger&) = delete;  ///< Deleted copy constructor
    Logger& operator=(const Logger&) = delete;  ///< Deleted assignment operator

    /**
     * @brief Внутренний метод для записи сообщения лога
     * @param level Уровень логирования (INFO, WARNING, ERROR, DEBUG)
     * @param message Сообщение лога
     */
    void write(const std::string& level, const std::string& message)
    {
        std::lock_guard<std::mutex> lock(log_mutex_);

        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;

        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        ss << "." << std::setfill('0') << std::setw(3) << ms.count();
        std::string timestamp = ss.str();

        std::string log_message = "[" + timestamp + "] [" + level + "] " + message;

        if (log_to_console_)
        {
            if (level == "ERROR")
                std::cerr << log_message << std::endl;
            else
                std::cout << log_message << std::endl;
        }

        if (log_to_file_ && log_file_.is_open())
        {
            log_file_ << log_message << std::endl;
            log_file_.flush();
        }
    }

public:
    /**
     * @brief Получить синглтон экземпляр логгера
     * @return Указатель на экземпляр логгера
     */
    static Logger* getInstance()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (instance_ == nullptr)
            instance_ = new Logger();
        return instance_;
    }

    /**
     * @brief Включить или отключить логирование в файл
     * @param enable True для включения логирования в файл, false для отключения
     */
    void setLogToFile(bool enable)
    {
        std::lock_guard<std::mutex> lock(log_mutex_);
        log_to_file_ = enable;
    }

    /**
     * @brief Включить или отключить логирование в консоль
     * @param enable True для включения логирования в консоль, false для отключения
     */
    void setLogToConsole(bool enable)
    {
        std::lock_guard<std::mutex> lock(log_mutex_);
        log_to_console_ = enable;
    }

    /**
     * @brief Получить текущий путь к файлу лога
     * @return Путь к файлу лога
     */
    std::string getLogFilePath() const
    {
        return log_file_path_;
    }

    /**
     * @brief Записать информационное сообщение
     * @param message Сообщение для логирования
     */
    void logInfo(const std::string& message)
    {
        write("INFO", message);
    }

    /**
     * @brief Записать предупреждающее сообщение
     * @param message Сообщение для логирования
     */
    void logWarning(const std::string& message)
    {
        write("WARNING", message);
    }

    /**
     * @brief Записать сообщение об ошибке
     * @param message Сообщение для логирования
     */
    void logError(const std::string& message)
    {
        write("ERROR", message);
    }

    /**
     * @brief Записать отладочное сообщение
     * @param message Сообщение для логирования
     */
    void logDebug(const std::string& message)
    {
        write("DEBUG", message);
    }
};

/**
 * @brief Удобная функция для логирования информационных сообщений (обратная совместимость)
 * @param message Сообщение для логирования
 */
inline void LogInfo(const std::string& message)
{
    Logger::getInstance()->logInfo(message);
}

/**
 * @brief Удобная функция для логирования предупреждающих сообщений (обратная совместимость)
 * @param message Сообщение для логирования
 */
inline void LogWarning(const std::string& message)
{
    Logger::getInstance()->logWarning(message);
}

/**
 * @brief Удобная функция для логирования сообщений об ошибках (обратная совместимость)
 * @param message Сообщение для логирования
 */
inline void LogError(const std::string& message)
{
    Logger::getInstance()->logError(message);
}

/**
 * @brief Удобная функция для логирования отладочных сообщений (обратная совместимость)
 * @param message Сообщение для логирования
 */
inline void LogDebug(const std::string& message)
{
    Logger::getInstance()->logDebug(message);
}
