#ifndef SMPASS_API_H
#define SMPASS_API_H

/**
 * @file smpass_api.h
 * @brief Password Manager API - Работа с шифрованием и хранением пароля
 * @author Tosa5656
 * @date 4 января, 2026
 */

#include <string>
#include <vector>
#include <map>
#include <memory>

namespace SecurityManager
{
    /**
    * @brief Коды ошибок
    */
    enum class PasswordError
    {
        SUCCESS = 0,
        FILE_NOT_FOUND = 1,
        PERMISSION_DENIED = 2,
        INVALID_ARGUMENT = 3,
        ENCRYPTION_ERROR = 5,
        STORAGE_ERROR = 6
    };

    /**
    * @brief Обвертка результатов работы с паролями
    */
    template<typename T>
    struct PasswordResult
    {
        PasswordError code;
        std::string message;
        T data;

        PasswordResult() : code(PasswordError::SUCCESS) {}
        PasswordResult(PasswordError c, const std::string& msg) : code(c), message(msg) {}
        PasswordResult(PasswordError c, const std::string& msg, const T& d) : code(c), message(msg), data(d) {}

        bool success() const { return code == PasswordError::SUCCESS; }
        operator bool() const { return success(); }
    };

    /**
    * @brief Доступные алгоритмы хеширования
    */
    enum class HashAlgorithm
    {
        SHA256,
        AES256
    };

    /**
    * @brief Структура строки пароля
    */
    struct PasswordEntry
    {
        std::string service;
        std::string username;
        std::string password;
        std::string created_date;
        std::string last_modified;
    };

    /**
    * @brief Класс менеджера паролей
    */
    class PasswordManager
    {
    public:
        PasswordManager();
        ~PasswordManager();

        /**
        * @brief Хешировать строку нужных алгоритмом
        * @param input Строка для хеширования
        * @param algorithm Алгоритм шифрования
        * @return Хешированая строка/Ошибка
        */
        PasswordResult<std::string> hashString(const std::string& input, HashAlgorithm algorithm);

        /**
        * @brief Добавить новый пароль
        * @param service Сервис
        * @param username Имя пользователя
        * @param password Пароль
        * @param description Описание
        * @return Удача/Неудача
        */
        PasswordResult<bool> addPassword(const std::string& service, const std::string& username, const std::string& password, const std::string& description = "");

        /**
        * @brief Получить пароль по сервису
        * @param service Сервис
        * @return Пароль/Ошибка
        */
        PasswordResult<PasswordEntry> getPassword(const std::string& service);

        /**
        * @brief Обновить существующий пароль
        * @param service Сервис
        * @param new_password Новый пароль
        * @return Удача/Неудача
        */
        PasswordResult<bool> updatePassword(const std::string& service, const std::string& new_password);

        /**
        * @brief Удалить пароль
        * @param service Сервис
        * @return Удача/Неудача
        */
        PasswordResult<bool> deletePassword(const std::string& service);

        /**
        * @brief Получить список всех сервисов в хранилище
        * @return std::vector с названими сервисов
        */
        PasswordResult<std::vector<std::string>> listServices();

        /**
        * @brief Поиск пароля по ключевому слову
        * @param keyword Ключевому слову
        * @return std::vector с паролями подходящими по условию
        */
        PasswordResult<std::vector<PasswordEntry>> searchPasswords(const std::string& keyword);
    private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };
}

#endif