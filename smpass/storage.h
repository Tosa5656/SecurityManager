/**
 * @file storage.h
 * @brief Хранение паролей и шифрование для инструмента smpass
 * @author Tosa5656
 * @date 1 января, 2026
 */

#pragma once

#include <iostream>
#include <fstream>
#include <sstream>
#include <format>
#include <filesystem>
#include <cstdlib>
#include <vector>
#include <algorithm>
#include "../json/json.hpp"
#include "sha256.h"
#include "aes256.h"

using json = nlohmann::json;

namespace fs = std::filesystem;

#define STORAGE_DIR std::format("{}/.sm/storage", std::getenv("HOME"))

/**
 * @brief Структура, представляющая запись пароля
 */
struct PasswordEntry
{
    std::string name;
    std::string login;
    std::string password;
    std::string password_key;
    std::string message;

    json to_json() const
    {
        return json
        {
            {"name", name},
            {"login", login},
            {"password", password},
            {"password_key", password_key},
            {"message", message}
        };
    }

    /**
     * @brief Создать запись из JSON
     * @param j JSON объект для разбора
     * @return Экземпляр PasswordEntry
     */
    static PasswordEntry from_json(const json& j)
    {
        PasswordEntry entry;
        entry.name = j.value("name", "");
        entry.login = j.value("login", "");
        entry.password = j.value("password", "");
        entry.password_key = j.value("password_key", "");
        entry.message = j.value("message", "");
        return entry;
    }
};

class Storage
{
public:
    /**
     * @brief Конструктор - инициализирует хранилище
     */
    Storage();

    /**
     * @brief Создать стандартные базы хранения
     * @return Статус успешности
     */
    int createStandardBases();

    /**
     * @brief Создать новую базу хранения
     * @param baseName Имя базы для создания
     */
    void createBase(const std::string baseName);

    /**
     * @brief Удалить базу хранения
     * @param baseName Имя базы для удаления
     */
    void removeBase(const std::string baseName);

    /**
     * @brief Загрузить пароли из хранилища
     * @return Вектор записей паролей
     */
    std::vector<PasswordEntry> loadPasswords();

    /**
     * @brief Сохранить пароли в хранилище
     * @param entries Вектор записей паролей для сохранения
     */
    void savePasswords(const std::vector<PasswordEntry>& entries);

    /**
     * @brief Добавить новую запись пароля
     * @param name Имя записи
     * @param login Логин/имя пользователя
     * @param password Пароль для шифрования и хранения
     * @param msg Дополнительное сообщение/заметки
     */
    void addNewPassword(const std::string& name, const std::string& login, const std::string& password, const std::string& msg);

    /**
     * @brief Получить расшифрованный пароль
     * @param name Имя записи
     * @param masterKey Мастер-ключ для расшифровки (опционально)
     * @return Расшифрованный пароль
     */
    std::string getPassword(const std::string& name, const std::string& masterKey = "");

    /**
     * @brief Удалить запись пароля
     * @param name Имя записи для удаления
     * @return True если успешно удалено
     */
    bool deletePassword(const std::string& name);

    /**
     * @brief Удалить все пароли
     */
    void deletePasswords();

private:
    std::string passwordsStorage = std::format("{}/passwords.smdb", STORAGE_DIR);  ///< Path to password storage file
    std::vector<PasswordEntry> passwords;  ///< In-memory password cache
};