/**
 * @file smpass_api.cpp
 * @brief Реализация Password Manager API
 * @author Tosa5656
 * @date 4 января, 2026
 */

#include "smpass_api.h"
#include "../../smpass/sha256.h"
#include "../../smpass/aes256.h"
#include "../../smpass/storage.h"
#include <chrono>
#include <ctime>

namespace SecurityManager
{

class PasswordManager::Impl
{
private:
    Storage storage;

    std::string getCurrentTimestamp()
    {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        char buffer[26];
        ctime_r(&time_t, buffer);
        std::string timestamp(buffer);
        if (!timestamp.empty() && timestamp.back() == '\n')
            timestamp.pop_back();
        return timestamp;
    }

public:
    std::string hashSHA256(const std::string& input)
    {
        return SHA256::hashString(input);
    }

    std::string hashAES256(const std::string& input)
    {
        auto key = AES256::generateKey();
        auto iv = AES256::generateIV();
        return AES256::encrypt(input, key, iv);
    }

    bool addPasswordEntry(const std::string& service, const std::string& username,
                         const std::string& password, const std::string& description)
    {
        try
        {
            storage.addNewPassword(service, username, password, description);
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    PasswordEntry getPasswordEntry(const std::string& service)
    {
        PasswordEntry entry;
        entry.service = service;

        try
        {
            auto entries = storage.loadPasswords();
            for (const auto& stored_entry : entries)
            {
                if (stored_entry.name == service)
                {
                    entry.username = stored_entry.login;
                    entry.password = stored_entry.password;
                    entry.created_date = "Unknown";
                    entry.last_modified = getCurrentTimestamp();
                    break;
                }
            }
        }
        catch (...)
        {
        }

        return entry;
    }

    bool updatePasswordEntry(const std::string& service, const std::string& new_password)
    {
        try
        {
            auto existing_entry = getPasswordEntry(service);
            if (existing_entry.username.empty())
                return false;

            storage.deletePassword(service);
            std::string description = existing_entry.last_modified;
            storage.addNewPassword(service, existing_entry.username, new_password, description);
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

    bool deletePasswordEntry(const std::string& service)
    {
        try
        {
            return storage.deletePassword(service);
        }
        catch (...)
        {
            return false;
        }
    }

    std::vector<std::string> listServices()
    {
        std::vector<std::string> services;
        try
        {
            auto entries = storage.loadPasswords();
            for (const auto& entry : entries)
            {
                services.push_back(entry.name);
            }
        }
        catch (...)
        {
        }
        return services;
    }

    std::vector<PasswordEntry> searchPasswords(const std::string& keyword)
    {
        std::vector<PasswordEntry> results;
        try
        {
            auto entries = storage.loadPasswords();
            std::string lower_keyword = keyword;
            std::transform(lower_keyword.begin(), lower_keyword.end(), lower_keyword.begin(), ::tolower);

            for (const auto& entry : entries)
            {
                std::string lower_service = entry.name;
                std::string lower_username = entry.login;
                std::transform(lower_service.begin(), lower_service.end(), lower_service.begin(), ::tolower);
                std::transform(lower_username.begin(), lower_username.end(), lower_username.begin(), ::tolower);

                if (lower_service.find(lower_keyword) != std::string::npos ||
                    lower_username.find(lower_keyword) != std::string::npos)
                {
                    PasswordEntry result_entry;
                    result_entry.service = entry.name;
                    result_entry.username = entry.login;
                    result_entry.password = entry.password;
                    result_entry.created_date = "Unknown";
                    result_entry.last_modified = getCurrentTimestamp();
                    results.push_back(result_entry);
                }
            }
        }
        catch (...)
        {
        }
        return results;
    }
};

/**
 * @brief Конструктор - инициализирует менеджер паролей
 */
PasswordManager::PasswordManager() : impl_(std::make_unique<Impl>())
{
}

/**
 * @brief Деструктор
 */
PasswordManager::~PasswordManager() = default;

/**
 * @brief Хеширует строку указанным алгоритмом
 * @param input Входная строка для хеширования
 * @param algorithm Алгоритм хеширования
 * @return Результат с хешированной строкой или ошибкой
 */
PasswordResult<std::string> PasswordManager::hashString(const std::string& input, HashAlgorithm algorithm)
{
    try
    {
        std::string result;
        switch (algorithm)
        {
            case HashAlgorithm::SHA256:
                result = impl_->hashSHA256(input);
                break;
            case HashAlgorithm::AES256:
                result = impl_->hashAES256(input);
                break;
            default:
                return PasswordResult<std::string>(PasswordError::INVALID_ARGUMENT, "Unsupported hash algorithm");
        }
        return PasswordResult<std::string>(PasswordError::SUCCESS, "", result);
    }
    catch (const std::exception& e)
    {
        return PasswordResult<std::string>(PasswordError::ENCRYPTION_ERROR, e.what());
    }
}

/**
 * @brief Добавляет новую запись пароля
 * @param service Имя сервиса
 * @param username Имя пользователя для сервиса
 * @param password Пароль для хранения
 * @param description Необязательное описание
 * @return Результат с true при успехе, false при ошибке
 */
PasswordResult<bool> PasswordManager::addPassword(const std::string& service,
                                                const std::string& username,
                                                const std::string& password,
                                                const std::string& description)
{
    try
    {
        bool success = impl_->addPasswordEntry(service, username, password, description);
        return PasswordResult<bool>(success ? PasswordError::SUCCESS : PasswordError::STORAGE_ERROR,
                                  success ? "" : "Failed to add password", success);
    }
    catch (const std::exception& e)
    {
        return PasswordResult<bool>(PasswordError::STORAGE_ERROR, e.what(), false);
    }
}

/**
 * @brief Получает запись пароля по имени сервиса
 * @param service Имя сервиса для поиска
 * @return Результат с записью пароля или ошибкой
 */
PasswordResult<PasswordEntry> PasswordManager::getPassword(const std::string& service)
{
    try
    {
        auto entry = impl_->getPasswordEntry(service);
        if (entry.username.empty())
            return PasswordResult<PasswordEntry>(PasswordError::FILE_NOT_FOUND, "Password entry not found");
        return PasswordResult<PasswordEntry>(PasswordError::SUCCESS, "", entry);
    }
    catch (const std::exception& e)
    {
        return PasswordResult<PasswordEntry>(PasswordError::STORAGE_ERROR, e.what());
    }
}

/**
 * @brief Обновляет существующую запись пароля
 * @param service Имя сервиса
 * @param new_password Новый пароль
 * @return Результат с true при успехе, false при ошибке
 */
PasswordResult<bool> PasswordManager::updatePassword(const std::string& service, const std::string& new_password)
{
    try
    {
        bool success = impl_->updatePasswordEntry(service, new_password);
        return PasswordResult<bool>(success ? PasswordError::SUCCESS : PasswordError::STORAGE_ERROR,
                                  success ? "" : "Failed to update password", success);
    }
    catch (const std::exception& e)
    {
        return PasswordResult<bool>(PasswordError::STORAGE_ERROR, e.what(), false);
    }
}

/**
 * @brief Удаляет запись пароля
 * @param service Имя сервиса для удаления
 * @return Результат с true при успехе, false при ошибке
 */
PasswordResult<bool> PasswordManager::deletePassword(const std::string& service)
{
    try
    {
        bool success = impl_->deletePasswordEntry(service);
        return PasswordResult<bool>(success ? PasswordError::SUCCESS : PasswordError::STORAGE_ERROR,
                                  success ? "" : "Failed to delete password", success);
    }
    catch (const std::exception& e)
    {
        return PasswordResult<bool>(PasswordError::STORAGE_ERROR, e.what(), false);
    }
}

/**
 * @brief Получает список всех сохраненных имен сервисов
 * @return Результат с вектором имен сервисов
 */
PasswordResult<std::vector<std::string>> PasswordManager::listServices()
{
    try
    {
        auto services = impl_->listServices();
        return PasswordResult<std::vector<std::string>>(PasswordError::SUCCESS, "", services);
    }
    catch (const std::exception& e)
    {
        return PasswordResult<std::vector<std::string>>(PasswordError::STORAGE_ERROR, e.what());
    }
}

/**
 * @brief Ищет записи паролей по ключевому слову
 * @param keyword Ключевое слово для поиска
 * @return Результат с вектором подходящих записей паролей
 */
PasswordResult<std::vector<PasswordEntry>> PasswordManager::searchPasswords(const std::string& keyword)
{
    try
    {
        auto results = impl_->searchPasswords(keyword);
        return PasswordResult<std::vector<PasswordEntry>>(PasswordError::SUCCESS, "", results);
    }
    catch (const std::exception& e)
    {
        return PasswordResult<std::vector<PasswordEntry>>(PasswordError::STORAGE_ERROR, e.what());
    }
}

} // namespace SecurityManager