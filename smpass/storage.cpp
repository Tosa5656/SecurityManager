/**
 * @file storage.cpp
 * @brief Реализация безопасного хранения паролей
 * @author Tosa5656
 * @date 4 января, 2026
 */

#include "storage.h"
#include "../logger/logger.h"

Storage::Storage()
{
    fs::create_directories(STORAGE_DIR);
    OpenSSL_add_all_algorithms();

    if (!fs::exists(passwordsStorage))
        createStandardBases();
}

int Storage::createStandardBases()
{
    std::ofstream file(passwordsStorage);
    std::stringstream ss;
    if (file.is_open())
    {
        json emptyArray = json::array();
        file << emptyArray.dump(4);
        ss << "Created new database: " << passwordsStorage << std::endl;
        LogInfo(ss.str());
        return 1;
    }
    else
    {
        ss << "Failed to create database: " << passwordsStorage << std::endl;
        LogError(ss.str());
        return -1;
    }
}

std::vector<PasswordEntry> Storage::loadPasswords()
{
    std::vector<PasswordEntry> entries;
    std::ifstream file(passwordsStorage);

    if (!file.is_open())
    {
        std::cerr << "[WARN] File " << passwordsStorage << " not found or cannot be opened." << std::endl;
        return entries;
    }

    try
    {
        json j;
        file >> j;

        if (j.is_array())
            for (const auto& item : j)
                entries.push_back(PasswordEntry::from_json(item));
        else
            std::cerr << "[ERROR] JSON file has incorrect format (not an array)." << std::endl;
    }
    catch (const json::exception& e)
    {
        std::cerr << "[ERROR] Ошибка парсинга JSON: " << e.what() << std::endl;
    }
    return entries;
}

void Storage::savePasswords(const std::vector<PasswordEntry>& entries)
{
    json j = json::array();

    for (const auto& entry : entries)
        j.push_back(entry.to_json());

    std::ofstream file(passwordsStorage);
    if (file.is_open())
    {
        file << j.dump(4);
        std::cout << "[INFO] Данные успешно сохранены в " << passwordsStorage << std::endl;
    }
    else
        std::cerr << "[ERROR] Не удалось открыть файл " << passwordsStorage << " для записи." << std::endl;
}

void Storage::addNewPassword(const std::string& name, const std::string& login, const std::string& password, const std::string& msg)
{
    std::vector<PasswordEntry> entries = loadPasswords();

    try
    {
        auto key = AES256::generateKey();
        auto iv = AES256::generateIV();

        std::string encryptedPassword = AES256::encrypt(password, key, iv);
        std::string str_key = AES256::keyToHex(key);

        PasswordEntry newEntry{name, login, encryptedPassword, str_key, msg};
        entries.push_back(newEntry);
        
        savePasswords(entries);
        std::cout << "[INFO] Пароль для '" << name << "' успешно добавлен." << std::endl;
    } 
    catch (const std::exception& e)
    {
        std::cerr << "[ERROR] Ошибка при шифровании пароля: " << e.what() << std::endl;
    }
}

std::string Storage::getPassword(const std::string& name, const std::string& masterKey)
{
    std::vector<PasswordEntry> entries = loadPasswords();
    
    for (const auto& entry : entries)
    {
        if (entry.name == name)
        {
            try
            {
                auto key = AES256::hexToKey(entry.password_key);
                return AES256::decrypt(entry.password, key);
            }
            catch (const std::exception& e)
            {
                std::cerr << "[ERROR] Ошибка при дешифровании пароля: " << e.what() << std::endl;
                return "";
            }
        }
    }
    
    std::cerr << "[WARN] Запись с именем/URL '" << name << "' не найдена." << std::endl;
    return "";
}

bool Storage::deletePassword(const std::string& name)
{
    std::vector<PasswordEntry> entries = loadPasswords();
    size_t initial_size = entries.size();
    
    auto new_end = std::remove_if(entries.begin(), entries.end(), 
    [&name](const PasswordEntry& entry) { return entry.name == name; });

    entries.erase(new_end, entries.end());
    
    if (entries.size() < initial_size)
    {
        savePasswords(entries);
        std::cout << "[INFO] Запись '" << name << "' успешно удалена." << std::endl;
        return true;
    }
    else
    {
        std::cerr << "[WARN] Запись с именем/URL '" << name << "' не найдена." << std::endl;
        return false;
    }
}

void Storage::deletePasswords()
{
    std::vector<PasswordEntry> entries;
    
    savePasswords(entries);
    std::cout << "[INFO] Все записи паролей были удалены." << std::endl;
}