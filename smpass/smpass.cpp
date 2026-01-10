/**
 * @file smpass.cpp
 * @brief Password manager command-line tool
 * @author Tosa5656
 * @date Jan 4, 2026
 */

#include "../logger/logger.h"
#include "storage.h"
#include "sha256.h"
#include "aes256.h"
#include <iostream>
#include <sstream>
#include <cstring>

Storage storage;  ///< Глобальный экземпляр хранилища

// Просто выводит справочное сообщение
/**
 * @brief Display help information
 */
void help()
{
    std::cout << "Использование smpass:" << std::endl;
    std::cout << "smpass help - показать справочное сообщение" << std::endl;
    std::cout << "smpass add-password - добавить новый пароль" << std::endl;
    std::cout << "smpass delete-password - удалить пароль" << std::endl;
    std::cout << "smpass hash-sha256 <строка> - хэшировать строку с SHA256" << std::endl;
    std::cout << "smpass hash-aes256 <строка> - зашифровать строку с AES256" << std::endl;
}

// Запрашивает у пользователя детали пароля и добавляет его
/**
 * @brief Interactive function to add a new password
 */
void add_password()
{
    std::string name, login, password, message;

    std::cout << "Введите имя для пароля: ";
    std::cin >> name;

    std::cout << "Введите логин для пароля: ";
    std::cin >> login;

    std::cout << "Введите пароль: ";
    std::cin >> password;

    std::cout << "Введите информацию для пароля: ";
    std::cin >> message;

    storage.addNewPassword(name, login, password, message);
}

/**
 * @brief Interactive function to delete a password
 */
void delete_password()
{
    std::string name;
    std::cout << "Введите имя: ";
    std::cin >> name;
    storage.deletePassword(name);
}

/**
 * @brief Hash a string using SHA256
 * @param string String to hash
 */
void hash_sha256(std::string string)
{
    std::stringstream ss;
    ss << "Hashed string: " << SHA256::hashString(string);
    LogInfo(ss.str());
}

/**
 * @brief Encrypt a string using AES256
 * @param string String to encrypt
 */
void hash_aes256(std::string string)
{
    auto key = AES256::generateKey();
    auto iv = AES256::generateIV();

    std::string encryptedString = AES256::encrypt(string, key, iv);
    std::string str_key = AES256::keyToHex(key);

    std::stringstream ss;
    ss << "Encrypted string: " << encryptedString;
    LogInfo(ss.str());
    ss.str("");
    ss << "Encrypt key: " << str_key;
    LogInfo(ss.str());
}

/**
 * @brief Main entry point for smpass tool
 * @param argc Number of command-line arguments
 * @param argv Array of command-line arguments
 * @return Exit code (0 for success, 1 for error)
 */
int main(int argc, char* argv[])
{
    // Не заданы аргументы
    if (argc == 1) {
        std::cout << "Use smpass help to see how to use the program" << std::endl;
        return 0;
    }

    // Показать справку
    if (argc == 2 && strcmp(argv[1], "help") == 0) {
        help();
        return 0;
    }

    // Добавить новый пароль
    if (argc >= 2 && strcmp(argv[1], "add-password") == 0) {
        add_password();
        return 0;
    }

    // Удалить пароль
    if (argc >= 2 && strcmp(argv[1], "delete-password") == 0) {
        delete_password();
        return 0;
    }

    // Хэшировать с SHA256
    if (argc == 3 && strcmp(argv[1], "hash-sha256") == 0) {
        hash_sha256(argv[2]);
        return 0;
    }

    // Шифровать с AES256
    if (argc == 3 && strcmp(argv[1], "hash-aes256") == 0) {
        hash_aes256(argv[2]);
        return 0;
    }

    // Неизвестная команда
    std::stringstream ss;
    ss << "Error: unknown command: " << argv[1];
    LogError(ss.str());
    LogError("Use smpass help to see available commands");
    return 1;
}