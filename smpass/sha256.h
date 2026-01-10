/**
 * @file sha256.h
 * @brief SHA-256 hashing implementation with salt
 * @author Tosa5656
 * @date Jan 3, 2026
 */

#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>
#include "../logger/logger.h"

/**
 * @brief Класс хэширования SHA-256 с поддержкой соли
 */
class SHA256
{
private:
    static constexpr int SALT_SIZE = 32;    /**< Размер соли для хэширования паролей */
    static constexpr int HASH_SIZE = 32;    /**< Размер хэша SHA-256 */
    static constexpr int KEY_LENGTH = 32;   /**< Длина производного ключа */
    static constexpr int ITERATIONS = 100000; /**< Итерации PBKDF2 */

public:
    /**
     * @brief Generate random salt for password hashing
     * @return Vector containing the random salt
     */
    static std::vector<unsigned char> generateSalt()
    {
        std::vector<unsigned char> salt(SALT_SIZE);
        if (RAND_bytes(salt.data(), SALT_SIZE) != 1)
        {
            LogError("Error generating salt!");
            return salt;
        }

        return salt;
    }

    /**
     * @brief Hash string with provided salt using PBKDF2
     * @param string Input string to hash
     * @param salt Salt for hashing
     * @return Hex-encoded hash with salt prefix
     */
    static std::string hashString(const std::string& string, const std::vector<unsigned char>& salt)
    {
        std::vector<unsigned char> key(KEY_LENGTH);

        if (PKCS5_PBKDF2_HMAC(string.c_str(), string.length(),salt.data(), salt.size(),ITERATIONS,EVP_sha256(),KEY_LENGTH,key.data()) != 1)
        {
            LogError("Failed to hash string!");
            return "";
        }

        std::vector<unsigned char> result;
        result.reserve(salt.size() + key.size());
        result.insert(result.end(), salt.begin(), salt.end());
        result.insert(result.end(), key.begin(), key.end());

        return bytesToHex(result);
    }

    /**
     * @brief Hash string with auto-generated salt
     * @param string Input string to hash
     * @return Hex-encoded hash with salt prefix
     */
    static std::string hashString(const std::string& string)
    {
        auto salt = generateSalt();
        return hashString(string, salt);
    }

    // Проверка строки
    static bool verifyString(const std::string& string, const std::string& storedHash)
    {
        try
        {
            // Шестнадцатеричное в байты
            auto storedBytes = hexToBytes(storedHash);
            
            // Проверка сохраненных байтов
            if (storedBytes.size() != SALT_SIZE + KEY_LENGTH)
                return false;
            
            // Получение соли
            std::vector<unsigned char> salt(storedBytes.begin(), storedBytes.begin() + SALT_SIZE);
            // Хэширование
            std::string newHash = hashString(string, salt);
            
            // Проверка
            return constantTimeCompare(newHash, storedHash);
        }
        catch (...)
        {
            return false;
        }
    }
private:
    /**
     * @brief Convert bytes to hexadecimal string
     * @param bytes Input bytes
     * @return Hexadecimal string representation
     */
    static std::string bytesToHex(const std::vector<unsigned char>& bytes)
    {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        
        for (unsigned char byte : bytes)
            ss << std::setw(2) << static_cast<int>(byte);
        
        return ss.str();
    }

    /**
     * @brief Convert hexadecimal string to bytes
     * @param hex Input hexadecimal string
     * @return Vector of bytes
     */
    static std::vector<unsigned char> hexToBytes(const std::string& hex)
    {
        std::vector<unsigned char> bytes;
        
        if (hex.length() % 2 != 0)
            throw std::runtime_error("Wrong hex string");
        
        for (size_t i = 0; i < hex.length(); i += 2)
        {
            std::string byteString = hex.substr(i, 2);
            unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
            bytes.push_back(byte);
        }
        
        return bytes;
    }

    /**
     * @brief Constant-time string comparison for security
     * @param a First string
     * @param b Second string
     * @return True if strings are equal
     */
    static bool constantTimeCompare(const std::string& a, const std::string& b)
    {
        if (a.length() != b.length())
            return false;
        
        unsigned char result = 0;
        for (size_t i = 0; i < a.length(); i++)
            result |= a[i] ^ b[i];
        
        return result == 0;
    }
};