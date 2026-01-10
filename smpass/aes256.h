/**
 * @file aes256.h
 * @brief AES-256 encryption/decryption implementation
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
#include <openssl/err.h>
#include <iomanip>
#include <sstream>
#include "../logger/logger.h"

#define AES256_KEY_TO_STR(key) key.begin(), key.end()

/**
 * @brief Класс шифрования/дешифрования AES-256 с использованием OpenSSL
 *
 * Предоставляет безопасное шифрование и дешифрование с использованием режима AES-256-GCM.
 */
class AES256
{
private:
    static constexpr int KEY_SIZE = 32;     /**< AES-256 key size (256 bits) */
    static constexpr int IV_SIZE = 16;      /**< Initialization vector size */
    static constexpr int BLOCK_SIZE = 16;   /**< AES block size */
    static constexpr int TAG_SIZE = 16;     /**< GCM authentication tag size */

public:
    /**
     * @brief Generate a random AES-256 encryption key
     * @return Vector containing the 256-bit key
     */
    static std::vector<unsigned char> generateKey()
    {
        std::vector<unsigned char> key(KEY_SIZE);
        if (RAND_bytes(key.data(), KEY_SIZE) != 1)
            throw std::runtime_error("Error to generate key");
        return key;
    }

    /**
     * @brief Generate a random initialization vector
     * @return Vector containing the 128-bit IV
     */
    static std::vector<unsigned char> generateIV()
    {
        std::vector<unsigned char> iv(IV_SIZE);
        if (RAND_bytes(iv.data(), IV_SIZE) != 1)
            throw std::runtime_error("Error to generate IV");
        return iv;
    }

    /**
     * @brief Encrypt plaintext using AES-256-GCM
     * @param plaintext Text to encrypt
     * @param key Encryption key (256 bits)
     * @param iv Initialization vector (128 bits)
     * @return Base64-encoded encrypted data with IV and authentication tag
     */
    static std::string encrypt(const std::string& plaintext, const std::vector<unsigned char>& key,const std::vector<unsigned char>& iv)
    {
        if (key.size() != KEY_SIZE)
            throw std::runtime_error("Wrong key size");
        if (iv.size() != IV_SIZE)
            throw std::runtime_error("Wrong IV size");

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
            throw std::runtime_error("Error to create ctx context");

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Error to initialize encryption");
        }

        std::vector<unsigned char> ciphertext(plaintext.size() + BLOCK_SIZE);
        int len = 0;
        int ciphertext_len = 0;

        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (const unsigned char*)plaintext.data(),  plaintext.size()) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Error to encrypt");
        }
        ciphertext_len = len;

        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Error to finalize encryption");
        }
        ciphertext_len += len;

        std::vector<unsigned char> tag(TAG_SIZE);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data()) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to get tag");
        }

        EVP_CIPHER_CTX_free(ctx);

        std::vector<unsigned char> result;
        result.reserve(iv.size() + tag.size() + ciphertext_len);
        result.insert(result.end(), iv.begin(), iv.end());
        result.insert(result.end(), tag.begin(), tag.end());
        result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);

        return bytesToHex(result);
    }

    /**
     * @brief Decrypt ciphertext using AES-256-GCM
     * @param encryptedHex Base64-encoded encrypted data with IV and tag
     * @param key Decryption key (256 bits)
     * @return Decrypted plaintext
     */
    static std::string decrypt(const std::string& encryptedHex, const std::vector<unsigned char>& key)
    {
        auto encryptedBytes = hexToBytes(encryptedHex);
        
        if (encryptedBytes.size() < IV_SIZE + TAG_SIZE) {
            throw std::runtime_error("Incorrect data to decrypt");
        }

        std::vector<unsigned char> iv(encryptedBytes.begin(), encryptedBytes.begin() + IV_SIZE);
        std::vector<unsigned char> tag(encryptedBytes.begin() + IV_SIZE,encryptedBytes.begin() + IV_SIZE + TAG_SIZE);
        std::vector<unsigned char> ciphertext(encryptedBytes.begin() + IV_SIZE + TAG_SIZE,encryptedBytes.end());

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
        {
            throw std::runtime_error("Failed to create context");
        }

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), iv.data()) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize decryption");
        }

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag.data()) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to set tag");
        }

        std::vector<unsigned char> plaintext(ciphertext.size() + BLOCK_SIZE);
        int len = 0;
        int plaintext_len = 0;

        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed decrypt data");
        }
        plaintext_len = len;

        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len) <= 0)
        {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Error to auth or invalid data");
        }
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
    }

    static std::pair<std::string, std::vector<unsigned char>> encryptSimple(const std::string& plaintext)
    {
        auto key = generateKey();
        auto iv = generateIV();
        std::string encrypted = encrypt(plaintext, key, iv);
        return {encrypted, key};
    }

    static std::string bytesToHex(const std::vector<unsigned char>& bytes)
    {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (unsigned char byte : bytes)
            ss << std::setw(2) << static_cast<int>(byte);
        return ss.str();
    }

    static std::vector<unsigned char> hexToBytes(const std::string& hex)
    {
        std::vector<unsigned char> bytes;
        if (hex.length() % 2 != 0)
            throw std::runtime_error("Unknown hex string");
        for (size_t i = 0; i < hex.length(); i += 2)
        {
            std::string byteString = hex.substr(i, 2);
            unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
            bytes.push_back(byte);
        }
        return bytes;
    }

    static std::string keyToHex(const std::vector<unsigned char>& key)
    {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (unsigned char byte : key)
            ss << std::setw(2) << static_cast<int>(byte);
        return ss.str();
    }

    static std::vector<unsigned char> hexToKey(const std::string& hex)
    {
        std::vector<unsigned char> key;
        
        if (hex.length() % 2 != 0)
            throw std::runtime_error("Unknown hex string (odd length)");
        
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byteString = hex.substr(i, 2);
            unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
            key.push_back(byte);
        }
        
        return key;
    }
};