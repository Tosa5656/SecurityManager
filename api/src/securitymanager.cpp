/**
 * @file securitymanager.cpp
 * @brief Реализация Security Manager API
 * @author Tosa5656
 * @date 4 января, 2026
 */

#include "securitymanager.h"
#include <iostream>

// Флаг инициализации
static bool g_initialized = false;

namespace SecurityManager
{
    /**
    * @brief Инициализация Security Manager API
    * @return Удача/Неудача
    */
    bool initialize()
    {
        if (g_initialized)
            return true;

        g_initialized = true;
        return true;
    }

    /**
    * @brief Очистка Security Manager API
    */
    void cleanup()
    {
        if (!g_initialized)
            return;

        g_initialized = false;
    }

    /**
    * @brief Полчить версию Security Manager API
    * @return Версия
    */
    const char* getVersion()
    {
        return VERSION;
    }

    /**
    * @brief Получить описание Security Manager API
    * @return Описание
    */
    const char* getDescription()
    {
        return DESCRIPTION;
    }

    /**
    * @brief Получить последнюю ошибку
    * @return Сообщение об ошибке
    */
    std::string getLastError()
    {
        return "No error information available";
    }
}