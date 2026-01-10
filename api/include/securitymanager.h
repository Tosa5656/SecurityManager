#ifndef SECURITYMANAGER_H
#define SECURITYMANAGER_H

/**
 * @file securitymanager.h
 * @brief Security Manager C++ API - API для использования функций Security Manager
 * @author Tosa5656
 * @date 4 января, 2026
 */

#include "smpass_api.h"
#include "smnet_api.h"
#include "smlog_api.h"
#include "smssh_api.h"
#include "smdb_api.h"

namespace SecurityManager
{
    // Информация и версии API и его описании
    constexpr const char* VERSION = "1.0.0";
    constexpr const char* DESCRIPTION = "Security Manager C++ API";

    // Инициализация, очистка, получение основной информации
    bool initialize();
    void cleanup();
    const char* getVersion();
    const char* getDescription();
    std::string getLastError();
}

#endif