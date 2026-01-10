#ifndef SMNET_API_H
#define SMNET_API_H

/**
 * @file smnet_api.h
 * @brief Network Monitor API - Мониторинг сетевых интерфейсов
 * @author Tosa5656
 * @date 4 января, 2026
 */

#include <string>
#include <vector>
#include <memory>

namespace SecurityManager
{
    /**
    * @brief Коды ошибок
    */
    enum class NetworkError
    {
        SUCCESS = 0,
        NETWORK_ERROR = 1,
        PERMISSION_DENIED = 2,
        INVALID_ARGUMENT = 3,
        TIMEOUT = 4
    };

    /**
    * @brief Обвертка резултатов сетевых запросов
    */
    template<typename T>
    struct NetworkResult
    {
        NetworkError code;
        std::string message;
        T data;

        NetworkResult() : code(NetworkError::SUCCESS) {}
        NetworkResult(NetworkError c, const std::string& msg) : code(c), message(msg) {}
        NetworkResult(NetworkError c, const std::string& msg, const T& d) : code(c), message(msg), data(d) {}

        bool success() const { return code == NetworkError::SUCCESS; }
        operator bool() const { return success(); }
    };

    /**
    * @brief Результат сканирования портов
    */
    struct PortResult
    {
        int port;
        std::string service;
        std::string state; // open, closed, filtered
        std::string protocol; // tcp, udp
    };

    /**
    * @brief Информация о интернет соединении
    */
    struct ConnectionInfo
    {
        std::string local_address;
        std::string remote_address;
        std::string protocol;
        std::string state;
        int local_port;
        int remote_port;
        unsigned long bytes_sent;
        unsigned long bytes_received;
    };

    /**
    * @brief Информация об интернет устройстве
    */
    struct InterfaceInfo
    {
        std::string name;
        std::string address;
        std::string netmask;
        std::string mac_address;
        bool is_up;
        unsigned long rx_bytes;
        unsigned long tx_bytes;
    };

    /**
    * @brief Сетевая статистика
    */
    struct NetworkStats
    {
        unsigned long long total_bytes_received;
        unsigned long long total_bytes_sent;
        unsigned long long total_packets_received;
        unsigned long long total_packets_sent;
        std::vector<InterfaceInfo> interfaces;
    };

    /**
    * @brief Класс сетевого монитора
    */
    class NetworkMonitor
    {
    public:
        NetworkMonitor();
        ~NetworkMonitor();

        /**
        * @brief Сканирование портов на localhost
        * @param start_port Стартовый порт для сканирования (по умолчанию: 1)
        * @param end_port Конечный порт для сканирования (по умолчанию: 1024)
        * @return std::vector с результатами сканирования портов
        */
        NetworkResult<std::vector<PortResult>> scanPorts(int start_port = 1, int end_port = 1024);

        /**
        * @brief Получить активные сетевые подключения
        * @return std::vector с сетевыми подключениями
        */
        NetworkResult<std::vector<ConnectionInfo>> getActiveConnections();

        /**
        * @brief Получить информацию о сетевых интерфейсах
        * @return std::vector с информацией о сетевых интерфейсах
        */
        NetworkResult<std::vector<InterfaceInfo>> getNetworkInterfaces();

        /**
        * @brief Получить статистику сети
        * @return Статистика сети
        */
        NetworkResult<NetworkStats> getNetworkStats();

        /**
        * @brief Проверить открыт ли порт на удаленом сервере
        * @param host IP сервера
        * @param port Порт дл проверки
        * @return Открыт/Закрыт
        */
        NetworkResult<bool> isPortOpen(const std::string& host, int port);

        /**
        * @brief Получить имя удаленого сервера
        * @param ip_address IP адрес сервера
        * @return Имя сервера/ошибка
        */
        NetworkResult<std::string> resolveHostname(const std::string& ip_address);
    private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };
}

#endif