/**
 * @file smnet_api.cpp
 * @brief Реализация Network Monitor API
 * @author Tosa5656
 * @date 4 января, 2026
 */

#include "smnet_api.h"
#include "../../smnet/networkStats.h"
#include "../../smnet/portScanner.h"
#include <fstream>
#include <sstream>
#include <regex>
#include <set>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <linux/if.h>
#include <sys/ioctl.h>

namespace SecurityManager
{

/**
 * @brief Приватная реализация класса NetworkMonitor
 */
class NetworkMonitor::Impl
{
public:
    /**
     * @brief Сканирует порты в указанном диапазоне
     * @param start_port Стартовый порт
     * @param end_port Конечный порт
     * @return Вектор с результатами сканирования портов
     */
    std::vector<PortResult> scanPorts(int start_port, int end_port)
    {
        std::vector<PortResult> results;
        PortScanner scanner;
        auto connections = scanner.scanConnections();

        std::map<int, std::string> port_services = {
            {22, "ssh"}, {23, "telnet"}, {25, "smtp"}, {53, "dns"},
            {80, "http"}, {110, "pop3"}, {143, "imap"}, {443, "https"},
            {993, "imaps"}, {995, "pop3s"}, {3306, "mysql"}, {5432, "postgresql"}
        };

        std::set<int> open_ports;
        for (const auto& conn : connections)
        {
            if (conn.state == "LISTEN" || conn.state == "ESTABLISHED")
            {
                if (conn.local_port >= start_port && conn.local_port <= end_port)
                    open_ports.insert(conn.local_port);
            }
        }

        for (int port = start_port; port <= end_port; port++)
        {
            PortResult result;
            result.port = port;
            result.protocol = "tcp";

            if (open_ports.count(port))
                result.state = "open";
            else
                result.state = isPortOpen("127.0.0.1", port) ? "open" : "closed";

            if (port_services.count(port))
                result.service = port_services[port];
            else
                result.service = "unknown";

            results.push_back(result);
        }

        return results;
    }

    std::vector<ConnectionInfo> getActiveConnections()
    {
        std::vector<ConnectionInfo> connections;
        PortScanner scanner;
        auto scanner_connections = scanner.scanConnections();

        for (const auto& conn : scanner_connections)
        {
            ConnectionInfo info;
            info.local_address = conn.local_address;
            info.local_port = conn.local_port;
            info.remote_address = conn.remote_address;
            info.remote_port = conn.remote_port;
            info.protocol = conn.protocol;
            info.state = conn.state;
            info.bytes_sent = 0;
            info.bytes_received = 0;
            connections.push_back(info);
        }

        return connections;
    }

    std::vector<InterfaceInfo> getNetworkInterfaces()
    {
        std::vector<InterfaceInfo> interfaces;

        struct ifaddrs *ifaddrs_ptr, *ifa;
        if (getifaddrs(&ifaddrs_ptr) == -1)
            return interfaces;

        ::NetworkStats stats_manager;
        stats_manager.RefreshStats();

        for (ifa = ifaddrs_ptr; ifa != nullptr; ifa = ifa->ifa_next)
        {
            if (!ifa->ifa_addr)
                continue;

            InterfaceInfo info;
            info.name = ifa->ifa_name;

            if (ifa->ifa_addr->sa_family == AF_INET)
            {
                struct sockaddr_in* sin = (struct sockaddr_in*)ifa->ifa_addr;
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &sin->sin_addr, ip_str, INET_ADDRSTRLEN);
                info.address = ip_str;

                if (ifa->ifa_netmask)
                {
                    struct sockaddr_in* mask = (struct sockaddr_in*)ifa->ifa_netmask;
                    char mask_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &mask->sin_addr, mask_str, INET_ADDRSTRLEN);
                    info.netmask = mask_str;
                }
            }
            else if (ifa->ifa_addr->sa_family == AF_INET6)
            {
                continue;
            }
            else
            {
                continue;
            }

            int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
            if (sockfd >= 0)
            {
                struct ifreq ifr;
                strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ - 1);
                ifr.ifr_name[IFNAMSIZ - 1] = '\0';

                if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == 0)
                {
                    char mac_str[18];
                    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                            (unsigned char)ifr.ifr_hwaddr.sa_data[0],
                            (unsigned char)ifr.ifr_hwaddr.sa_data[1],
                            (unsigned char)ifr.ifr_hwaddr.sa_data[2],
                            (unsigned char)ifr.ifr_hwaddr.sa_data[3],
                            (unsigned char)ifr.ifr_hwaddr.sa_data[4],
                            (unsigned char)ifr.ifr_hwaddr.sa_data[5]);
                    info.mac_address = mac_str;
                }

                if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) == 0)
                    info.is_up = (ifr.ifr_flags & IFF_UP) != 0;

                close(sockfd);
            }

            auto iface_stats = stats_manager.GetInterfaceStats(info.name);
            if (!iface_stats.empty())
            {
                info.rx_bytes = iface_stats.count("rx_bytes") ? iface_stats.at("rx_bytes") : 0;
                info.tx_bytes = iface_stats.count("tx_bytes") ? iface_stats.at("tx_bytes") : 0;
            }
            else
            {
                info.rx_bytes = 0;
                info.tx_bytes = 0;
            }

            bool exists = false;
            for (auto& existing : interfaces)
            {
                if (existing.name == info.name && existing.address == info.address)
                {
                    exists = true;
                    break;
                }
            }

            if (!exists && !info.address.empty())
                interfaces.push_back(info);
        }

        freeifaddrs(ifaddrs_ptr);
        return interfaces;
    }

    NetworkStats getNetworkStats()
    {
        SecurityManager::NetworkStats result = {0};

        ::NetworkStats stats_manager;
        stats_manager.RefreshStats();
        auto total_stats = stats_manager.GetTotalStats();

        result.total_bytes_received = total_stats.count("rx_bytes") ? total_stats.at("rx_bytes") : 0;
        result.total_bytes_sent = total_stats.count("tx_bytes") ? total_stats.at("tx_bytes") : 0;
        result.total_packets_received = total_stats.count("rx_packets") ? total_stats.at("rx_packets") : 0;
        result.total_packets_sent = total_stats.count("tx_packets") ? total_stats.at("tx_packets") : 0;
        result.interfaces = getNetworkInterfaces();

        return result;
    }

    bool isPortOpen(const std::string& host, int port)
    {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0)
            return false;

        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        inet_pton(AF_INET, host.c_str(), &server_addr.sin_addr);

        bool result = (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0);
        close(sock);
        return result;
    }

    std::string resolveHostname(const std::string& ip_address)
    {
        struct sockaddr_in sa;
        char host[1024];
        char service[20];

        sa.sin_family = AF_INET;
        inet_pton(AF_INET, ip_address.c_str(), &sa.sin_addr);

        if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host),
                       service, sizeof(service), 0) == 0)
            return std::string(host);

        return ip_address;
    }

private:
    std::pair<std::string, int> parseAddress(const std::string& hex_addr)
    {
        size_t colon_pos = hex_addr.find(':');
        if (colon_pos == std::string::npos)
            throw std::runtime_error("Invalid address format");

        std::string ip_hex = hex_addr.substr(0, colon_pos);
        std::string port_hex = hex_addr.substr(colon_pos + 1);

        if (ip_hex.length() != 8)
            throw std::runtime_error("Invalid IP format");

        std::string ip_str;
        for (int i = 6; i >= 0; i -= 2)
        {
            std::string octet = ip_hex.substr(i, 2);
            ip_str += std::to_string(std::stoi(octet, nullptr, 16));
            if (i > 0)
                ip_str += ".";
        }

        int port = std::stoi(port_hex, nullptr, 16);
        return {ip_str, port};
    }

    std::string getStateString(int state)
    {
        static const char* states[] = {
            "UNKNOWN", "ESTABLISHED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1",
            "FIN_WAIT2", "TIME_WAIT", "CLOSE", "CLOSE_WAIT", "LAST_ACK",
            "LISTEN", "CLOSING"
        };

        if (state >= 0 && state < 12)
            return states[state];

        return "UNKNOWN";
    }
};

/**
 * @brief Конструктор - инициализирует сетевой монитор
 */
NetworkMonitor::NetworkMonitor() : impl_(std::make_unique<Impl>())
{
}

/**
 * @brief Деструктор
 */
NetworkMonitor::~NetworkMonitor() = default;

/**
 * @brief Сканирует порты в указанном диапазоне
 * @param start_port Стартовый порт
 * @param end_port Конечный порт
 * @return Результат с вектором результатов сканирования или ошибкой
 */
NetworkResult<std::vector<PortResult>> NetworkMonitor::scanPorts(int start_port, int end_port)
{
    try
    {
        auto results = impl_->scanPorts(start_port, end_port);
        return NetworkResult<std::vector<PortResult>>(NetworkError::SUCCESS, "", results);
    }
    catch (const std::exception& e)
    {
        return NetworkResult<std::vector<PortResult>>(NetworkError::NETWORK_ERROR, e.what());
    }
}

/**
 * @brief Получает информацию об активных сетевых соединениях
 * @return Результат с вектором активных соединений или ошибкой
 */
NetworkResult<std::vector<ConnectionInfo>> NetworkMonitor::getActiveConnections()
{
    try
    {
        auto connections = impl_->getActiveConnections();
        return NetworkResult<std::vector<ConnectionInfo>>(NetworkError::SUCCESS, "", connections);
    }
    catch (const std::exception& e)
    {
        return NetworkResult<std::vector<ConnectionInfo>>(NetworkError::NETWORK_ERROR, e.what());
    }
}

/**
 * @brief Получает информацию о сетевых интерфейсах
 * @return Результат с вектором информации о сетевых интерфейсах или ошибкой
 */
NetworkResult<std::vector<InterfaceInfo>> NetworkMonitor::getNetworkInterfaces()
{
    try
    {
        auto interfaces = impl_->getNetworkInterfaces();
        return NetworkResult<std::vector<InterfaceInfo>>(NetworkError::SUCCESS, "", interfaces);
    }
    catch (const std::exception& e)
    {
        return NetworkResult<std::vector<InterfaceInfo>>(NetworkError::NETWORK_ERROR, e.what());
    }
}

/**
 * @brief Получает сетевую статистику
 * @return Результат со статистикой сети или ошибкой
 */
NetworkResult<NetworkStats> NetworkMonitor::getNetworkStats()
{
    try
    {
        auto stats = impl_->getNetworkStats();
        return NetworkResult<NetworkStats>(NetworkError::SUCCESS, "", stats);
    }
    catch (const std::exception& e)
    {
        return NetworkResult<NetworkStats>(NetworkError::NETWORK_ERROR, e.what());
    }
}

/**
 * @brief Проверяет, открыт ли порт на указанном хосте
 * @param host Имя хоста или IP адрес
 * @param port Номер порта для проверки
 * @return Результат с true, если порт открыт, false в противном случае, или ошибкой
 */
NetworkResult<bool> NetworkMonitor::isPortOpen(const std::string& host, int port)
{
    try
    {
        bool result = impl_->isPortOpen(host, port);
        return NetworkResult<bool>(NetworkError::SUCCESS, "", result);
    }
    catch (const std::exception& e)
    {
        return NetworkResult<bool>(NetworkError::NETWORK_ERROR, e.what(), false);
    }
}

/**
 * @brief Резолвит IP адрес в имя хоста
 * @param ip_address IP адрес для резолвинга
 * @return Результат с именем хоста или ошибкой
 */
NetworkResult<std::string> NetworkMonitor::resolveHostname(const std::string& ip_address)
{
    try
    {
        auto hostname = impl_->resolveHostname(ip_address);
        return NetworkResult<std::string>(NetworkError::SUCCESS, "", hostname);
    }
    catch (const std::exception& e)
    {
        return NetworkResult<std::string>(NetworkError::NETWORK_ERROR, e.what());
    }
}

} // namespace SecurityManager
