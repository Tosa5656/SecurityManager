/**
 * @file networkStats.h
 * @brief Мониторинг статистики сетевых интерфейсов
 * @author Tosa5656
 * @date 2 января, 2026
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <algorithm>
#include <numeric>
#include <thread>
#include <atomic>
#include <mutex>

/**
 * @brief Класс мониторинга сетевой статистики
 *
 * Мониторит статистику сетевых интерфейсов включая использование полосы пропускания,
 * счетчики пакетов, ошибки и рассчитывает скорости передачи.
 */
class NetworkStats {
private:
    /**
     * @brief Structure holding statistics for a single network interface
     */
    struct InterfaceStats {
        uint64_t rx_bytes = 0;
        uint64_t tx_bytes = 0;
        uint64_t rx_packets = 0;
        uint64_t tx_packets = 0;
        uint64_t rx_errors = 0;
        uint64_t tx_errors = 0;
        uint64_t rx_dropped = 0;
        uint64_t tx_dropped = 0;
        uint64_t rx_fifo = 0;
        uint64_t tx_fifo = 0;
        uint64_t rx_frame = 0;
        uint64_t tx_colls = 0;
        
        // Для расчета скорости
        uint64_t last_rx_bytes = 0;
        uint64_t last_tx_bytes = 0;
        uint64_t last_rx_packets = 0;
        uint64_t last_tx_packets = 0;
        std::chrono::steady_clock::time_point last_update;
        
        double rx_speed_bps = 0.0;
        double tx_speed_bps = 0.0;
        double rx_pps = 0.0;
        double tx_pps = 0.0;
        
        void update_speed()
        {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                now - last_update).count();

            if (elapsed > 0)
            {
                rx_speed_bps = (rx_bytes - last_rx_bytes) * 8.0 / elapsed;
                tx_speed_bps = (tx_bytes - last_tx_bytes) * 8.0 / elapsed;
                rx_pps = (rx_packets - last_rx_packets) * 1.0 / elapsed;
                tx_pps = (tx_packets - last_tx_packets) * 1.0 / elapsed;

                last_rx_bytes = rx_bytes;
                last_tx_bytes = tx_bytes;
                last_rx_packets = rx_packets;
                last_tx_packets = tx_packets;
                last_update = now;
            }
        }
    };
    
    // Структура для статистики протокола
    struct ProtocolStats {
        uint64_t packets = 0;
        uint64_t bytes = 0;
        uint64_t errors = 0;
        
        // Для расчета скорости
        uint64_t last_packets = 0;
        uint64_t last_bytes = 0;
        std::chrono::steady_clock::time_point last_update;
        
        double packet_rate = 0.0;
        double byte_rate = 0.0;
        
        void update_rate()
        {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                now - last_update).count();

            if (elapsed > 0)
            {
                packet_rate = (packets - last_packets) * 1.0 / elapsed;
                byte_rate = (bytes - last_bytes) * 1.0 / elapsed;

                last_packets = packets;
                last_bytes = bytes;
                last_update = now;
            }
        }
    };
    
    // Статистика по интерфейсам
    std::unordered_map<std::string, InterfaceStats> interface_stats_;
    
    // Статистика по протоколам (глобальная и по интерфейсам)
    std::unordered_map<std::string, ProtocolStats> global_protocol_stats_;
    std::unordered_map<std::string, 
        std::unordered_map<std::string, ProtocolStats>> interface_protocol_stats_;
    
    // Мьютекс для потокобезопасности
    mutable std::mutex stats_mutex_;
    
    // Флаги и состояния
    std::atomic<bool> is_monitoring_{false};
    std::thread monitoring_thread_;
    
    // Вспомогательные методы
    std::string format_bytes(uint64_t bytes) const
    {
        const char* units[] = {"B", "KB", "MB", "GB", "TB"};
        double value = bytes;
        int unit = 0;

        while (value >= 1024.0 && unit < 4)
        {
            value /= 1024.0;
            unit++;
        }

        std::stringstream ss;
        if (unit == 0)
            ss << bytes << " B";
        else
            ss << std::fixed << std::setprecision(2) << value << " " << units[unit];
        return ss.str();
    }
    
    std::string format_speed(double bps) const
    {
        const char* units[] = {"bps", "Kbps", "Mbps", "Gbps"};
        double value = bps;
        int unit = 0;

        while (value >= 1000.0 && unit < 3)
        {
            value /= 1000.0;
            unit++;
        }

        std::stringstream ss;
        ss << std::fixed << std::setprecision(2) << value << " " << units[unit];
        return ss.str();
    }
    
    void parse_proc_net_dev()
    {
        std::ifstream file("/proc/net/dev");
        if (!file.is_open())
            return;

        std::lock_guard<std::mutex> lock(stats_mutex_);

        std::string line;
        std::getline(file, line);
        std::getline(file, line);

        while (std::getline(file, line))
        {
            size_t pos = line.find_first_not_of(' ');
            if (pos != std::string::npos)
                line = line.substr(pos);

            pos = line.find(':');
            if (pos == std::string::npos)
                continue;

            std::string interface_name = line.substr(0, pos);
            std::string stats_str = line.substr(pos + 1);

            if (interface_name.find("lo") == 0)
                continue;

            std::istringstream iss(stats_str);
            InterfaceStats stats;

            iss >> stats.rx_bytes >> stats.rx_packets >> stats.rx_errors
                >> stats.rx_dropped >> stats.rx_fifo >> stats.rx_frame
                >> stats.tx_bytes >> stats.tx_packets >> stats.tx_errors
                >> stats.tx_dropped >> stats.tx_fifo >> stats.tx_colls;

            auto it = interface_stats_.find(interface_name);
            if (it != interface_stats_.end())
            {
                stats.last_rx_bytes = it->second.last_rx_bytes;
                stats.last_tx_bytes = it->second.last_tx_bytes;
                stats.last_rx_packets = it->second.last_rx_packets;
                stats.last_tx_packets = it->second.last_tx_packets;
                stats.last_update = it->second.last_update;
            }
            else
            {
                stats.last_update = std::chrono::steady_clock::now();
            }

            stats.update_speed();
            interface_stats_[interface_name] = stats;
        }
    }
    
    void parse_proc_net_snmp() {
        std::ifstream file("/proc/net/snmp");
        if (!file.is_open()) return;
        
        std::lock_guard<std::mutex> lock(stats_mutex_);
        
        std::string line;
        std::string current_protocol;
        
        while (std::getline(file, line)) {
            // Ищем заголовки протоколов
            if (line.find("Ip:") == 0 || line.find("Icmp:") == 0 || 
                line.find("IcmpMsg:") == 0 || line.find("Tcp:") == 0 ||
                line.find("Udp:") == 0 || line.find("UdpLite:") == 0) {
                
                current_protocol = line.substr(0, line.find(':'));
                std::getline(file, line); // Читаем строку с данными
                
                std::istringstream iss(line);
                std::vector<uint64_t> values;
                uint64_t val;
                
                while (iss >> val) {
                    values.push_back(val);
                }
                
                if (values.size() >= 2) {
                    ProtocolStats& stats = global_protocol_stats_[current_protocol];
                    stats.packets = values[0];   // InDatagrams/InMsgs
                    stats.bytes = values[1];     // InOctets
                    stats.update_rate();
                }
            }
        }
    }
    
    void monitoring_loop() {
        while (is_monitoring_) {
            parse_proc_net_dev();
            parse_proc_net_snmp();
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }

public:
    /**
     * @brief Default constructor
     */
    NetworkStats() = default;

    /**
     * @brief Destructor - stops monitoring if running
     */
    ~NetworkStats() {
        StopMonitoring();
    }

    /**
     * @brief Start real-time monitoring of network statistics
     * @param update_interval_ms Update interval in milliseconds (default 1000ms)
     */
    void StartMonitoring(int update_interval_ms = 1000) {
        if (is_monitoring_) return;
        
        is_monitoring_ = true;
        monitoring_thread_ = std::thread([this, update_interval_ms]() {
            while (is_monitoring_) {
                parse_proc_net_dev();
                parse_proc_net_snmp();
                std::this_thread::sleep_for(std::chrono::milliseconds(update_interval_ms));
            }
        });
    }

    /**
     * @brief Stop real-time monitoring
     */
    void StopMonitoring() {
        if (!is_monitoring_) return;

        is_monitoring_ = false;
        if (monitoring_thread_.joinable()) {
            monitoring_thread_.join();
        }
    }

    /**
     * @brief Manually refresh network statistics
     */
    void RefreshStats() {
        parse_proc_net_dev();
        parse_proc_net_snmp();
    }

    /**
     * @brief Get list of all network interfaces
     * @return Vector of interface names
     */
    std::vector<std::string> GetInterfaces() const {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        std::vector<std::string> interfaces;
        
        for (const auto& [name, _] : interface_stats_) {
            interfaces.push_back(name);
        }
        
        return interfaces;
    }
    
    // Получить статистику интерфейса
    std::unordered_map<std::string, uint64_t> GetInterfaceStats(
        const std::string& interface_name) const {
        
        std::lock_guard<std::mutex> lock(stats_mutex_);
        std::unordered_map<std::string, uint64_t> result;
        
        auto it = interface_stats_.find(interface_name);
        if (it != interface_stats_.end()) {
            const auto& stats = it->second;
            result["rx_bytes"] = stats.rx_bytes;
            result["tx_bytes"] = stats.tx_bytes;
            result["rx_packets"] = stats.rx_packets;
            result["tx_packets"] = stats.tx_packets;
            result["rx_errors"] = stats.rx_errors;
            result["tx_errors"] = stats.tx_errors;
        }
        
        return result;
    }
    
    // Получить скорость интерфейса
    std::unordered_map<std::string, double> GetInterfaceSpeed(
        const std::string& interface_name) const {
        
        std::lock_guard<std::mutex> lock(stats_mutex_);
        std::unordered_map<std::string, double> result;
        
        auto it = interface_stats_.find(interface_name);
        if (it != interface_stats_.end()) {
            const auto& stats = it->second;
            result["rx_speed_bps"] = stats.rx_speed_bps;
            result["tx_speed_bps"] = stats.tx_speed_bps;
            result["rx_pps"] = stats.rx_pps;
            result["tx_pps"] = stats.tx_pps;
        }
        
        return result;
    }
    
    // Получить статистику протокола
    std::unordered_map<std::string, uint64_t> GetProtocolStats(
        const std::string& protocol) const {
        
        std::lock_guard<std::mutex> lock(stats_mutex_);
        std::unordered_map<std::string, uint64_t> result;
        
        auto it = global_protocol_stats_.find(protocol);
        if (it != global_protocol_stats_.end()) {
            const auto& stats = it->second;
            result["packets"] = stats.packets;
            result["bytes"] = stats.bytes;
            result["errors"] = stats.errors;
        }
        
        return result;
    }
    
    // Получить скорость протокола
    std::unordered_map<std::string, double> GetProtocolRate(
        const std::string& protocol) const {
        
        std::lock_guard<std::mutex> lock(stats_mutex_);
        std::unordered_map<std::string, double> result;
        
        auto it = global_protocol_stats_.find(protocol);
        if (it != global_protocol_stats_.end()) {
            const auto& stats = it->second;
            result["packet_rate"] = stats.packet_rate;
            result["byte_rate"] = stats.byte_rate;
        }
        
        return result;
    }
    
    // Получить суммарную статистику по всем интерфейсам
    std::unordered_map<std::string, uint64_t> GetTotalStats() const {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        std::unordered_map<std::string, uint64_t> total;
        
        for (const auto& [_, stats] : interface_stats_) {
            total["rx_bytes"] += stats.rx_bytes;
            total["tx_bytes"] += stats.tx_bytes;
            total["rx_packets"] += stats.rx_packets;
            total["tx_packets"] += stats.tx_packets;
            total["rx_errors"] += stats.rx_errors;
            total["tx_errors"] += stats.tx_errors;
        }
        
        return total;
    }
    
    // Вывести статистику интерфейсов в таблицу
    void PrintInterfaceStatsTable(bool show_speed = false) const {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        
        if (interface_stats_.empty()) {
            std::cout << "No interface statistics available.\n";
            return;
        }
        
        std::cout << "\x1b[1;36m╔══════════════════════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                          INTERFACE STATISTICS                              ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════════════════════════╣\n";
        
        if (!show_speed) {
            std::cout << "║ " << std::setw(12) << std::left << "Interface"
                      << std::setw(16) << "RX Bytes"
                      << std::setw(16) << "TX Bytes"
                      << std::setw(12) << "RX Pkts"
                      << std::setw(12) << "TX Pkts"
                      << std::setw(10) << "RX Err"
                      << std::setw(10) << "TX Err" << " ║\n";
        } else {
            std::cout << "║ " << std::setw(12) << std::left << "Interface"
                      << std::setw(16) << "RX Speed"
                      << std::setw(16) << "TX Speed"
                      << std::setw(12) << "RX PPS"
                      << std::setw(12) << "TX PPS"
                      << std::setw(10) << "RX Err"
                      << std::setw(10) << "TX Err" << " ║\n";
        }
        
        std::cout << "╠══════════════════════════════════════════════════════════════════════════════════╣\n";
        
        for (const auto& [name, stats] : interface_stats_) {
            if (!show_speed) {
                std::cout << "║ " << std::setw(12) << std::left << name
                          << std::setw(16) << format_bytes(stats.rx_bytes)
                          << std::setw(16) << format_bytes(stats.tx_bytes)
                          << std::setw(12) << stats.rx_packets
                          << std::setw(12) << stats.tx_packets
                          << std::setw(10) << stats.rx_errors
                          << std::setw(10) << stats.tx_errors << " ║\n";
            } else {
                std::cout << "║ " << std::setw(12) << std::left << name
                          << std::setw(16) << format_speed(stats.rx_speed_bps)
                          << std::setw(16) << format_speed(stats.tx_speed_bps)
                          << std::setw(12) << std::fixed << std::setprecision(1) << stats.rx_pps
                          << std::setw(12) << std::fixed << std::setprecision(1) << stats.tx_pps
                          << std::setw(10) << stats.rx_errors
                          << std::setw(10) << stats.tx_errors << " ║\n";
            }
        }
        
        std::cout << "╚══════════════════════════════════════════════════════════════════════════════════╝\n";
    }
    
    // Вывести статистику протоколов в таблицу
    void PrintProtocolStatsTable(bool show_rate = false) const {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        
        if (global_protocol_stats_.empty()) {
            std::cout << "No protocol statistics available.\n";
            return;
        }
        
        std::cout << "\x1b[1;36m╔══════════════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                          PROTOCOL STATISTICS                           ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════════════════╣\n";
        
        if (!show_rate) {
            std::cout << "║ " << std::setw(12) << std::left << "Protocol"
                      << std::setw(20) << "Packets"
                      << std::setw(20) << "Bytes"
                      << std::setw(15) << "Errors" << " ║\n";
        } else {
            std::cout << "║ " << std::setw(12) << std::left << "Protocol"
                      << std::setw(20) << "Packet Rate"
                      << std::setw(20) << "Byte Rate"
                      << std::setw(15) << "Errors" << " ║\n";
        }
        
        std::cout << "╠══════════════════════════════════════════════════════════════════════════╣\n";
        
        // Сортируем по имени протокола
        std::vector<std::pair<std::string, ProtocolStats>> sorted_protocols(
            global_protocol_stats_.begin(), global_protocol_stats_.end());
        
        std::sort(sorted_protocols.begin(), sorted_protocols.end(),
            [](const auto& a, const auto& b) { return a.first < b.first; });
        
        for (const auto& [name, stats] : sorted_protocols) {
            if (!show_rate) {
                std::cout << "║ " << std::setw(12) << std::left << name
                          << std::setw(20) << stats.packets
                          << std::setw(20) << format_bytes(stats.bytes)
                          << std::setw(15) << stats.errors << " ║\n";
            } else {
                std::cout << "║ " << std::setw(12) << std::left << name
                          << std::setw(20) << std::fixed << std::setprecision(1) << stats.packet_rate << " pps"
                          << std::setw(20) << format_speed(stats.byte_rate * 8) << "/s"
                          << std::setw(15) << stats.errors << " ║\n";
            }
        }
        
        std::cout << "╚══════════════════════════════════════════════════════════════════════════╝\n";
    }
    
    // Вывести топ интерфейсов по трафику
    void PrintTopInterfaces(int limit = 5, bool by_bytes = true) const {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        
        std::vector<std::pair<std::string, uint64_t>> sorted_interfaces;
        
        for (const auto& [name, stats] : interface_stats_) {
            uint64_t value = by_bytes ? 
                (stats.rx_bytes + stats.tx_bytes) : 
                (stats.rx_packets + stats.tx_packets);
            sorted_interfaces.push_back({name, value});
        }
        
        std::sort(sorted_interfaces.begin(), sorted_interfaces.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });
        
        std::cout << "\x1b[1;33m╔══════════════════════════════════════════════════════╗\n";
        std::cout << "║               TOP " << std::setw(2) << limit 
                  << " INTERFACES " << (by_bytes ? "BY BYTES" : "BY PACKETS") 
                  << "           ║\n";
        std::cout << "╠══════════════════════════════════════════════════════╣\n";
        std::cout << "║ " << std::setw(20) << std::left << "Interface"
                  << std::setw(15) << (by_bytes ? "Total Bytes" : "Total Packets")
                  << std::setw(15) << "RX/TX Ratio" << " ║\n";
        std::cout << "╠══════════════════════════════════════════════════════╣\n";
        
        for (int i = 0; i < std::min(limit, (int)sorted_interfaces.size()); i++) {
            const auto& [name, total] = sorted_interfaces[i];
            const auto& stats = interface_stats_.at(name);
            
            double rx_tx_ratio = (stats.tx_bytes > 0) ? 
                static_cast<double>(stats.rx_bytes) / stats.tx_bytes : 0.0;
            
            std::cout << "║ " << std::setw(20) << std::left << name
                      << std::setw(15) << (by_bytes ? format_bytes(total) : std::to_string(total))
                      << std::setw(15) << std::fixed << std::setprecision(2) << rx_tx_ratio << " ║\n";
        }
        
        std::cout << "╚══════════════════════════════════════════════════════╝\n";
    }
    
    // Вывести сводную статистику
    void PrintSummary() const {
        auto total = GetTotalStats();
        
        std::cout << "\x1b[1;35m╔══════════════════════════════════════════════════════════════╗\n";
        std::cout << "║                  NETWORK STATISTICS SUMMARY                ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
        std::cout << "║ " << std::setw(30) << std::left << "Total RX Bytes:"
                  << std::setw(20) << std::right << format_bytes(total["rx_bytes"]) << " ║\n";
        std::cout << "║ " << std::setw(30) << std::left << "Total TX Bytes:"
                  << std::setw(20) << std::right << format_bytes(total["tx_bytes"]) << " ║\n";
        std::cout << "║ " << std::setw(30) << std::left << "Total RX Packets:"
                  << std::setw(20) << std::right << total["rx_packets"] << " ║\n";
        std::cout << "║ " << std::setw(30) << std::left << "Total TX Packets:"
                  << std::setw(20) << std::right << total["tx_packets"] << " ║\n";
        std::cout << "║ " << std::setw(30) << std::left << "Total RX Errors:"
                  << std::setw(20) << std::right << total["rx_errors"] << " ║\n";
        std::cout << "║ " << std::setw(30) << std::left << "Total TX Errors:"
                  << std::setw(20) << std::right << total["tx_errors"] << " ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
    }
    
    // Экспорт статистики в JSON формат (упрощенный)
    std::string ToJson() const {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        std::stringstream json;
        
        json << "{\n";
        json << "  \"interfaces\": {\n";
        
        bool first_interface = true;
        for (const auto& [name, stats] : interface_stats_) {
            if (!first_interface) json << ",\n";
            json << "    \"" << name << "\": {\n";
            json << "      \"rx_bytes\": " << stats.rx_bytes << ",\n";
            json << "      \"tx_bytes\": " << stats.tx_bytes << ",\n";
            json << "      \"rx_packets\": " << stats.rx_packets << ",\n";
            json << "      \"tx_packets\": " << stats.tx_packets << ",\n";
            json << "      \"rx_errors\": " << stats.rx_errors << ",\n";
            json << "      \"tx_errors\": " << stats.tx_errors << ",\n";
            json << "      \"rx_speed_bps\": " << stats.rx_speed_bps << ",\n";
            json << "      \"tx_speed_bps\": " << stats.tx_speed_bps << "\n";
            json << "    }";
            first_interface = false;
        }
        
        json << "\n  },\n";
        json << "  \"protocols\": {\n";
        
        bool first_protocol = true;
        for (const auto& [name, stats] : global_protocol_stats_) {
            if (!first_protocol) json << ",\n";
            json << "    \"" << name << "\": {\n";
            json << "      \"packets\": " << stats.packets << ",\n";
            json << "      \"bytes\": " << stats.bytes << ",\n";
            json << "      \"errors\": " << stats.errors << ",\n";
            json << "      \"packet_rate\": " << stats.packet_rate << ",\n";
            json << "      \"byte_rate\": " << stats.byte_rate << "\n";
            json << "    }";
            first_protocol = false;
        }
        
        json << "\n  }\n";
        json << "}\n";
        
        return json.str();
    }
};