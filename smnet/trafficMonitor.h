/**
 * @file trafficMonitor.h
 * @brief Мониторинг сетевого трафика с использованием libpcap
 * @author Tosa5656
 * @date 2 января, 2026
 */

#include <iostream>
#include <iomanip>
#include <string>
#include <atomic>
#include <thread>
#include <chrono>
#include <csignal>
#include <vector>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

/**
 * @brief Глобальный флаг для управления потоком мониторинга
 */
std::atomic<bool> g_running{true};

/**
 * @brief Обработчик сигналов для корректного завершения
 * @param sig Номер сигнала
 */
inline void signalHandler(int sig) { g_running = false; }

/**
 * @brief Structure for storing network traffic statistics
 */
struct Stats
{
    std::atomic<uint64_t> total_packets{0};  /**< Total packets captured */
    std::atomic<uint64_t> total_bytes{0};    /**< Total bytes captured */
    std::atomic<uint64_t> tcp_packets{0};    /**< TCP packets count */
    std::atomic<uint64_t> udp_packets{0};    /**< UDP packets count */
    std::atomic<uint64_t> icmp_packets{0};   /**< ICMP packets count */
    std::atomic<uint64_t> packets_last_sec{0}; /**< Packets per second */
    std::atomic<uint64_t> bytes_last_sec{0};   /**< Bytes per second */
};

/**
 * @brief Monitor network traffic on specified interface
 * @param interface Network interface to monitor (default: "eth0")
 * @param filter BPF filter expression (default: none)
 * @param update_interval_ms Statistics update interval in milliseconds (default: 1000)
 */
void monitor_traffic(const std::string& interface = "eth0",
                     const std::string& filter = "",
                     int update_interval_ms = 1000)
{
    g_running = true;
    Stats stats;

    pcap_t* pcap_handle = nullptr;
    std::signal(SIGINT, signalHandler);
    
    auto format_bytes = [](uint64_t bytes) -> std::string
    {
        if (bytes < 1024) return std::to_string(bytes) + " B";
        double value = bytes;
        const char* units[] = {"KB", "MB", "GB"};
        int unit = 0;
        while (value >= 1024 && unit < 2) {
            value /= 1024;
            unit++;
        }
        std::stringstream ss;
        ss << std::fixed << std::setprecision(2) << value << " " << units[unit];
        return ss.str();
    };
    
    auto format_speed = [&format_bytes](uint64_t bytes_per_sec) -> std::string
    {
        return format_bytes(bytes_per_sec) + "/s";
    };
    
    std::thread capture_thread([&]()
    {
        char errbuf[PCAP_ERRBUF_SIZE];

        pcap_handle = pcap_open_live(interface.c_str(), 65536, 1, 1000, errbuf);
        if (!pcap_handle)
        {
            std::cerr << "Error opening interface: " << errbuf << std::endl;
            g_running = false;
            return;
        }
        
        if (!filter.empty())
        {
            struct bpf_program fp;
            if (pcap_compile(pcap_handle, &fp, filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1)
            {
                std::cerr << "Bad filter expression" << std::endl;
                pcap_close(pcap_handle);
                g_running = false;
                return;
            }
            pcap_setfilter(pcap_handle, &fp);
            pcap_freecode(&fp);
        }
        
        struct pcap_pkthdr* header;
        const u_char* packet_data;
        time_t last_second = time(nullptr);
        uint64_t packets_this_sec = 0;
        uint64_t bytes_this_sec = 0;
        
        while (g_running.load())
        {
            int result = pcap_next_ex(pcap_handle, &header, &packet_data);
            
            if (result == 1)
            {
                stats.total_packets++;
                stats.total_bytes += header->len;
                packets_this_sec++;
                bytes_this_sec += header->len;
                
                struct ether_header* eth_header = (struct ether_header*)packet_data;
                if (ntohs(eth_header->ether_type) == ETHERTYPE_IP)
                {
                    struct ip* ip_header = (struct ip*)(packet_data + sizeof(struct ether_header));
                    switch (ip_header->ip_p)
                    {
                        case IPPROTO_TCP: stats.tcp_packets++; break;
                        case IPPROTO_UDP: stats.udp_packets++; break;
                        case IPPROTO_ICMP: stats.icmp_packets++; break;
                    }
                }
                
                time_t current_time = time(nullptr);
                if (current_time != last_second)
                {
                    stats.packets_last_sec = packets_this_sec;
                    stats.bytes_last_sec = bytes_this_sec;
                    packets_this_sec = 0;
                    bytes_this_sec = 0;
                    last_second = current_time;
                }
            }
            else if (result == 0)
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            else
                break;
        }
        
        if (pcap_handle)
            pcap_close(pcap_handle);
    });
    
    std::cout << "\n\x1b[32m=== smnet Traffic Monitor ===\x1b[0m\n";
    std::cout << "Interface: " << interface << std::endl;
    if (!filter.empty())
        std::cout << "Filter: " << filter << std::endl;
    std::cout << "Press Ctrl+C to stop\n" << std::endl;
    
    auto last_display = std::chrono::steady_clock::now();
    
    while (g_running.load())
    {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_display);
        
        if (elapsed.count() >= update_interval_ms)
        {
            system("clear");
            
            std::cout << "\x1b[1;36m╔══════════════════════════════════════════════════════════╗\n";
            std::cout << "║                  TRAFFIC MONITOR                     ║\n";
            std::cout << "╠══════════════════════════════════════════════════════════╣\n";
            std::cout << "║ Interface: " << std::setw(41) << std::left << interface << "║\n";
            std::cout << "╠══════════════════════════════════════════════════════════╣\x1b[0m\n";
            
            uint64_t total_packets = stats.total_packets.load();
            uint64_t total_bytes = stats.total_bytes.load();
            uint64_t packets_sec = stats.packets_last_sec.load();
            uint64_t bytes_sec = stats.bytes_last_sec.load();
            
            std::cout << "\x1b[1;37m║ \x1b[32mTotal: \x1b[37m" 
                      << std::setw(12) << total_packets << " packets, "
                      << format_bytes(total_bytes) << std::setw(20) << "" << " ║\n";
            std::cout << "║ \x1b[32mRate:  \x1b[37m" 
                      << std::setw(12) << packets_sec << " pps,   "
                      << format_speed(bytes_sec) << std::setw(20) << "" << " ║\n";
            
            std::cout << "\x1b[1;36m╠══════════════════════════════════════════════════════════╣\x1b[0m\n";
            
            std::cout << "\x1b[1;37m║ \x1b[33mTCP: \x1b[37m" << std::setw(10) << stats.tcp_packets.load()
                      << " \x1b[33mUDP: \x1b[37m" << std::setw(10) << stats.udp_packets.load()
                      << " \x1b[33mICMP: \x1b[37m" << std::setw(10) << stats.icmp_packets.load()
                      << std::setw(10) << "" << " ║\n";
            
            std::cout << "\x1b[1;36m╚══════════════════════════════════════════════════════════╝\x1b[0m\n";
            
            last_display = now;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    if (capture_thread.joinable())
        capture_thread.join();
    
    std::cout << "\n\x1b[33m=== Final Statistics ===\x1b[0m\n";
    std::cout << "Total packets: " << stats.total_packets.load() << "\n";
    std::cout << "Total bytes:   " << format_bytes(stats.total_bytes.load()) << "\n";
    std::cout << "TCP packets:   " << stats.tcp_packets.load() << "\n";
    std::cout << "UDP packets:   " << stats.udp_packets.load() << "\n";
    std::cout << "ICMP packets:  " << stats.icmp_packets.load() << "\n";
}