/**
 * @file portScanner.h
 * @brief Сканирование сетевых портов и мониторинг соединений
 * @author Tosa5656
 * @date 2 января, 2026
 */

#pragma once

#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <unordered_map>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>

/**
 * @brief Сканер портов и анализатор сетевых соединений
 *
 * Сканирует сетевые порты и анализирует активные соединения,
 * предоставляя детальную информацию о сетевой активности.
 */
class PortScanner
{
private:
    /**
     * @brief Structure containing network connection information
     */
    struct ConnectionInfo
    {
        std::string protocol;        /**< Network protocol (TCP/UDP) */
        std::string local_address;   /**< Local IP address */
        int local_port;              /**< Local port number */
        std::string remote_address;  /**< Remote IP address */
        int remote_port;             /**< Remote port number */
        std::string state;           /**< Connection state */
        pid_t pid;                   /**< Process ID owning the connection */
        std::string process_name;    /**< Process name owning the connection */
    };

    std::unordered_map<std::string, std::string> socket_states;
    std::unordered_map<std::string, std::pair<pid_t, std::string>> inode_to_process;

public:
    /**
     * @brief Constructor - initializes the port scanner
     */
    PortScanner()
    {
        socket_states = {
            {"01", "ESTABLISHED"}, {"02", "SYN_SENT"}, {"03", "SYN_RECV"},
            {"04", "FIN_WAIT1"}, {"05", "FIN_WAIT2"}, {"06", "TIME_WAIT"},
            {"07", "CLOSE"}, {"08", "CLOSE_WAIT"}, {"09", "LAST_ACK"},
            {"0A", "LISTEN"}, {"0B", "CLOSING"}
        };
        
        buildInodeProcessMap();
    }

private:
    void buildInodeProcessMap()
    {
        auto proc_dir = opendir("/proc");
        if (!proc_dir) return;
        
        struct dirent* entry;
        while ((entry = readdir(proc_dir)) != nullptr)
        {
            std::string dirname = entry->d_name;
            
            if (std::all_of(dirname.begin(), dirname.end(), ::isdigit))
            {
                pid_t pid = std::stoi(dirname);
                std::string fd_path = "/proc/" + dirname + "/fd/";
                
                std::string comm_path = "/proc/" + dirname + "/comm";
                std::ifstream comm_file(comm_path);
                std::string process_name;
                if (comm_file)
                    std::getline(comm_file, process_name);
                
                auto fd_dir = opendir(fd_path.c_str());
                if (fd_dir)
                {
                    struct dirent* fd_entry;
                    while ((fd_entry = readdir(fd_dir)) != nullptr)
                    {
                        std::string fd_name = fd_entry->d_name;
                        if (fd_name == "." || fd_name == "..") continue;
                        
                        std::string link_path = fd_path + fd_name;
                        char link_target[256];
                        ssize_t len = readlink(link_path.c_str(), link_target, sizeof(link_target)-1);
                        if (len != -1)
                        {
                            link_target[len] = '\0';
                            std::string target_str(link_target);
                            
                            size_t pos = target_str.find("socket:[");
                            if (pos != std::string::npos)
                            {
                                std::string inode = target_str.substr(pos + 8);
                                inode.pop_back();
                                inode_to_process[inode] = {pid, process_name};
                            }
                        }
                    }
                    closedir(fd_dir);
                }
            }
        }
        closedir(proc_dir);
    }

    std::string hexToIp(const std::string& hex_ip)
    {
        if (hex_ip.length() != 8) return "0.0.0.0";
        
        unsigned int ip_int;
        std::stringstream ss;
        ss << std::hex << hex_ip;
        ss >> ip_int;
        
        return std::to_string(ip_int & 0xFF) + "." +
               std::to_string((ip_int >> 8) & 0xFF) + "." +
               std::to_string((ip_int >> 16) & 0xFF) + "." +
               std::to_string((ip_int >> 24) & 0xFF);
    }

    int hexToPort(const std::string& hex_port)
    {
        int port;
        std::stringstream ss;
        ss << std::hex << hex_port;
        ss >> port;
        return port;
    }

public:
    /**
     * @brief Scan all active network connections
     * @return Vector of connection information structures
     */
    std::vector<ConnectionInfo> scanConnections()
    {
        std::vector<ConnectionInfo> connections;
        
        std::vector<std::pair<std::string, std::string>> proc_files = {
            {"/proc/net/tcp", "TCP"},
            {"/proc/net/udp", "UDP"},
            {"/proc/net/tcp6", "TCP6"},
            {"/proc/net/udp6", "UDP6"}
        };
        
        for (const auto& [filename, protocol] : proc_files)
        {
            std::ifstream file(filename);
            if (!file.is_open()) continue;
            
            std::string line;
            std::getline(file, line);
            
            while (std::getline(file, line)) {
                std::istringstream iss(line);
                std::vector<std::string> tokens;
                std::string token;
                
                while (iss >> token) {
                    tokens.push_back(token);
                }
                
                if (tokens.size() < 10) continue;
                
                ConnectionInfo info;
                info.protocol = protocol;
                
                std::string local_addr = tokens[1];
                size_t colon_pos = local_addr.find(':');
                std::string local_ip_hex = local_addr.substr(0, colon_pos);
                std::string local_port_hex = local_addr.substr(colon_pos + 1);
                
                info.local_address = hexToIp(local_ip_hex);
                info.local_port = hexToPort(local_port_hex);
                
                std::string remote_addr = tokens[2];
                colon_pos = remote_addr.find(':');
                std::string remote_ip_hex = remote_addr.substr(0, colon_pos);
                std::string remote_port_hex = remote_addr.substr(colon_pos + 1);
                
                info.remote_address = hexToIp(remote_ip_hex);
                info.remote_port = hexToPort(remote_port_hex);
                
                std::string state_hex = tokens[3];
                info.state = socket_states.count(state_hex) ? 
                            socket_states[state_hex] : "UNKNOWN";
                
                std::string inode = tokens[9];
                if (inode_to_process.count(inode))
                {
                    info.pid = inode_to_process[inode].first;
                    info.process_name = inode_to_process[inode].second;
                }
                else
                {
                    info.pid = -1;
                    info.process_name = "unknown";
                }
                
                connections.push_back(info);
            }
            
            file.close();
        }
        
        return connections;
    }

    void printConnections(const std::vector<ConnectionInfo>& connections)
    {
        std::cout << std::left
                  << std::setw(8) << "PROTO"
                  << std::setw(20) << "LOCAL ADDRESS"
                  << std::setw(20) << "REMOTE ADDRESS"
                  << std::setw(15) << "STATE"
                  << std::setw(10) << "PID"
                  << std::setw(25) << "PROCESS"
                  << std::endl;
        
        std::cout << std::string(100, '-') << std::endl;
        
        for (const auto& conn : connections)
        {
            if (conn.state == "LISTEN" || conn.state == "ESTABLISHED")
            {
                std::cout << std::setw(8) << conn.protocol
                          << std::setw(20) << (conn.local_address + ":" + std::to_string(conn.local_port))
                          << std::setw(20) << (conn.remote_address + ":" + std::to_string(conn.remote_port))
                          << std::setw(15) << conn.state
                          << std::setw(10) << (conn.pid == -1 ? "-" : std::to_string(conn.pid))
                          << std::setw(25) << (conn.process_name.length() > 24 ? 
                                               conn.process_name.substr(0, 21) + "..." : 
                                               conn.process_name)
                          << std::endl;
            }
        }
    }
};