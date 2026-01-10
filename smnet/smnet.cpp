/**
 * @file smnet.cpp
 * @brief Инструмент мониторинга и анализа сети
 * @author Tosa5656
 * @date 4 января, 2026
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
#include <cstring>

#include "../argsparser/argsparser.h"
#include "../logger/logger.h"
#include "portScanner.h"
#include "trafficMonitor.h"
#include "networkStats.h"

/**
 * @brief Display help information
 */
void help()
{
    std::cout << "Использование smnet:" << std::endl;
    std::cout << "smnet scan - проверить все используемые порты в системе" << std::endl;
    std::cout << "smnet connection - проверить все соединения в системе (на устройстве eth0)" << std::endl;
    std::cout << "smnet connection <устройство> - проверить все соединения в системе на устройстве" << std::endl;
    std::cout << "smnet stats - проверить статистику сетевых соединений" << std::endl;
}

/**
 * @brief Функция сканирования открытых портов и соединений
 */
void scan_ports()
{
    PortScanner scanner;
    auto connections = scanner.scanConnections();
    scanner.printConnections(connections);
}

/**
 * @brief Функция отображения сетевой статистики
 */
void net_stats()
{
    NetworkStats stats;
    stats.RefreshStats();
    
    stats.PrintInterfaceStatsTable();
    getchar();
    stats.PrintInterfaceStatsTable(true);
    getchar();
    stats.PrintTopInterfaces(5, true);
    getchar();
    stats.PrintSummary();
}


// Главная функция - обрабатывает аргументы командной строки
/**
 * @brief Main entry point for smnet tool
 * @param argc Number of command-line arguments
 * @param argv Array of command-line arguments
 * @return Exit code (0 for success)
 */
int main(int argc, char* argv[])
{
    // Нет аргументов - показать справку
    if(argc == 1) {
        std::cout << "Use smnet help to see how use a programm" << std::endl;
        return 0;
    }

    // Команда помощи
    if(argc == 2 && strcmp(argv[1], "help") == 0) {
        help();
        return 0;
    }

    // Сканировать порты
    if(argc == 2 && strcmp(argv[1], "scan") == 0) {
        scan_ports();
        return 0;
    }

    // Мониторить соединения
    if(argc >= 2 && strcmp(argv[1], "connections") == 0) {
        if(argc == 3)
            monitor_traffic(argv[2]);
        else
            monitor_traffic();
        return 0;
    }

    // Статистика сети
    if(argc == 2 && strcmp(argv[1], "stats") == 0) {
        net_stats();
        return 0;
    }

    // Неизвестная команда - просто выйти
    return 0;
}