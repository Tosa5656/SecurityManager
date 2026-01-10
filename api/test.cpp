/**
 * @file test.cpp
 * @brief Тестовая программа для Security Manager API
 * @author Tosa5656
 * @date 4 января, 2026
 */

#include <securitymanager.h>
#include <iostream>

int main()
{
    std::cout << "Тест Security Manager API" << std::endl;
    std::cout << "Версия: " << SecurityManager::getVersion() << std::endl;
    std::cout << std::endl;

    std::cout << "Тестирование менеджера паролей..." << std::endl;
    SecurityManager::PasswordManager pwd_mgr;

    auto hash_result = pwd_mgr.hashString("test_password", SecurityManager::HashAlgorithm::SHA256);
    if (hash_result.success())
        std::cout << "Хеширование успешно: " << hash_result.data.substr(0, 32) << "..." << std::endl;
    else
        std::cout << "Ошибка хеширования: " << hash_result.message << std::endl;

    std::cout << "Тестирование сетевого монитора..." << std::endl;
    SecurityManager::NetworkMonitor net_mgr;

    auto ports_result = net_mgr.scanPorts(20, 25);
    if (ports_result.success())
        std::cout << "Сканирование портов успешно: найдено " << ports_result.data.size() << " портов" << std::endl;
    else
        std::cout << "Ошибка сканирования портов: " << ports_result.message << std::endl;

    std::cout << "Тестирование анализатора логов..." << std::endl;
    SecurityManager::LogAnalyzer log_analyzer;

    auto log_result = log_analyzer.readLogFile("test/test_system.log", {}, 2);
    if (log_result.success())
        std::cout << "Чтение лога успешно: " << log_result.data.size() << " записей" << std::endl;
    else
        std::cout << "Ошибка чтения лога: " << log_result.message << std::endl;

    std::cout << "Тестирование SSH безопасности..." << std::endl;
    SecurityManager::SSHSecurity ssh_sec;

    auto ssh_result = ssh_sec.analyzeConfiguration("test/test_sshd_config");
    if (ssh_result.success())
        std::cout << "Анализ SSH успешен: оценка " << ssh_result.data.security_score << "/100" << std::endl;
    else
        std::cout << "Ошибка анализа SSH: " << ssh_result.message << std::endl;

    std::cout << "Тестирование базы данных атак..." << std::endl;
    SecurityManager::AttackDatabase attack_db;

    auto search_result = attack_db.searchAttacks("brute");
    if (search_result.success())
        std::cout << "Поиск атак успешен: найдено " << search_result.data.size() << " атак" << std::endl;
    else
        std::cout << "Ошибка поиска атак: " << search_result.message << std::endl;

    auto stats_result = attack_db.getDatabaseStats();
    if (stats_result.success())
        std::cout << "Статистика БД успешна: " << stats_result.data.total_attacks << " атак" << std::endl;
    else
        std::cout << "Ошибка статистики БД: " << stats_result.message << std::endl;

    std::cout << std::endl << "Все тесты API завершены!" << std::endl;
    return 0;
}