/**
 * @file example.cpp
 * @brief Пример использования Security Manager API
 * @author Tosa5656
 * @date 4 января, 2026
 */

#include <securitymanager.h>
#include <iostream>
#include <vector>

int main()
{
    std::cout << "Пример использования Security Manager API" << std::endl;
    std::cout << "Версия: " << SecurityManager::getVersion() << std::endl;
    std::cout << "Описание: " << SecurityManager::getDescription() << std::endl;
    std::cout << std::endl;

    if (!SecurityManager::initialize())
    {
        std::cerr << "Ошибка инициализации API: " << SecurityManager::getLastError() << std::endl;
        return 1;
    }

    std::cout << "=== Управление паролями ===" << std::endl;
    SecurityManager::PasswordManager pwd_mgr;

    auto hash_result = pwd_mgr.hashString("MySecurePassword123!", SecurityManager::HashAlgorithm::SHA256);
    if (hash_result.success())
        std::cout << "SHA256 хеш: " << hash_result.data.substr(0, 32) << "..." << std::endl;
    else
        std::cout << "Ошибка хеширования: " << hash_result.message << std::endl;

    auto add_result = pwd_mgr.addPassword("github.com", "myuser", "MyPassword123!");
    if (add_result.success())
        std::cout << "Пароль успешно добавлен" << std::endl;

    auto list_result = pwd_mgr.listServices();
    if (list_result.success())
        std::cout << "Сохранено сервисов: " << list_result.data.size() << std::endl;

    std::cout << std::endl;

    std::cout << "=== Мониторинг сети ===" << std::endl;
    SecurityManager::NetworkMonitor net_mgr;

    auto ports_result = net_mgr.scanPorts(20, 25);
    if (ports_result.success())
    {
        std::cout << "Результаты сканирования портов:" << std::endl;
        for (const auto& port : ports_result.data)
            std::cout << "  Порт " << port.port << " (" << port.service << "): " << port.state << std::endl;
    }

    auto net_stats_result = net_mgr.getNetworkStats();
    if (net_stats_result.success())
    {
        std::cout << "Отправлено байт: " << net_stats_result.data.total_bytes_sent << std::endl;
        std::cout << "Получено байт: " << net_stats_result.data.total_bytes_received << std::endl;
    }

    std::cout << std::endl;

    std::cout << "=== Анализ логов ===" << std::endl;
    SecurityManager::LogAnalyzer log_analyzer;

    auto log_result = log_analyzer.readLogFile("test/test_system.log", {}, 3);
    if (log_result.success())
    {
        std::cout << "Прочитано " << log_result.data.size() << " записей лога" << std::endl;
        for (const auto& entry : log_result.data)
            std::cout << "  [" << entry.level << "] " << entry.message.substr(0, 50) << "..." << std::endl;
    }

    std::cout << std::endl;

    std::cout << "=== SSH безопасность ===" << std::endl;
    SecurityManager::SSHSecurity ssh_sec;

    auto ssh_result = ssh_sec.analyzeConfiguration("test/test_sshd_config");
    if (ssh_result.success())
    {
        std::cout << "Анализ SSH конфигурации:" << std::endl;
        std::cout << "  Найдено проблем: " << ssh_result.data.total_issues << std::endl;
        std::cout << "  Оценка безопасности: " << ssh_result.data.security_score << "/100" << std::endl;
        std::cout << "  Уровень риска: " << ssh_result.data.overall_risk_level << std::endl;
    }

    auto attack_result = ssh_sec.detectAttacks("test/test_brute.log");
    if (attack_result.success())
        std::cout << "Обнаружено SSH атак: " << attack_result.data.size() << std::endl;

    std::cout << std::endl;

    std::cout << "=== База данных MITRE ATT&CK ===" << std::endl;
    SecurityManager::AttackDatabase attack_db;

    auto search_result = attack_db.searchAttacks("brute force");
    if (search_result.success())
    {
        std::cout << "Найдено " << search_result.data.size() << " атак, соответствующих 'brute force':" << std::endl;
        for (const auto& result : search_result.data)
            std::cout << "  " << result.attack_id << " - " << result.title << std::endl;
    }

    auto info_result = attack_db.getAttackInfo("T1110");
    if (info_result.success())
    {
        std::cout << std::endl << "Детальная информация по T1110:" << std::endl;
        std::cout << "  Название: " << info_result.data.title << std::endl;
        std::cout << "  Тактика: " << info_result.data.tactic << std::endl;
        std::cout << "  Платформы: " << info_result.data.platform << std::endl;
        std::cout << "  Инструменты защиты: " << info_result.data.protection_tools.size() << std::endl;
    }

    auto db_stats_result = attack_db.getDatabaseStats();
    if (db_stats_result.success())
    {
        std::cout << std::endl << "Статистика базы данных:" << std::endl;
        std::cout << "  Всего атак: " << db_stats_result.data.total_attacks << std::endl;
        std::cout << "  Тактик: " << db_stats_result.data.tactics_count << std::endl;
        std::cout << "  Версия: " << db_stats_result.data.version << std::endl;
    }

    std::cout << std::endl;

    std::cout << "=== Пример экспорта ===" << std::endl;
    auto export_result = attack_db.exportAttackInfo("T1110", "txt", "/tmp/t1110_info.txt");
    if (export_result.success())
        std::cout << "Информация об атаке экспортирована в /tmp/t1110_info.txt" << std::endl;

    SecurityManager::cleanup();

    std::cout << std::endl << "Пример использования API успешно завершен!" << std::endl;
    std::cout << "Для дополнительной информации см. api/README.md" << std::endl;

    return 0;
}
