#ifndef SMDB_API_H
#define SMDB_API_H

/**
 * @file smdb_api.h
 * @brief MITRE ATT&CK Database API - База знаний об атаках и защите от них(на основе MITRE ATT&CK)
 * @author Tosa5656
 * @date 4 января, 2026
 */

#include <string>
#include <vector>
#include <map>
#include <memory>

namespace SecurityManager
{
    /**
    * @brief Коды ошибок
    */
    enum class DatabaseError
    {
        SUCCESS = 0,
        ATTACK_NOT_FOUND = 1,
        FILE_NOT_FOUND = 2,
        PARSE_ERROR = 3,
        INVALID_ARGUMENT = 4
    };

    /**
    * @brief Обвертка результата запроса к базе данных
    */
    template<typename T>
    struct DatabaseResult
    {
        DatabaseError code;
        std::string message;
        T data;

        DatabaseResult() : code(DatabaseError::SUCCESS) {}
        DatabaseResult(DatabaseError c, const std::string& msg) : code(c), message(msg) {}
        DatabaseResult(DatabaseError c, const std::string& msg, const T& d) : code(c), message(msg), data(d) {}

        bool success() const { return code == DatabaseError::SUCCESS; }
        operator bool() const { return success(); }
    };

    /**
    * @brief Информация об атаке из MITRE ATT&CK
    */
    struct AttackInfo
    {
        std::string id;                    // MITRE ID (например T1110)
        std::string title;                 // Название атаки
        std::string description;           // Описание
        std::string mitre_url;             // Ссылка на MITRE ATT&CK страницу
        std::string tactic;                // Тактика атаки (например Initial Access)
        std::string platform;              // На какие платформы ориентированно
        std::string data_sources;          // Данные для обнаружения
        std::vector<std::string> tags;     // Теги
        std::vector<std::string> protection_tools;    // При помощи каких утилит SM можно противостоять
        std::vector<std::string> recommendations;     // Рекомендации по безопастности
        bool requires_privileges;          // Требуются ли root права
        std::string impact;                // Потенциальный урон
        std::string difficulty;            // Сложность
    };

    /**
    * @brief Рекомендации по защите
    */
    struct ProtectionGuidance
    {
        std::string attack_id;
        std::vector<std::string> detection_methods;
        std::vector<std::string> prevention_steps;
        std::vector<std::string> response_actions;
        std::string risk_level;           // Critical, High, Medium, Low
        std::string sm_tools_command;     // Команды SM утилит
    };

    /**
    * @brief Результат поиска атаки
    */
    struct AttackSearchResult
    {
        std::string attack_id;
        std::string title;
        std::string relevance_score;      // Насколько подходит поиску
        std::vector<std::string> matched_keywords;
    };

    /**
    * @brief Статистика базы
    */
    struct DatabaseStats
    {
        int total_attacks;
        int tactics_count;
        std::vector<std::string> available_tactics;
        std::vector<std::string> platforms;
        std::string last_updated;
        std::string version;
    };

    /**
    * @brief Основной класс базы данных
    */
    class AttackDatabase
    {
    public:
        AttackDatabase();
        ~AttackDatabase();

        /**
        * @brief Поиск атаки по ключевому слову
        * @param keyword Ключевое слово
        * @param tactic Тактика(опционально)
        * @param platform Платформа(опционально)
        * @return std::vector с атаками соотвесвующих поиску
        */
        DatabaseResult<std::vector<AttackSearchResult>> searchAttacks(const std::string& keyword, const std::string& tactic = "", const std::string& platform = "");

        /**
        * @brief Получить подробную информацию об атаке
        * @param attack_id MITRE ID (например T1110)
        * @return Информация об атаке
        */
        DatabaseResult<AttackInfo> getAttackInfo(const std::string& attack_id);

        /**
        * @brief Получить рекомендации по защите от атаки
        * @param attack_id MITRE ID
        * @return Рекомендации по защите
        */
        DatabaseResult<ProtectionGuidance> getProtectionGuidance(const std::string& attack_id);

        /**
        * @brief Получить все атаки соответстсвующие тактике
        * @param tactic Тактика
        * @return std::vector с MITRE ID атак соответствующих тактике
        */
        DatabaseResult<std::vector<std::string>> getAttacksByTactic(const std::string& tactic);

        /**
        * @brief Получить все атаки соответствующие платформе
        * @param platform Платформа (Windows, Linux, macOS)
        * @return std::vector с MITRE ID атак соответствующих платформе
        */
        DatabaseResult<std::vector<std::string>> getAttacksByPlatform(const std::string& platform);

        /**
        * @brief Получить список всех атак
        * @return std::vector с MITRE ID всех атак
        */
        DatabaseResult<std::vector<std::string>> listAllAttacks();

        /**
        * @brief Получить статистику базы данных
        * @return Статистика базы данных
        */
        DatabaseResult<DatabaseStats> getDatabaseStats();

        /**
        * @brief Экспорт информации об атаке в файл
        * @param attack_id ID атаки
        * @param format Формат экспорта (json, html, txt)
        * @param output_file Выходной файл
        * @return Удача/Неудача
        */
        DatabaseResult<bool> exportAttackInfo(const std::string& attack_id, const std::string& format, const std::string& output_file);

        /**
        * @brief Получить похожие атаки
        * @param attack_id ID атаки
        * @return std::vector с ID похожих атак
        */
        DatabaseResult<std::vector<std::string>> getRelatedAttacks(const std::string& attack_id);

        /**
        * @brief Получить стратегии смягчения последствий
        * @param attack_id ID атаки
        * @return std::vector с стратегией смягчения
        */
        DatabaseResult<std::vector<std::string>> getMitigationStrategies(const std::string& attack_id);
    private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };
}

#endif