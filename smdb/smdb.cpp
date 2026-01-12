/**
 * @file smdb.cpp
 * @brief Инструмент запросов базы данных MITRE ATT&CK
 * @author Tosa5656
 * @date 4 января, 2026
 */
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#include <regex>
#include <algorithm>
#include <cstring>
#include "../logger/logger.h"

namespace fs = std::filesystem;

// Извлечь заголовок из HTML файла
std::string getHtmlTitle(const std::string& filepath)
{
    std::ifstream file(filepath);
    if (!file.is_open())
        return "";

    std::string line;
    std::regex titleRegex("<title>([^<]+)</title>", std::regex_constants::icase);

    while (std::getline(file, line))
    {
        std::smatch match;
        if (std::regex_search(line, match, titleRegex))
            return match[1].str();
    }
    return "";
}

// Извлечь содержимое из HTML тега
std::string getHtmlContent(const std::string& filepath, const std::string& tag)
{
    std::ifstream file(filepath);
    if (!file.is_open())
        return "";

    std::string content;
    std::string line;
    bool inTag = false;
    std::regex startTagRegex("<" + tag + "[^>]*>", std::regex_constants::icase);
    std::regex endTagRegex("</" + tag + ">", std::regex_constants::icase);

    while (std::getline(file, line))
    {
        if (!inTag)
        {
            if (std::regex_search(line, startTagRegex))
            {
                inTag = true;
                std::regex htmlTagRegex("<[^>]+>");
                line = std::regex_replace(line, htmlTagRegex, "");
            }
        }
        else
        {
            if (std::regex_search(line, endTagRegex))
            {
                inTag = false;
                std::regex htmlTagRegex("<[^>]+>");
                line = std::regex_replace(line, htmlTagRegex, "");
            }
            else
            {
                std::regex htmlTagRegex("<[^>]+>");
                line = std::regex_replace(line, htmlTagRegex, "");
            }
        }

        if (inTag && !line.empty())
        {
            line.erase(line.begin(), std::find_if(line.begin(), line.end(), [](unsigned char ch) {
                return !std::isspace(ch);
            }));
            line.erase(std::find_if(line.rbegin(), line.rend(), [](unsigned char ch) {
                return !std::isspace(ch);
            }).base(), line.end());

            if (!line.empty())
            {
                if (!content.empty())
                    content += " ";
                content += line;
            }
        }
    }

    return content;
}

// Поиск по файлам документации атак
std::vector<std::string> searchAttacks(const std::string& query, const std::string& docsPath)
{
    std::vector<std::string> results;

    if (!fs::exists(docsPath))
    {
        LogError("Не удалось найти документацию по пути: " + docsPath);
        return results;
    }

    for (const auto& entry : fs::directory_iterator(docsPath))
    {
        if (entry.path().extension() == ".html")
        {
            std::ifstream file(entry.path());
            if (!file.is_open())
                continue;

            std::string line;
            bool found = false;
            std::string lowerQuery = query;
            std::transform(lowerQuery.begin(), lowerQuery.end(), lowerQuery.begin(), ::tolower);

            while (std::getline(file, line))
            {
                std::string lowerLine = line;
                std::transform(lowerLine.begin(), lowerLine.end(), lowerLine.begin(), ::tolower);

                if (lowerLine.find(lowerQuery) != std::string::npos)
                {
                    found = true;
                    break;
                }
            }

            if (found)
                results.push_back(entry.path().string());
        }
    }

    return results;
}

// Отобразить детальную информацию об определенной атаке
void showAttackDetails(const std::string& filepath)
{
    std::cout << "=== " << getHtmlTitle(filepath) << " ===" << std::endl;
    std::cout << std::endl;

    std::string description = getHtmlContent(filepath, "p");
    if (!description.empty())
    {
        std::cout << "Описание: " << description << std::endl;
        std::cout << std::endl;
    }

    std::cout << "Защита с помощью Security Manager:" << std::endl;

    std::ifstream file(filepath);
    if (file.is_open())
    {
        std::string line;
        bool inProtection = false;
        std::regex protectionStart("<h3>|<h2>.*Security Manager.*</h3>|<h2>.*Защита.*</h2>", std::regex_constants::icase);
        std::regex protectionEnd("</h2>|</h3>|<h2>", std::regex_constants::icase);

        while (std::getline(file, line))
        {
            if (std::regex_search(line, protectionStart))
            {
                inProtection = true;
                std::regex toolRegex("(sm\\w+|smlog|smnet|smpass|smssh)");
                std::smatch toolMatch;
                if (std::regex_search(line, toolMatch, toolRegex))
                    std::cout << "• " << toolMatch[1].str() << std::endl;
            }
            else if (inProtection && std::regex_search(line, protectionEnd))
                inProtection = false;
            else if (inProtection && line.find("<li>") != std::string::npos)
            {
                std::regex htmlTagRegex("<[^>]+>");
                std::string cleanLine = std::regex_replace(line, htmlTagRegex, "");
                if (!cleanLine.empty())
                    std::cout << "  - " << cleanLine << std::endl;
            }
        }
    }

    std::cout << std::endl;
    std::cout << "Подробности смотри в: " << filepath << std::endl;
}

void listAllAttacks(const std::string& docsPath)
{
    if (!fs::exists(docsPath))
    {
        LogError("Documentation path does not exist: " + docsPath);
        return;
    }

    std::cout << "Attacks from MITRE ATT&CK:" << std::endl;
    std::cout << "==================================" << std::endl;

    for (const auto& entry : fs::directory_iterator(docsPath))
    {
        if (entry.path().extension() == ".html")
        {
            std::string title = getHtmlTitle(entry.path());
            if (!title.empty())
                std::cout << "• " << title << std::endl;
        }
    }
    std::cout << std::endl;
}

// Отобразить справочную информацию
void help(const std::string& docsPath)
{
    std::cout << "smdb - База возможных атак для Security Manager" << std::endl;
    std::cout << std::endl;
    std::cout << "Usage:" << std::endl;
    std::cout << "  smdb help                    - показать этот раздел" << std::endl;
    std::cout << "  smdb list                    - показать все доступные атаки" << std::endl;
    std::cout << "  smdb search <keyword>        - поиск атаки по ключевому слову" << std::endl;
    std::cout << "  smdb show <attack_id>        - показать подробную инфорацию об атаке" << std::endl;
    std::cout << "  smdb tools <attack_id>       - показать инструменты защиты от атаки" << std::endl;
    std::cout << std::endl;
    std::cout << "Примеры:" << std::endl;
    std::cout << "  smdb list" << std::endl;
    std::cout << "  smdb search brute" << std::endl;
    std::cout << "  smdb show T1110" << std::endl;
    std::cout << "  smdb tools T1078" << std::endl;
    std::cout << std::endl;
    std::cout << "Путь к документации: " << docsPath << "/*.html" << std::endl;
}

// Главная точка входа для инструмента smdb
int main(int argc, char* argv[])
{
    std::string docsPath;
    if (fs::exists("/usr/share/doc/security-manager/attacks"))
        docsPath = "/usr/share/doc/security-manager/attacks";
    else
        docsPath = "doc/attacks";

    if (argc < 2)
    {
        help(docsPath);
        return 0;
    }

    std::string command = argv[1];

    if (command == "help")
        help(docsPath);
    else if (command == "list")
        listAllAttacks(docsPath);
    else if (command == "search" && argc >= 3)
    {
        std::string query = argv[2];
        auto results = searchAttacks(query, docsPath);

        if (results.empty())
        {
            std::cout << "Не найдено атак по запросу: " << query << std::endl;
        }
        else
        {
            std::cout << "Найденные атаки:" << std::endl;
            for (const auto& result : results)
            {
                std::string title = getHtmlTitle(result);
                std::cout << "• " << title << std::endl;
            }
            std::cout << std::endl;
            std::cout << "Используйте 'smdb show <attack_id>' для подробной информации" << std::endl;
        }
    }
    else if (command == "show" && argc >= 3)
    {
        std::string attackId = argv[2];
        std::string filepath = docsPath + "/" + attackId + ".html";

        if (fs::exists(filepath))
            showAttackDetails(filepath);
        else
        {
            std::cout << "Атака не найдена: " << attackId << std::endl;
            std::cout << "Используйте 'smdb list' для просмотра доступных атак" << std::endl;
        }
    }
    else if (command == "tools" && argc >= 3)
    {
        std::string attackId = argv[2];
        std::string filepath = docsPath + "/" + attackId + ".html";

        if (fs::exists(filepath))
        {
            std::cout << "Инструменты Security Manager для защиты от " << attackId << ":" << std::endl;
            std::cout << "=======================================================" << std::endl;

            std::ifstream file(filepath);
            if (file.is_open())
            {
                std::string line;
                bool inProtection = false;

                while (std::getline(file, line))
                {
                    if (line.find("Security Manager") != std::string::npos)
                        inProtection = true;
                    else if (inProtection && line.find("<h3>") != std::string::npos)
                    {
                        std::regex toolRegex("(sm\\w+|smlog|smnet|smpass|smssh)");
                        std::smatch toolMatch;
                        if (std::regex_search(line, toolMatch, toolRegex))
                        {
                            std::cout << std::endl;
                            std::cout << toolMatch[1].str() << ":" << std::endl;
                        }
                    }
                    else if (inProtection && line.find("<li>") != std::string::npos)
                    {
                        std::regex htmlTagRegex("<[^>]+>");
                        std::string cleanLine = std::regex_replace(line, htmlTagRegex, "");
                        if (!cleanLine.empty() && cleanLine.find("strong") == std::string::npos)
                            std::cout << "  • " << cleanLine << std::endl;
                    }
                    else if (inProtection && (line.find("</h2>") != std::string::npos || line.find("<h2>") != std::string::npos))
                    {
                        if (line.find("Рекомендации") != std::string::npos)
                            break;
                    }
                }
            }
        }
        else
        {
            std::cout << "Атака не найдена: " << attackId << std::endl;
        }
    }
    else
    {
        std::cout << "Неизвестная команда: " << command << std::endl;
        std::cout << "Используйте 'smdb help' для справки" << std::endl;
        return 1;
    }

    return 0;
}