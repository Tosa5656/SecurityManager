/**
 * @file argsparser.cpp
 * @brief Реализация парсера аргументов командной строки
 * @author Tosa5656
 * @date 28 декабря, 2026
 */

#include "argsparser.h"

ArgumentParser::ArgumentParser(int argc, char* argv[])
{
    if (argc > 1)
        for (int i = 1; i < argc; ++i)
            processArgument(argv[i]);
}

/**
 * @brief Нормализовать имя флага, удалив ведущие дефисы
 * @param rawFlag Исходная строка флага (например, "-v", "--verbose")
 * @return Нормализованное имя флага без дефисов
 */
std::string ArgumentParser::normalizeFlagName(const std::string& rawFlag) const
{
    if (rawFlag.size() > 2 && (rawFlag.substr(0, 2) == "--" || rawFlag.substr(0, 2) == "-#"))
        return rawFlag.substr(2);
    if (!rawFlag.empty() && rawFlag[0] == '-')
        return rawFlag.substr(1);
    return rawFlag;
}

/**
 * @brief Обработать отдельный аргумент командной строки
 * @param arg Строка аргумента для обработки
 */
void ArgumentParser::processArgument(const std::string& arg)
{
    if (arg.rfind("--", 0) == 0 || arg.rfind("-", 0) == 0)
    {
        size_t eqPos = arg.find('=');
        if (eqPos != std::string::npos && eqPos > 1)
        {
            std::string key = arg.substr(arg.rfind("-", 0) == 0 ? 1 : 0, eqPos - (arg.rfind("-", 0) == 0 ? 1 : 0));
            std::string value = arg.substr(eqPos + 1);

            if (key.size() > 1 && key[0] == '-')
                key = key.substr(1);

            parameters[key] = value;
            return;
        }

        std::string cleanArg = normalizeFlagName(arg);

        if (arg.rfind("--", 0) == 0)
            flags[cleanArg] = true;
        else if (arg.rfind("-", 0) == 0)
        {
            if (cleanArg.length() > 1)
                for (char c : cleanArg)
                    flags[std::string(1, c)] = true;
            else
                flags[cleanArg] = true;
        }
    }
    else
    {
        positionalArgs.push_back(arg);
    }
}

/**
 * @brief Проверить, был ли предоставлен флаг (реализация)
 * @param flag Имя флага для проверки
 * @return true если флаг присутствует
 */
bool ArgumentParser::hasFlag(const std::string& flag) const
{
    return flags.count(flag) > 0;
}

/**
 * @brief Получить значение параметра по ключу (реализация)
 * @param key Имя параметра для поиска
 * @return Значение параметра или пустая строка, если не найдено
 */
std::string ArgumentParser::getParameter(const std::string& key) const
{
    auto it = parameters.find(key);
    if (it != parameters.end())
        return it->second;
    return "";
}
