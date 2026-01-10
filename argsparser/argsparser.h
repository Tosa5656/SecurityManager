/**
 * @file argsparser.h
 * @brief Парсер аргументов командной строки для инструментов Security Manager
 * @author Tosa5656
 * @date 28 декабря, 2026
 */

#ifndef ARGUMENT_PARSER_H
#define ARGUMENT_PARSER_H

#include <string>
#include <vector>
#include <map>
#include <iostream>
#include <algorithm>

/**
 * @brief Класс парсера аргументов командной строки
 *
 * Разбирает аргументы командной строки, включая флаги, параметры и позиционные аргументы.
 * Поддерживает короткий (-) и длинный (--) форматы флагов.
 */
class ArgumentParser
{
public:
    /**
     * @brief Конструктор, который разбирает аргументы командной строки
     * @param argc Количество аргументов командной строки
     * @param argv Массив аргументов командной строки
     */
    ArgumentParser(int argc, char* argv[]);

    /**
     * @brief Проверить, был ли предоставлен флаг
     * @param flag Имя флага для проверки (без ведущих дефисов)
     * @return true если флаг присутствует, false в противном случае
     */
    bool hasFlag(const std::string& flag) const;

    /**
     * @brief Получить значение параметра по ключу
     * @param key Имя параметра для поиска
     * @return Значение параметра или пустая строка, если не найдено
     */
    std::string getParameter(const std::string& key) const;

    /**
     * @brief Получить позиционные аргументы (аргументы без флагов)
     * @return Вектор позиционных аргументов
     */
    const std::vector<std::string>& getPositionalArguments() const { return positionalArgs; }

private:
    std::map<std::string, bool> flags;
    std::map<std::string, std::string> parameters;
    std::vector<std::string> positionalArgs;

    std::string normalizeFlagName(const std::string& rawFlag) const;
    void processArgument(const std::string& arg);
};

#endif