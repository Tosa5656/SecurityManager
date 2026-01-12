# Security Manager | JSON
Здесь хранится библиотека для взаимодействия с JSON в C++.  
Все права на код пренадлежат [nlohmann](https://github.com/nlohmann/json)

## Примеры использования
### Чтение из файла .json
```cpp
#include <fstream>
#include <nlohmann/json.hpp>
using json = nlohmann::json;

//...
std::ifstream f("example.json");
json data = json::parse(f);
```

```cpp
import std;
import nlohmann.json;

using json = nlohmann::json;

// ...

std::ifstream f("example.json");
json data = json::parse(f);
```
### Создание JSON объекта
```cpp
// Using (raw) string literals and json::parse
json ex1 = json::parse(R"(
  {
    "pi": 3.141,
    "happy": true
  }
)");

// Using user-defined (raw) string literals
using namespace nlohmann::literals;
json ex2 = R"(
  {
    "pi": 3.141,
    "happy": true
  }
)"_json;

// Using initializer lists
json ex3 = {
  {"happy", true},
  {"pi", 3.141},
};
```