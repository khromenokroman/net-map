#pragma once
#include <map>
#include <string>
#include <string_view>

#include "ipv4.hpp"

/**
 * @brief Разбирает таблицу маршрутов /proc/net/route и находит шлюзы по умолчанию.
 * @param text Содержимое /proc/net/route.
 * @return Шлюз по умолчанию для каждого интерфейса, у которого он есть (маршрут с наименьшей метрикой).
 */
[[nodiscard]] std::map<std::string, Ipv4> parse_default_gateways(std::string_view text);

/**
 * @brief Читает /proc/net/route и возвращает шлюзы по умолчанию по интерфейсам.
 */
[[nodiscard]] std::map<std::string, Ipv4> default_gateways();
