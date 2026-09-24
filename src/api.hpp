#pragma once
#include <map>
#include <nlohmann/json.hpp>
#include <string>

#include "net_monitor.hpp"

/**
 * @brief Формирует JSON-ответ /api/network из снимка состояния сети.
 *
 * Время передаётся в миллисекундах от эпохи Unix.
 *
 * @param snap Снимок состояния сети.
 * @param gateways Шлюзы по умолчанию по интерфейсам.
 * @param hostname Имя машины, на которой работает программа.
 * @param scan_interval_sec Период сканирования из конфигурации.
 * @return JSON-объект.
 */
[[nodiscard]] nlohmann::json network_to_json(NetSnapshot const &snap, std::map<std::string, Ipv4> const &gateways, std::string const &hostname,
                                             int scan_interval_sec);
