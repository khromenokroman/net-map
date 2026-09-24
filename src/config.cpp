#include "config.hpp"

#include <fmt/format.h>

#include <cerrno>
#include <fstream>
#include <stdexcept>
#include <system_error>

namespace {

template <typename T>
void read_int(nlohmann::json const &j, std::string_view key, T &out, T min, T max) {
    if (!j.contains(key)) {
        return;
    }
    auto const &v = j.at(key);
    if (!v.is_number_integer()) {
        throw std::runtime_error(fmt::format("Поле \"{}\" должно быть целым числом", key));
    }
    auto const value = v.get<std::int64_t>();
    if (value < static_cast<std::int64_t>(min) || value > static_cast<std::int64_t>(max)) {
        throw std::runtime_error(fmt::format("Поле \"{}\": {} вне допустимого диапазона {}-{}", key, value, min, max));
    }
    out = static_cast<T>(value);
}

} // namespace

Config parse_config(nlohmann::json const &j) {
    if (!j.is_object()) {
        throw std::runtime_error("Конфигурация должна быть JSON-объектом");
    }

    Config cfg;
    if (j.contains("listen_addr")) {
        if (!j.at("listen_addr").is_string()) {
            throw std::runtime_error("Поле \"listen_addr\" должно быть строкой");
        }
        cfg.listen_addr = j.at("listen_addr").get<std::string>();
    }
    read_int(j, "port", cfg.port, 1, 65535);
    read_int(j, "log_level", cfg.log_level, 0, 7);
    read_int(j, "scan_interval_sec", cfg.scan_interval_sec, 5, 86400);
    read_int(j, "host_timeout_sec", cfg.host_timeout_sec, 10, 30 * 86400);
    read_int(j, "arp_timeout_ms", cfg.arp_timeout_ms, 100, 10000);
    read_int(j, "max_hosts", cfg.max_hosts, std::uint64_t{1}, std::uint64_t{65536});

    if (j.contains("interfaces")) {
        auto const &ifs = j.at("interfaces");
        if (!ifs.is_array()) {
            throw std::runtime_error("Поле \"interfaces\" должно быть массивом");
        }
        for (std::size_t i = 0; i < ifs.size(); ++i) {
            if (!ifs[i].is_string() || ifs[i].get<std::string>().empty()) {
                throw std::runtime_error(fmt::format("interfaces[{}]: ожидается непустое имя интерфейса", i));
            }
            cfg.interfaces.push_back(ifs[i].get<std::string>());
        }
    }
    return cfg;
}

Config load_config(std::string_view path) {
    std::ifstream file{std::string{path}};
    if (!file.is_open()) {
        auto const err = errno;
        throw std::runtime_error(fmt::format("Не могу открыть настройки({}): {}", path, std::generic_category().message(err)));
    }
    nlohmann::json j;
    try {
        file >> j;
    } catch (nlohmann::json::parse_error const &ex) {
        throw std::runtime_error(fmt::format("Ошибка разбора настроек({}): {}", path, ex.what()));
    }
    return parse_config(j);
}
