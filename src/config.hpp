#pragma once
#include <cstdint>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <vector>

/**
 * @brief Конфигурация приложения.
 */
struct Config {
    std::string listen_addr{"0.0.0.0"};                   ///< Адрес, на котором слушает HTTP-сервер.
    std::string oui_file{"/usr/share/ieee-data/oui.txt"}; ///< База производителей по MAC (пакет ieee-data).
    std::vector<std::string> interfaces{}; ///< Интерфейсы для сканирования; пусто — все подходящие.
    std::uint64_t max_hosts{4096};         ///< Максимальное число адресов в сканируемой подсети.
    int port{8081};                        ///< Порт HTTP-сервера.
    int log_level{6};                      ///< Уровень логирования syslog.
    int scan_interval_sec{60};             ///< Период сканирования, секунд.
    int host_timeout_sec{600};         ///< Через сколько секунд без ответа хост считается пропавшим.
    int arp_timeout_ms{1000};          ///< Сколько ждать ответов после рассылки ARP-запросов, мс.
    int dhcp_probe_interval_sec{3600}; ///< Период активного поиска DHCP-серверов, секунд.
    bool dhcp_watch{true};             ///< Прослушивать DHCP на сканируемых интерфейсах.
    bool dhcp_probe{false};            ///< Периодически рассылать DHCPDISCOVER для поиска серверов.
};

/**
 * @brief Разбирает и проверяет конфигурацию из JSON. Все поля необязательны.
 * @param j JSON-объект конфигурации.
 * @return Проверенная конфигурация.
 * @throw std::runtime_error при некорректной конфигурации.
 */
[[nodiscard]] Config parse_config(nlohmann::json const &j);

/**
 * @brief Загружает конфигурацию из файла.
 * @param path Путь к JSON-файлу конфигурации.
 * @return Проверенная конфигурация.
 * @throw std::runtime_error если файл не открывается или содержит ошибки.
 */
[[nodiscard]] Config load_config(std::string_view path);
