#pragma once
#include <string>
#include <vector>

#include "ipv4.hpp"

/**
 * @brief IPv4-адрес на сетевом интерфейсе.
 *
 * Если на интерфейсе несколько IPv4-адресов, каждый описывается отдельной записью.
 */
struct NetInterface {
    std::string name; ///< Имя интерфейса, например "eth0".
    Subnet subnet;    ///< Подсеть адреса.
    Mac mac;          ///< MAC-адрес интерфейса.
    Ipv4 addr;        ///< Адрес интерфейса.
    int index{};      ///< Индекс интерфейса в ядре.
    bool up{};        ///< Интерфейс поднят (IFF_UP и IFF_RUNNING).
    bool arp{};       ///< Интерфейс поддерживает ARP (не loopback, не point-to-point, без IFF_NOARP).
};

/**
 * @brief Возвращает IPv4-адреса всех сетевых интерфейсов системы.
 * @throw std::runtime_error если getifaddrs завершился ошибкой.
 */
[[nodiscard]] std::vector<NetInterface> list_interfaces();

/**
 * @brief Подсеть, которую нужно сканировать, и интерфейс, через который это делать.
 */
struct ScanTarget {
    NetInterface iface; ///< Интерфейс и его адрес в подсети.
};

/**
 * @brief Результат выбора подсетей для сканирования.
 */
struct ScanPlan {
    std::vector<ScanTarget> targets;   ///< Подсети для сканирования.
    std::vector<std::string> warnings; ///< Пропущенные интерфейсы и причины.
};

/**
 * @brief Выбирает подсети для сканирования.
 *
 * Если список имён пуст, берутся все поднятые интерфейсы с поддержкой ARP.
 * Подсети больше max_hosts адресов пропускаются с предупреждением, как и
 * указанные в конфигурации, но отсутствующие или не подходящие интерфейсы.
 *
 * @param all Все IPv4-адреса интерфейсов системы.
 * @param names Имена интерфейсов из конфигурации; пустой список — автоматический выбор.
 * @param max_hosts Максимальное число адресов в сканируемой подсети.
 * @return План сканирования.
 */
[[nodiscard]] ScanPlan plan_scan(std::vector<NetInterface> const &all, std::vector<std::string> const &names, std::uint64_t max_hosts);
