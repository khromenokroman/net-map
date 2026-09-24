#pragma once
#include <chrono>
#include <map>
#include <set>
#include <vector>

#include "ipv4.hpp"
#include "netif.hpp"

/**
 * @brief Хост, замеченный в сети: пара IP и MAC.
 */
struct Observation {
    Mac mac; ///< MAC-адрес.
    Ipv4 ip; ///< IP-адрес.

    auto operator<=>(Observation const &) const = default;
};

/**
 * @brief Результат сканирования одной подсети.
 */
struct ScanResult {
    std::vector<Observation> hosts; ///< Уникальные пары IP/MAC, отсортированные по IP.
    std::uint64_t sent{};           ///< Отправлено ARP-запросов.
};

/**
 * @brief Находит IP-адреса, на которые ответили несколько разных MAC-адресов.
 * @param hosts Замеченные пары IP/MAC.
 * @return Конфликтующие адреса и их MAC-адреса.
 */
[[nodiscard]] std::map<Ipv4, std::set<Mac>> find_conflicts(std::vector<Observation> const &hosts);

/**
 * @brief Сканер подсети ARP-запросами через сырой сокет AF_PACKET.
 *
 * Рассылает ARP-запрос на каждый адрес подсети, кроме собственного, и собирает ответы.
 * Кроме ответов учитываются ARP-запросы других хостов подсети. Требуется право CAP_NET_RAW.
 */
class ArpScanner {
   public:
    /**
     * @brief Создаёт сканер для подсети интерфейса.
     * @param target Подсеть и интерфейс, через который сканировать.
     */
    explicit ArpScanner(ScanTarget target);

    /**
     * @brief Сканирует подсеть.
     * @param wait Сколько ждать ответов после отправки последнего запроса.
     * @return Замеченные хосты.
     * @throw std::runtime_error если не удалось открыть сырой сокет или отправить запросы.
     */
    [[nodiscard]] ScanResult scan(std::chrono::milliseconds wait) const;

   private:
    ScanTarget m_target; // 64
};
