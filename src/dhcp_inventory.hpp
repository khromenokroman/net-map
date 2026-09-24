#pragma once
#include <chrono>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "dhcp_packet.hpp"
#include "inventory.hpp"
#include "oui.hpp"

/**
 * @brief DHCP-сервер, замеченный в сегменте сети.
 */
struct DhcpServer {
    std::string iface;                                ///< Интерфейс, на котором замечен сервер.
    std::string vendor;                               ///< Производитель по MAC-адресу.
    std::chrono::system_clock::time_point first_seen; ///< Когда замечен впервые.
    std::chrono::system_clock::time_point last_seen;  ///< Последнее сообщение сервера.
    std::optional<Ipv4> router;                       ///< Шлюз, который раздаёт сервер.
    std::optional<std::uint32_t> lease;               ///< Время аренды, секунд.
    std::optional<std::uint8_t> prefix;               ///< Длина префикса выдаваемой подсети.
    std::uint64_t messages{};                         ///< Число сообщений сервера.
    Mac mac;                                          ///< MAC-адрес отправителя ответов.
    Ipv4 ip;                                          ///< Адрес сервера (Server-ID или IP отправителя).
    Ipv4 last_offered;                                ///< Последний выданный или предложенный адрес.
    bool answered_probe{};                            ///< Ответил на наш DHCPDISCOVER.
};

/**
 * @brief DHCP-клиент, замеченный по его запросам.
 */
struct DhcpClient {
    std::string iface;                                ///< Интерфейс, на котором замечен клиент.
    std::string client_id;                            ///< Client-ID (опция 61), hex.
    std::string hostname;                             ///< Имя хоста (опция 12).
    std::string vendor_class;                         ///< Vendor class (опция 60).
    std::chrono::system_clock::time_point first_seen; ///< Когда замечен впервые.
    std::chrono::system_clock::time_point last_seen;  ///< Последнее сообщение клиента.
    std::optional<Ipv4> requested_ip;                 ///< Запрошенный адрес (опция 50) или текущий (ciaddr).
    std::optional<Ipv4> server_id;                    ///< Сервер, выбранный клиентом (опция 54).
    Mac mac;                                          ///< MAC клиента (chaddr).
    DHCP_TYPE last_type{};                            ///< Тип последнего сообщения.
};

/**
 * @brief Снимок состояния DHCP в сети.
 */
struct DhcpSnapshot {
    std::vector<DhcpServer> servers;                           ///< Замеченные серверы.
    std::vector<DhcpClient> clients;                           ///< Замеченные клиенты.
    std::map<std::string, std::vector<Mac>> shared_client_ids; ///< Client-ID, используемые несколькими MAC.
    std::chrono::system_clock::time_point last_probe;          ///< Когда отправлялся последний DHCPDISCOVER.
    bool watching{};                                           ///< Идёт прослушивание DHCP.
    bool probing{};                                            ///< Включён активный поиск серверов.
};

/**
 * @brief Учёт DHCP-серверов и клиентов по перехваченным сообщениям и формирование событий.
 */
class DhcpInventory {
   public:
    using clock = std::chrono::system_clock;

    /**
     * @brief Конструктор.
     * @param oui База производителей; может быть nullptr.
     */
    explicit DhcpInventory(OuiDb const *oui);

    /**
     * @brief Учитывает перехваченное DHCP-сообщение.
     * @param iface Интерфейс, на котором перехвачено сообщение.
     * @param frame Сообщение.
     * @param probe MAC, которым программа ищет серверы на этом интерфейсе (такие запросы не считаются клиентом).
     * @param now Текущее время.
     * @return События.
     */
    std::vector<Event> update(std::string const &iface, DhcpFrame const &frame, Mac const &probe, clock::time_point now);

    /**
     * @brief Удаляет серверы и клиентов, не замеченных дольше суток.
     * @param now Текущее время.
     */
    void purge(clock::time_point now);

    /**
     * @brief Возвращает серверы, клиентов и общие Client-ID.
     */
    [[nodiscard]] DhcpSnapshot snapshot() const;

   private:
    /**
     * @brief Возвращает MAC-адреса клиентов, использующих Client-ID.
     */
    [[nodiscard]] std::vector<Mac> macs_of(std::string const &client_id) const;

    std::map<std::pair<Ipv4, Mac>, DhcpServer> m_servers; // 48
    std::map<Mac, DhcpClient> m_clients;                  // 48
    OuiDb const *m_oui;                                   // 8
};
