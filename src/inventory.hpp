#pragma once
#include <chrono>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "arp_scanner.hpp"
#include "ipv4.hpp"
#include "netif.hpp"
#include "oui.hpp"

/**
 * @brief Вид события в сети.
 */
enum class EVENT {
    NEW_HOST,          ///< Появился новый хост.
    HOST_LOST,         ///< Хост перестал отвечать дольше host_timeout.
    HOST_BACK,         ///< Пропавший хост снова отвечает.
    MAC_CHANGED,       ///< IP-адрес теперь отвечает с другого MAC.
    IP_CONFLICT,       ///< На один IP отвечают несколько MAC.
    CONFLICT_RESOLVED, ///< Конфликт IP-адреса пропал.
};

/**
 * @brief Возвращает строковое имя вида события ("new_host", "ip_conflict" и т.д.).
 */
[[nodiscard]] std::string_view event_name(EVENT kind);

/**
 * @brief Событие в сети.
 */
struct Event {
    std::string text;                           ///< Описание события.
    std::chrono::system_clock::time_point time; ///< Время события.
    Mac mac;                                    ///< MAC-адрес хоста.
    Ipv4 ip;                                    ///< IP-адрес хоста.
    EVENT kind{};                               ///< Вид события.
};

/**
 * @brief Хост в сети: пара IP/MAC и сведения о нём.
 */
struct Host {
    std::string iface;                                ///< Интерфейс, через который виден хост.
    std::string vendor;                               ///< Производитель по MAC-адресу.
    std::string hostname;                             ///< Имя из обратного DNS.
    std::chrono::system_clock::time_point first_seen; ///< Когда хост замечен впервые.
    std::chrono::system_clock::time_point last_seen;  ///< Когда хост отвечал последний раз.
    Subnet subnet;                                    ///< Подсеть хоста.
    Mac mac;                                          ///< MAC-адрес.
    Ipv4 ip;                                          ///< IP-адрес.
    bool self{};      ///< Это адрес самой машины, на которой работает программа.
    bool gateway{};   ///< Хост — шлюз по умолчанию.
    bool online{};    ///< Хост отвечал не дольше host_timeout назад.
    bool conflict{};  ///< На IP хоста отвечает ещё хотя бы один MAC.
    bool local_mac{}; ///< MAC-адрес локально администрируемый.
};

/**
 * @brief Учёт хостов по результатам сканирований и формирование событий.
 */
class Inventory {
   public:
    using clock = std::chrono::system_clock;

    /**
     * @brief Конструктор.
     * @param host_timeout Через сколько без ответа хост считается пропавшим.
     * @param oui База производителей; может быть nullptr.
     */
    Inventory(std::chrono::seconds host_timeout, OuiDb const *oui);

    /**
     * @brief Учитывает результат сканирования подсети интерфейса.
     * @param iface Интерфейс и его адрес в подсети.
     * @param seen Хосты, ответившие при сканировании.
     * @param gateway Шлюз по умолчанию через этот интерфейс, если есть.
     * @param now Текущее время.
     * @return События, произошедшие в подсети.
     */
    std::vector<Event> update(NetInterface const &iface, std::vector<Observation> const &seen, std::optional<Ipv4> gateway, clock::time_point now);

    /**
     * @brief Задаёт имя хоста из обратного DNS для всех записей с этим IP.
     * @param ip IP-адрес.
     * @param name Имя; пустая строка — имя неизвестно.
     */
    void set_hostname(Ipv4 ip, std::string const &name);

    /**
     * @brief Возвращает все известные хосты, отсортированные по подсети и IP.
     */
    [[nodiscard]] std::vector<Host> hosts() const;

   private:
    /**
     * @brief Создаёт запись о новом хосте.
     */
    Host make_host(NetInterface const &iface, Observation const &obs, clock::time_point now) const;

    std::map<std::pair<Ipv4, Mac>, Host> m_hosts; // 48
    std::set<Ipv4> m_conflicts;                   // 48
    std::chrono::seconds m_timeout;               // 8
    OuiDb const *m_oui;                           // 8
};
