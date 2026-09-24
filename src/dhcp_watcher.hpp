#pragma once
#include <chrono>
#include <functional>
#include <map>
#include <mutex>
#include <stop_token>
#include <thread>
#include <vector>

#include "config.hpp"
#include "dhcp_inventory.hpp"
#include "netif.hpp"

/**
 * @brief Прослушивание DHCP на сетевых интерфейсах и активный поиск DHCP-серверов.
 *
 * На каждом интерфейсе открывается сокет AF_PACKET с BPF-фильтром ядра, который пропускает
 * только DHCP (IPv4/UDP, порты 67/68). При включённом dhcp_probe периодически рассылается
 * DHCPDISCOVER; запрос REQUEST не отправляется, поэтому аренда не занимается.
 * Требуется право CAP_NET_RAW. Методы потокобезопасны.
 */
class DhcpWatcher {
   public:
    /**
     * @brief Конструктор.
     * @param config Конфигурация (dhcp_probe, dhcp_probe_interval_sec).
     * @param oui База производителей; должна жить дольше объекта; может быть nullptr.
     * @param on_events Вызывается из фонового потока с новыми событиями.
     */
    DhcpWatcher(Config const &config, OuiDb const *oui, std::function<void(std::vector<Event>)> on_events);

    /**
     * @brief Останавливает фоновый поток.
     */
    ~DhcpWatcher();

    DhcpWatcher(DhcpWatcher const &) = delete;
    DhcpWatcher &operator=(DhcpWatcher const &) = delete;

    /**
     * @brief Запускает фоновый поток.
     */
    void start();

    /**
     * @brief Останавливает фоновый поток и закрывает сокеты.
     */
    void stop();

    /**
     * @brief Задаёт интерфейсы для прослушивания; сокеты открываются и закрываются в фоновом потоке.
     * @param ifaces Интерфейсы.
     */
    void set_interfaces(std::vector<NetInterface> const &ifaces);

    /**
     * @brief Возвращает текущее состояние DHCP.
     */
    [[nodiscard]] DhcpSnapshot snapshot() const;

   private:
    /**
     * @brief Сокет прослушивания на интерфейсе.
     */
    struct Listener {
        NetInterface iface; ///< Интерфейс.
        Mac probe;          ///< MAC для поиска серверов.
        int fd{-1};         ///< Сокет AF_PACKET.
    };

    /**
     * @brief Основной цикл фонового потока.
     */
    void run(std::stop_token const &st);

    /**
     * @brief Открывает и закрывает сокеты в соответствии с заданными интерфейсами.
     * @return Предупреждения об ошибках открытия.
     */
    std::vector<std::string> sync_listeners();

    /**
     * @brief Отправляет DHCPDISCOVER на всех интерфейсах.
     */
    void send_probes();

    /**
     * @brief Читает и учитывает все ожидающие пакеты сокета.
     */
    void drain(Listener const &l);

    DhcpInventory m_inventory;                           // 104
    std::map<int, Listener> m_listeners;                 // 48
    std::function<void(std::vector<Event>)> m_on_events; // 32
    mutable std::mutex m_mutex;                          // 40
    std::vector<NetInterface> m_wanted;                  // 24
    std::jthread m_thread;                               // 16
    std::chrono::seconds m_probe_interval;               // 8
    std::chrono::system_clock::time_point m_last_probe;  // 8
    std::chrono::steady_clock::time_point m_next_probe;  // 8
    bool m_probe;                                        // 1
};
