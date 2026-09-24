#pragma once
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

#include "config.hpp"
#include "inventory.hpp"
#include "oui.hpp"

/**
 * @brief Снимок состояния сети для отображения.
 */
struct NetSnapshot {
    std::vector<Host> hosts;                         ///< Все известные хосты.
    std::vector<Event> events;                       ///< Последние события, новые в конце.
    std::vector<std::string> warnings;               ///< Предупреждения последнего цикла сканирования.
    std::vector<NetInterface> targets;               ///< Сканируемые подсети.
    std::chrono::system_clock::time_point last_scan; ///< Когда закончилось последнее сканирование.
    std::uint64_t scans{};                           ///< Число выполненных циклов сканирования.
};

/**
 * @brief Фоновый мониторинг сети.
 *
 * Периодически сканирует подсети ARP-запросами, ведёт учёт хостов, определяет имена
 * через обратный DNS и пишет события в syslog. Методы потокобезопасны.
 */
class NetMonitor {
   public:
    /**
     * @brief Конструктор. Загружает базу производителей.
     * @param config Проверенная конфигурация.
     */
    explicit NetMonitor(Config config);

    /**
     * @brief Останавливает фоновый поток.
     */
    ~NetMonitor();

    NetMonitor(NetMonitor const &) = delete;
    NetMonitor &operator=(NetMonitor const &) = delete;

    /**
     * @brief Запускает фоновое сканирование.
     * @param on_scan Вызывается после каждого цикла сканирования (из фонового потока); может быть пустым.
     */
    void start(std::function<void()> on_scan = {});

    /**
     * @brief Останавливает фоновое сканирование и ждёт завершения потока.
     */
    void stop();

    /**
     * @brief Выполняет один цикл сканирования в текущем потоке.
     */
    void scan_once();

    /**
     * @brief Возвращает текущее состояние сети.
     */
    [[nodiscard]] NetSnapshot snapshot() const;

   private:
    /**
     * @brief Определяет имена хостов через обратный DNS (с кэшем).
     * @param hosts Хосты, для которых нужно имя.
     */
    void resolve_names(std::vector<Host> const &hosts);

    /**
     * @brief Основной цикл фонового потока.
     */
    void run(std::stop_token const &st);

    Config m_config;                                                                     // 120
    Inventory m_inventory;                                                               // 112
    std::deque<Event> m_events;                                                          // 80
    std::condition_variable_any m_cv;                                                    // 64
    OuiDb m_oui;                                                                         // 56
    std::map<Ipv4, std::pair<std::string, std::chrono::steady_clock::time_point>> m_dns; // 48
    mutable std::mutex m_mutex;                                                          // 40
    std::function<void()> m_on_scan;                                                     // 32
    std::vector<std::string> m_warnings;                                                 // 24
    std::vector<NetInterface> m_targets;                                                 // 24
    std::jthread m_thread;                                                               // 16
    std::chrono::system_clock::time_point m_last_scan;                                   // 8
    std::uint64_t m_scans{};                                                             // 8
};
