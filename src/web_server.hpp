#pragma once
#include <httplib.h>

#include "config.hpp"
#include "net_monitor.hpp"

/**
 * @brief HTTP-сервер: страница с картой сети и JSON API.
 */
class WebServer {
   public:
    /**
     * @brief Конструктор.
     * @param config Конфигурация (адрес, порт, период сканирования).
     * @param monitor Источник данных о сети; должен жить дольше сервера.
     */
    WebServer(Config const &config, NetMonitor const &monitor);

    /**
     * @brief Регистрирует маршруты и запускает сервер. Блокирует поток до вызова stop().
     * @throw std::runtime_error если не удалось занять адрес и порт.
     */
    void run();

    /**
     * @brief Останавливает сервер. Может вызываться из другого потока.
     */
    void stop();

   private:
    httplib::Server m_server;    // 824
    Config const &m_config;      // 8
    NetMonitor const &m_monitor; // 8
};
