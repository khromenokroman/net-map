#include "web_server.hpp"

#include <fmt/format.h>
#include <syslog.h>
#include <unistd.h>

#include <array>
#include <climits>
#include <stdexcept>

#include "api.hpp"
#include "index_page.hpp"
#include "route.hpp"

namespace {

std::string hostname() {
    std::array<char, HOST_NAME_MAX + 1> buf{};
    return gethostname(buf.data(), buf.size() - 1) == 0 ? std::string{buf.data()} : std::string{};
}

} // namespace

WebServer::WebServer(Config const &config, NetMonitor const &monitor) : m_config{config}, m_monitor{monitor} {}

void WebServer::run() {
    m_server.Get("/", [](httplib::Request const &req, httplib::Response &res) {
        syslog(LOG_DEBUG, "Поступил запрос('/') от %s:%d", req.remote_addr.c_str(), req.remote_port);
        res.set_content(index_page().data(), index_page().size(), "text/html; charset=utf-8");
    });

    m_server.Get("/api/network", [this](httplib::Request const &req, httplib::Response &res) {
        syslog(LOG_DEBUG, "Поступил запрос('/api/network') от %s:%d", req.remote_addr.c_str(), req.remote_port);
        auto const body = network_to_json(m_monitor.snapshot(), default_gateways(), hostname(), m_config.scan_interval_sec).dump();
        res.set_header("Cache-Control", "no-store");
        res.set_content(body, "application/json; charset=utf-8");
    });

    m_server.set_socket_options([](socket_t sock) {
        int const opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    });
    if (!m_server.bind_to_port(m_config.listen_addr, m_config.port)) {
        auto const msg = fmt::format("Не удалось занять адрес {}:{}", m_config.listen_addr, m_config.port);
        syslog(LOG_ERR, "%s", msg.c_str());
        throw std::runtime_error(msg);
    }
    syslog(LOG_NOTICE, "Запущен сервер на http://%s:%d", m_config.listen_addr.c_str(), m_config.port);
    m_server.listen_after_bind();
    syslog(LOG_NOTICE, "Сервер остановлен");
}

void WebServer::stop() { m_server.stop(); }
