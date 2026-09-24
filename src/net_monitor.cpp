#include "net_monitor.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <syslog.h>

#include <array>

#include "arp_scanner.hpp"
#include "route.hpp"

namespace {

constexpr std::size_t MAX_EVENTS = 500;
constexpr auto DNS_TTL = std::chrono::minutes{10};

std::string reverse_dns(Ipv4 ip) {
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(ip.value);
    std::array<char, NI_MAXHOST> host{};
    if (getnameinfo(reinterpret_cast<sockaddr const *>(&sa), sizeof(sa), host.data(), host.size(), nullptr, 0, NI_NAMEREQD) != 0) {
        return {};
    }
    return host.data();
}

int event_priority(EVENT kind) {
    switch (kind) {
        case EVENT::IP_CONFLICT:
        case EVENT::MAC_CHANGED:
            return LOG_WARNING;
        case EVENT::HOST_LOST:
        case EVENT::CONFLICT_RESOLVED:
            return LOG_NOTICE;
        case EVENT::NEW_HOST:
        case EVENT::HOST_BACK:
            break;
    }
    return LOG_INFO;
}

} // namespace

NetMonitor::NetMonitor(Config config) : m_config{std::move(config)}, m_inventory{std::chrono::seconds{m_config.host_timeout_sec}, &m_oui} {
    auto const n = m_oui.load(m_config.oui_file);
    if (n == 0) {
        syslog(LOG_WARNING, "База производителей %s не загружена: производитель по MAC не будет показан", m_config.oui_file.c_str());
    } else {
        syslog(LOG_INFO, "Загружена база производителей %s: %zu записей", m_config.oui_file.c_str(), n);
    }
}

NetMonitor::~NetMonitor() { stop(); }

void NetMonitor::start(std::function<void()> on_scan) {
    m_on_scan = std::move(on_scan);
    m_thread = std::jthread{[this](std::stop_token st) { run(st); }};
}

void NetMonitor::stop() {
    if (m_thread.joinable()) {
        m_thread.request_stop();
        m_cv.notify_all();
        m_thread.join();
    }
}

void NetMonitor::run(std::stop_token const &st) {
    while (!st.stop_requested()) {
        try {
            scan_once();
        } catch (std::exception const &ex) {
            syslog(LOG_ERR, "Ошибка сканирования: %s", ex.what());
            std::lock_guard const lock{m_mutex};
            m_warnings = {ex.what()};
        }
        if (m_on_scan) {
            m_on_scan();
        }
        std::unique_lock lock{m_mutex};
        m_cv.wait_for(lock, st, std::chrono::seconds{m_config.scan_interval_sec}, [] { return false; });
    }
}

void NetMonitor::scan_once() {
    auto const plan = plan_scan(list_interfaces(), m_config.interfaces, m_config.max_hosts);
    auto const gateways = default_gateways();
    std::vector<std::string> warnings = plan.warnings;
    std::vector<NetInterface> targets;

    for (auto const &target : plan.targets) {
        ScanResult res;
        try {
            res = ArpScanner{target}.scan(std::chrono::milliseconds{m_config.arp_timeout_ms});
        } catch (std::exception const &ex) {
            warnings.emplace_back(ex.what());
            syslog(LOG_ERR, "%s", ex.what());
            continue;
        }
        targets.push_back(target.iface);
        std::optional<Ipv4> gw;
        if (auto const it = gateways.find(target.iface.name); it != gateways.end() && target.iface.subnet.contains(it->second)) {
            gw = it->second;
        }

        std::lock_guard const lock{m_mutex};
        for (auto const &e : m_inventory.update(target.iface, res.hosts, gw, std::chrono::system_clock::now())) {
            syslog(event_priority(e.kind), "%s", e.text.c_str());
            m_events.push_back(e);
            if (m_events.size() > MAX_EVENTS) {
                m_events.pop_front();
            }
        }
    }

    std::vector<Host> hosts;
    {
        std::lock_guard const lock{m_mutex};
        m_warnings = std::move(warnings);
        m_targets = std::move(targets);
        m_last_scan = std::chrono::system_clock::now();
        ++m_scans;
        hosts = m_inventory.hosts();
    }
    resolve_names(hosts);
}

void NetMonitor::resolve_names(std::vector<Host> const &hosts) {
    auto const now = std::chrono::steady_clock::now();
    for (auto const &h : hosts) {
        if (!h.online) {
            continue;
        }
        {
            std::lock_guard const lock{m_mutex};
            auto const it = m_dns.find(h.ip);
            if (it != m_dns.end() && now - it->second.second < DNS_TTL) {
                m_inventory.set_hostname(h.ip, it->second.first);
                continue;
            }
        }
        auto name = reverse_dns(h.ip);
        std::lock_guard const lock{m_mutex};
        m_inventory.set_hostname(h.ip, name);
        m_dns[h.ip] = {std::move(name), now};
    }
}

NetSnapshot NetMonitor::snapshot() const {
    std::lock_guard const lock{m_mutex};
    return {m_inventory.hosts(), {m_events.begin(), m_events.end()}, m_warnings, m_targets, m_last_scan, m_scans};
}
