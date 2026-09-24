#include "net_monitor.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <syslog.h>

#include <algorithm>
#include <array>
#include <future>

#include "arp_scanner.hpp"
#include "route.hpp"

namespace {

constexpr std::size_t MAX_EVENTS = 500;
constexpr auto DNS_TTL = std::chrono::minutes{10};
constexpr std::size_t DNS_PARALLEL = 8;

std::string reverse_dns(Ipv4 ip) {
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(ip.value);
    std::array<char, NI_MAXHOST> host{};
    if (getnameinfo(reinterpret_cast<sockaddr const *>(&sa), sizeof(sa), host.data(), host.size(), nullptr, 0, NI_NAMEREQD) != 0) {
        return {};
    }
    // Служебные имена nss-myhostname ("_gateway", "_outbound") не являются именами хостов
    return host[0] == '_' ? std::string{} : std::string{host.data()};
}

int event_priority(EVENT kind) {
    switch (kind) {
        case EVENT::IP_CONFLICT:
        case EVENT::MAC_CHANGED:
        case EVENT::DHCP_MULTIPLE_SERVERS:
        case EVENT::DHCP_SHARED_CLIENT_ID:
            return LOG_WARNING;
        case EVENT::HOST_LOST:
        case EVENT::CONFLICT_RESOLVED:
            return LOG_NOTICE;
        case EVENT::NEW_HOST:
        case EVENT::HOST_BACK:
        case EVENT::DHCP_SERVER:
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
    if (m_config.dhcp_watch) {
        m_dhcp = std::make_unique<DhcpWatcher>(m_config, &m_oui, [this](std::vector<Event> const &events) { add_events(events); });
    }
}

void NetMonitor::add_events(std::vector<Event> const &events) {
    std::lock_guard const lock{m_mutex};
    for (auto const &e : events) {
        syslog(event_priority(e.kind), "%s", e.text.c_str());
        m_events.push_back(e);
        if (m_events.size() > MAX_EVENTS) {
            m_events.pop_front();
        }
    }
}

NetMonitor::~NetMonitor() { stop(); }

void NetMonitor::start(std::function<void()> on_scan) {
    m_on_scan = std::move(on_scan);
    m_thread = std::jthread{[this](std::stop_token st) { run(st); }};
    m_resolver = std::jthread{[this](std::stop_token st) { run_resolver(st); }};
    if (m_dhcp) {
        m_dhcp->start();
    }
}

void NetMonitor::stop() {
    if (m_dhcp) {
        m_dhcp->stop();
    }
    m_thread.request_stop();
    m_resolver.request_stop();
    m_cv.notify_all();
    if (m_thread.joinable()) {
        m_thread.join();
    }
    if (m_resolver.joinable()) {
        m_resolver.join();
    }
}

void NetMonitor::run_resolver(std::stop_token const &st) {
    while (!st.stop_requested()) {
        {
            std::unique_lock lock{m_mutex};
            m_cv.wait(lock, st, [this] { return !m_dns_queue.empty(); });
        }
        resolve_pending(st);
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

        std::vector<Event> events;
        {
            std::lock_guard const lock{m_mutex};
            events = m_inventory.update(target.iface, res.hosts, gw, std::chrono::system_clock::now());
        }
        add_events(events);
    }
    if (m_dhcp) {
        m_dhcp->set_interfaces(targets);
    }

    {
        std::lock_guard const lock{m_mutex};
        m_warnings = std::move(warnings);
        m_targets = std::move(targets);
        m_last_scan = std::chrono::system_clock::now();
        ++m_scans;
        queue_names(m_inventory.hosts());
    }
    m_cv.notify_all();
}

void NetMonitor::queue_names(std::vector<Host> const &hosts) {
    auto const now = std::chrono::steady_clock::now();
    for (auto const &h : hosts) {
        auto const it = m_dns.find(h.ip);
        if (it != m_dns.end()) {
            m_inventory.set_hostname(h.ip, it->second.first);
        }
        auto const fresh = it != m_dns.end() && now - it->second.second < DNS_TTL;
        if (h.online && !fresh && std::ranges::find(m_dns_queue, h.ip) == m_dns_queue.end()) {
            m_dns_queue.push_back(h.ip);
        }
    }
}

void NetMonitor::resolve_pending(std::stop_token const &st) {
    while (!st.stop_requested()) {
        std::vector<Ipv4> batch;
        {
            std::lock_guard const lock{m_mutex};
            auto const n = std::min(m_dns_queue.size(), DNS_PARALLEL);
            batch.assign(m_dns_queue.begin(), m_dns_queue.begin() + static_cast<std::ptrdiff_t>(n));
        }
        if (batch.empty()) {
            return;
        }
        std::vector<std::future<std::string>> names;
        names.reserve(batch.size());
        for (auto const ip : batch) {
            names.push_back(std::async(std::launch::async, reverse_dns, ip));
        }
        auto const now = std::chrono::steady_clock::now();
        for (std::size_t i = 0; i < batch.size(); ++i) {
            auto name = names[i].get();
            std::lock_guard const lock{m_mutex};
            m_inventory.set_hostname(batch[i], name);
            m_dns[batch[i]] = {std::move(name), now};
            std::erase(m_dns_queue, batch[i]);
        }
    }
}

NetSnapshot NetMonitor::snapshot() const {
    auto dhcp = m_dhcp ? m_dhcp->snapshot() : DhcpSnapshot{};
    std::lock_guard const lock{m_mutex};
    return {m_inventory.hosts(), {m_events.begin(), m_events.end()}, m_warnings, m_targets, m_last_scan, m_scans, std::move(dhcp)};
}
