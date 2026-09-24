#include "dhcp_watcher.hpp"

#include <arpa/inet.h>
#include <fmt/format.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <random>
#include <system_error>

namespace {

constexpr int POLL_MS = 500;

int open_listener(NetInterface const &iface) {
    auto const fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, htons(ETH_P_IP));
    if (fd < 0) {
        throw std::system_error(errno, std::generic_category(), fmt::format("{}: не удалось открыть сокет DHCP", iface.name));
    }
    auto const bpf = dhcp_bpf_filter();
    sock_fprog prog{static_cast<unsigned short>(bpf.size()), reinterpret_cast<sock_filter *>(const_cast<BpfInsn *>(bpf.data()))};
    sockaddr_ll addr{};
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_IP);
    addr.sll_ifindex = iface.index;
    if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) != 0 ||
        bind(fd, reinterpret_cast<sockaddr const *>(&addr), sizeof(addr)) != 0) {
        auto const err = errno;
        close(fd);
        throw std::system_error(err, std::generic_category(), fmt::format("{}: не удалось настроить сокет DHCP", iface.name));
    }
    std::array<std::uint8_t, 2048> buf{};
    while (recv(fd, buf.data(), buf.size(), MSG_DONTWAIT) > 0) {
    }
    return fd;
}

} // namespace

DhcpWatcher::DhcpWatcher(Config const &config, OuiDb const *oui, std::function<void(std::vector<Event>)> on_events)
    : m_inventory{oui}, m_on_events{std::move(on_events)}, m_probe_interval{config.dhcp_probe_interval_sec}, m_probe{config.dhcp_probe} {}

DhcpWatcher::~DhcpWatcher() { stop(); }

void DhcpWatcher::start() {
    m_next_probe = std::chrono::steady_clock::now();
    m_thread = std::jthread{[this](std::stop_token st) { run(st); }};
}

void DhcpWatcher::stop() {
    if (m_thread.joinable()) {
        m_thread.request_stop();
        m_thread.join();
    }
    std::lock_guard const lock{m_mutex};
    for (auto const &[fd, l] : m_listeners) {
        close(fd);
    }
    m_listeners.clear();
}

void DhcpWatcher::set_interfaces(std::vector<NetInterface> const &ifaces) {
    std::lock_guard const lock{m_mutex};
    m_wanted = ifaces;
}

std::vector<std::string> DhcpWatcher::sync_listeners() {
    std::vector<NetInterface> wanted;
    {
        std::lock_guard const lock{m_mutex};
        wanted = m_wanted;
    }
    std::vector<std::string> warnings;
    std::lock_guard const lock{m_mutex};
    for (auto it = m_listeners.begin(); it != m_listeners.end();) {
        auto const keep =
            std::ranges::any_of(wanted, [&](NetInterface const &w) { return w.index == it->second.iface.index && w.addr == it->second.iface.addr; });
        if (keep) {
            ++it;
        } else {
            close(it->first);
            it = m_listeners.erase(it);
        }
    }
    for (auto const &w : wanted) {
        auto const exists = std::ranges::any_of(m_listeners, [&](auto const &kv) { return kv.second.iface.index == w.index; });
        if (exists) {
            continue;
        }
        try {
            auto const fd = open_listener(w);
            m_listeners.emplace(fd, Listener{w, probe_mac(w.mac), fd});
            syslog(LOG_INFO, "Прослушивание DHCP на %s", w.name.c_str());
        } catch (std::exception const &ex) {
            warnings.emplace_back(ex.what());
        }
    }
    return warnings;
}

void DhcpWatcher::send_probes() {
    static std::mt19937 rng{std::random_device{}()};
    std::lock_guard const lock{m_mutex};
    for (auto const &[fd, l] : m_listeners) {
        auto const frame = build_dhcp_discover(l.iface.mac, l.probe, static_cast<std::uint32_t>(rng()));
        sockaddr_ll dst{};
        dst.sll_family = AF_PACKET;
        dst.sll_protocol = htons(ETH_P_IP);
        dst.sll_ifindex = l.iface.index;
        dst.sll_halen = 6;
        std::fill_n(dst.sll_addr, 6, 0xff);
        if (sendto(fd, frame.data(), frame.size(), 0, reinterpret_cast<sockaddr const *>(&dst), sizeof(dst)) < 0) {
            syslog(LOG_ERR, "%s: не удалось отправить DHCPDISCOVER: %s", l.iface.name.c_str(), std::generic_category().message(errno).c_str());
        } else {
            syslog(LOG_INFO, "%s: отправлен DHCPDISCOVER для поиска DHCP-серверов", l.iface.name.c_str());
        }
    }
    m_last_probe = std::chrono::system_clock::now();
}

void DhcpWatcher::drain(Listener const &l) {
    std::array<std::uint8_t, 2048> buf{};
    for (;;) {
        sockaddr_ll from{};
        socklen_t from_len = sizeof(from);
        auto const n = recvfrom(l.fd, buf.data(), buf.size(), MSG_DONTWAIT, reinterpret_cast<sockaddr *>(&from), &from_len);
        if (n <= 0) {
            return;
        }
        if (from.sll_pkttype == PACKET_OUTGOING) {
            continue;
        }
        auto const frame = parse_dhcp_frame(std::span{buf.data(), static_cast<std::size_t>(n)});
        if (!frame) {
            continue;
        }
        std::vector<Event> events;
        {
            std::lock_guard const lock{m_mutex};
            events = m_inventory.update(l.iface.name, *frame, l.probe, std::chrono::system_clock::now());
        }
        if (!events.empty() && m_on_events) {
            m_on_events(std::move(events));
        }
    }
}

void DhcpWatcher::run(std::stop_token const &st) {
    std::vector<std::string> last_warnings;
    auto next_sync = std::chrono::steady_clock::now();
    while (!st.stop_requested()) {
        auto const now = std::chrono::steady_clock::now();
        if (now >= next_sync) {
            auto warnings = sync_listeners();
            if (warnings != last_warnings) {
                for (auto const &w : warnings) {
                    syslog(LOG_ERR, "%s", w.c_str());
                }
                last_warnings = std::move(warnings);
            }
            next_sync = now + std::chrono::seconds{5};
            std::lock_guard const lock{m_mutex};
            m_inventory.purge(std::chrono::system_clock::now());
        }
        bool have_listeners{};
        {
            std::lock_guard const lock{m_mutex};
            have_listeners = !m_listeners.empty();
        }
        if (m_probe && have_listeners && now >= m_next_probe) {
            send_probes();
            m_next_probe = now + m_probe_interval;
        }

        std::vector<Listener> ls;
        {
            std::lock_guard const lock{m_mutex};
            for (auto const &[fd, l] : m_listeners) {
                ls.push_back(l);
            }
        }
        std::vector<pollfd> fds;
        for (auto const &l : ls) {
            fds.push_back({l.fd, POLLIN, 0});
        }
        if (fds.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds{POLL_MS});
            continue;
        }
        if (poll(fds.data(), fds.size(), POLL_MS) <= 0) {
            continue;
        }
        for (std::size_t i = 0; i < fds.size(); ++i) {
            if ((fds[i].revents & POLLIN) != 0) {
                drain(ls[i]);
            }
        }
    }
}

DhcpSnapshot DhcpWatcher::snapshot() const {
    std::lock_guard const lock{m_mutex};
    auto snap = m_inventory.snapshot();
    snap.watching = !m_listeners.empty();
    snap.probing = m_probe;
    snap.last_probe = m_last_probe;
    return snap;
}
