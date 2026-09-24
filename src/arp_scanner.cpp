#include "arp_scanner.hpp"

#include <arpa/inet.h>
#include <fmt/format.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <stdexcept>
#include <system_error>
#include <thread>

#include "arp_packet.hpp"

namespace {

constexpr auto SEND_INTERVAL = std::chrono::microseconds{2000};

/**
 * @brief Владеющая обёртка над файловым дескриптором.
 */
class Fd {
   public:
    explicit Fd(int fd) : m_fd{fd} {}
    Fd(Fd const &) = delete;
    Fd &operator=(Fd const &) = delete;
    ~Fd() {
        if (m_fd >= 0) {
            close(m_fd);
        }
    }
    [[nodiscard]] int get() const { return m_fd; }

   private:
    int m_fd; // 4
};

std::runtime_error sys_error(std::string_view what, int err) {
    auto msg = fmt::format("{}: {}", what, std::generic_category().message(err));
    if (err == EPERM || err == EACCES) {
        msg += " (нужно право CAP_NET_RAW: запустите от root или через systemd с AmbientCapabilities=CAP_NET_RAW)";
    }
    return std::runtime_error{msg};
}

} // namespace

std::map<Ipv4, std::set<Mac>> find_conflicts(std::vector<Observation> const &hosts) {
    std::map<Ipv4, std::set<Mac>> by_ip;
    for (auto const &h : hosts) {
        by_ip[h.ip].insert(h.mac);
    }
    std::erase_if(by_ip, [](auto const &kv) { return kv.second.size() < 2; });
    return by_ip;
}

ArpScanner::ArpScanner(ScanTarget target) : m_target{std::move(target)} {}

ScanResult ArpScanner::scan(std::chrono::milliseconds wait) const {
    auto const &iface = m_target.iface;
    Fd const sock{socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ARP))};
    if (sock.get() < 0) {
        throw sys_error(fmt::format("{}: не удалось открыть сырой сокет", iface.name), errno);
    }

    sockaddr_ll addr{};
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ARP);
    addr.sll_ifindex = iface.index;
    if (bind(sock.get(), reinterpret_cast<sockaddr const *>(&addr), sizeof(addr)) != 0) {
        throw sys_error(fmt::format("{}: не удалось привязать сокет к интерфейсу", iface.name), errno);
    }

    sockaddr_ll dst = addr;
    dst.sll_halen = 6;
    std::fill_n(dst.sll_addr, 6, 0xff);

    std::set<Observation> seen;
    auto const drain = [&](int timeout_ms) {
        std::array<std::uint8_t, 1500> buf{};
        for (;;) {
            pollfd pfd{sock.get(), POLLIN, 0};
            if (poll(&pfd, 1, timeout_ms) <= 0) {
                return;
            }
            sockaddr_ll from{};
            socklen_t from_len = sizeof(from);
            auto const n = recvfrom(sock.get(), buf.data(), buf.size(), MSG_DONTWAIT, reinterpret_cast<sockaddr *>(&from), &from_len);
            if (n <= 0) {
                return;
            }
            if (from.sll_pkttype == PACKET_OUTGOING) {
                continue;
            }
            auto const sender = parse_arp_frame(std::span{buf.data(), static_cast<std::size_t>(n)});
            if (sender && sender->ip.value != 0 && iface.subnet.contains(sender->ip) && sender->mac != iface.mac) {
                seen.insert({sender->mac, sender->ip});
            }
            timeout_ms = 0;
        }
    };

    ScanResult result;
    auto const &subnet = iface.subnet;
    for (std::uint64_t ip = subnet.first_host().value; ip <= subnet.last_host().value; ++ip) {
        if (ip == iface.addr.value) {
            continue;
        }
        auto const frame = build_arp_request(iface.mac, iface.addr, Ipv4{static_cast<std::uint32_t>(ip)});
        if (sendto(sock.get(), frame.data(), frame.size(), 0, reinterpret_cast<sockaddr const *>(&dst), sizeof(dst)) < 0) {
            throw sys_error(fmt::format("{}: не удалось отправить ARP-запрос", iface.name), errno);
        }
        ++result.sent;
        drain(0);
        std::this_thread::sleep_for(SEND_INTERVAL);
    }

    auto const deadline = std::chrono::steady_clock::now() + wait;
    for (auto now = std::chrono::steady_clock::now(); now < deadline; now = std::chrono::steady_clock::now()) {
        drain(static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count()));
    }

    result.hosts.assign(seen.begin(), seen.end());
    std::ranges::sort(result.hosts, [](Observation const &a, Observation const &b) { return std::tie(a.ip, a.mac) < std::tie(b.ip, b.mac); });
    return result;
}
