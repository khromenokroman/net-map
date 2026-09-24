#include "netif.hpp"

#include <arpa/inet.h>
#include <fmt/format.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <net/if.h>

#include <algorithm>
#include <bit>
#include <cerrno>
#include <map>
#include <memory>
#include <stdexcept>
#include <system_error>

std::vector<NetInterface> list_interfaces() {
    ifaddrs *raw{};
    if (getifaddrs(&raw) != 0) {
        throw std::runtime_error(fmt::format("Не удалось получить список интерфейсов: {}", std::generic_category().message(errno)));
    }
    std::unique_ptr<ifaddrs, decltype(&freeifaddrs)> const guard{raw, freeifaddrs};

    std::map<std::string, Mac> macs;
    for (auto const *ifa = raw; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr != nullptr && ifa->ifa_addr->sa_family == AF_PACKET) {
            auto const *ll = reinterpret_cast<sockaddr_ll const *>(ifa->ifa_addr);
            Mac mac;
            if (ll->sll_halen == mac.bytes.size()) {
                std::copy_n(ll->sll_addr, mac.bytes.size(), mac.bytes.begin());
            }
            macs[ifa->ifa_name] = mac;
        }
    }

    std::vector<NetInterface> result;
    for (auto const *ifa = raw; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr || ifa->ifa_addr->sa_family != AF_INET || ifa->ifa_netmask == nullptr) {
            continue;
        }
        auto const addr = Ipv4{ntohl(reinterpret_cast<sockaddr_in const *>(ifa->ifa_addr)->sin_addr.s_addr)};
        auto const mask = ntohl(reinterpret_cast<sockaddr_in const *>(ifa->ifa_netmask)->sin_addr.s_addr);
        NetInterface iface;
        iface.name = ifa->ifa_name;
        iface.addr = addr;
        iface.subnet = Subnet::from(addr, static_cast<std::uint8_t>(std::popcount(mask)));
        iface.mac = macs[iface.name];
        iface.index = static_cast<int>(if_nametoindex(ifa->ifa_name));
        iface.up = (ifa->ifa_flags & IFF_UP) != 0 && (ifa->ifa_flags & IFF_RUNNING) != 0;
        iface.arp = (ifa->ifa_flags & (IFF_LOOPBACK | IFF_POINTOPOINT | IFF_NOARP)) == 0;
        result.push_back(std::move(iface));
    }
    return result;
}

ScanPlan plan_scan(std::vector<NetInterface> const &all, std::vector<std::string> const &names, std::uint64_t max_hosts) {
    ScanPlan plan;
    auto const add = [&plan, max_hosts](NetInterface const &iface) {
        if (!iface.up) {
            plan.warnings.push_back(fmt::format("{}: интерфейс не поднят", iface.name));
        } else if (!iface.arp) {
            plan.warnings.push_back(fmt::format("{}: интерфейс не поддерживает ARP", iface.name));
        } else if (iface.subnet.host_count() > max_hosts) {
            plan.warnings.push_back(fmt::format("{}: подсеть {} содержит {} адресов, больше max_hosts ({})", iface.name, iface.subnet.to_string(),
                                                iface.subnet.host_count(), max_hosts));
        } else if (std::ranges::none_of(plan.targets, [&iface](ScanTarget const &t) { return t.iface.subnet == iface.subnet; })) {
            plan.targets.push_back({iface});
        }
    };

    if (names.empty()) {
        for (auto const &iface : all) {
            if (iface.up && iface.arp) {
                add(iface);
            }
        }
        return plan;
    }

    for (auto const &name : names) {
        bool found = false;
        for (auto const &iface : all) {
            if (iface.name == name) {
                found = true;
                add(iface);
            }
        }
        if (!found) {
            plan.warnings.push_back(fmt::format("{}: интерфейс не найден или на нём нет IPv4-адреса", name));
        }
    }
    return plan;
}
