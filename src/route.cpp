#include "route.hpp"

#include <arpa/inet.h>

#include <fstream>
#include <sstream>

std::map<std::string, Ipv4> parse_default_gateways(std::string_view text) {
    std::map<std::string, std::pair<Ipv4, long>> best;
    std::istringstream in{std::string{text}};
    std::string line;
    std::getline(in, line);
    while (std::getline(in, line)) {
        std::istringstream fields{line};
        std::string iface;
        std::uint32_t dest{};
        std::uint32_t gateway{};
        unsigned flags{};
        long refcnt{};
        long use{};
        long metric{};
        std::uint32_t mask{};
        if (!(fields >> iface >> std::hex >> dest >> gateway >> flags >> std::dec >> refcnt >> use >> metric >> std::hex >> mask)) {
            continue;
        }
        constexpr unsigned RTF_UP_GATEWAY = 0x0001 | 0x0002;
        if (dest != 0 || mask != 0 || gateway == 0 || (flags & RTF_UP_GATEWAY) != RTF_UP_GATEWAY) {
            continue;
        }
        auto const gw = Ipv4{ntohl(gateway)};
        auto const it = best.find(iface);
        if (it == best.end() || metric < it->second.second) {
            best[iface] = {gw, metric};
        }
    }
    std::map<std::string, Ipv4> result;
    for (auto const &[iface, gw] : best) {
        result.emplace(iface, gw.first);
    }
    return result;
}

std::map<std::string, Ipv4> default_gateways() {
    std::ifstream f{"/proc/net/route"};
    std::ostringstream ss;
    ss << f.rdbuf();
    return parse_default_gateways(ss.str());
}
