#include "api.hpp"

namespace {

std::int64_t to_ms(std::chrono::system_clock::time_point t) {
    return t.time_since_epoch().count() == 0 ? 0 : std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch()).count();
}

nlohmann::json host_to_json(Host const &h) {
    return {
        {"ip", h.ip.to_string()},
        {"mac", h.mac.to_string()},
        {"vendor", h.vendor},
        {"hostname", h.hostname},
        {"iface", h.iface},
        {"subnet", h.subnet.to_string()},
        {"first_seen", to_ms(h.first_seen)},
        {"last_seen", to_ms(h.last_seen)},
        {"self", h.self},
        {"gateway", h.gateway},
        {"online", h.online},
        {"conflict", h.conflict},
        {"local_mac", h.local_mac},
    };
}

} // namespace

nlohmann::json network_to_json(NetSnapshot const &snap, std::map<std::string, Ipv4> const &gateways, std::string const &hostname,
                               int scan_interval_sec) {
    auto subnets = nlohmann::json::array();
    for (auto const &t : snap.targets) {
        nlohmann::json s{
            {"iface", t.name}, {"subnet", t.subnet.to_string()}, {"addr", t.addr.to_string()}, {"mac", t.mac.to_string()}, {"gateway", nullptr},
        };
        if (auto const it = gateways.find(t.name); it != gateways.end() && t.subnet.contains(it->second)) {
            s["gateway"] = it->second.to_string();
        }
        subnets.push_back(std::move(s));
    }

    auto hosts = nlohmann::json::array();
    for (auto const &h : snap.hosts) {
        hosts.push_back(host_to_json(h));
    }

    auto events = nlohmann::json::array();
    for (auto const &e : snap.events) {
        events.push_back({
            {"time", to_ms(e.time)},
            {"kind", event_name(e.kind)},
            {"text", e.text},
            {"ip", e.ip.to_string()},
            {"mac", e.mac.to_string()},
        });
    }

    nlohmann::json result;
    result["hostname"] = hostname;
    result["time"] = to_ms(std::chrono::system_clock::now());
    result["scan_interval_sec"] = scan_interval_sec;
    result["scans"] = snap.scans;
    result["last_scan"] = to_ms(snap.last_scan);
    result["warnings"] = snap.warnings;
    result["subnets"] = std::move(subnets);
    result["hosts"] = std::move(hosts);
    result["events"] = std::move(events);
    return result;
}
