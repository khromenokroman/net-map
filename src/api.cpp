#include "api.hpp"

#include <algorithm>
#include <type_traits>

namespace {

std::int64_t to_ms(std::chrono::system_clock::time_point t) {
    return t.time_since_epoch().count() == 0 ? 0 : std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch()).count();
}

template <typename T>
nlohmann::json opt(std::optional<T> const &v) {
    if (!v) {
        return nullptr;
    }
    if constexpr (std::is_same_v<T, Ipv4>) {
        return v->to_string();
    } else {
        return *v;
    }
}

nlohmann::json dhcp_to_json(DhcpSnapshot const &d) {
    auto servers = nlohmann::json::array();
    for (auto const &s : d.servers) {
        servers.push_back({
            {"ip", s.ip.to_string()},
            {"mac", s.mac.to_string()},
            {"vendor", s.vendor},
            {"iface", s.iface},
            {"first_seen", to_ms(s.first_seen)},
            {"last_seen", to_ms(s.last_seen)},
            {"router", opt(s.router)},
            {"lease", opt(s.lease)},
            {"prefix", opt(s.prefix)},
            {"last_offered", s.last_offered.value == 0 ? nlohmann::json(nullptr) : nlohmann::json(s.last_offered.to_string())},
            {"messages", s.messages},
            {"answered_probe", s.answered_probe},
        });
    }
    auto clients = nlohmann::json::array();
    for (auto const &c : d.clients) {
        clients.push_back({
            {"mac", c.mac.to_string()},
            {"client_id", c.client_id},
            {"hostname", c.hostname},
            {"vendor_class", c.vendor_class},
            {"iface", c.iface},
            {"first_seen", to_ms(c.first_seen)},
            {"last_seen", to_ms(c.last_seen)},
            {"requested_ip", opt(c.requested_ip)},
            {"server_id", opt(c.server_id)},
            {"last_type", dhcp_type_name(c.last_type)},
            {"shared_client_id", d.shared_client_ids.contains(c.client_id)},
        });
    }
    auto shared = nlohmann::json::object();
    for (auto const &[id, macs] : d.shared_client_ids) {
        auto list = nlohmann::json::array();
        for (auto const &m : macs) {
            list.push_back(m.to_string());
        }
        shared[id] = std::move(list);
    }
    return {
        {"watching", d.watching},        {"probing", d.probing},          {"last_probe", to_ms(d.last_probe)},
        {"servers", std::move(servers)}, {"clients", std::move(clients)}, {"shared_client_ids", std::move(shared)},
    };
}

nlohmann::json host_to_json(Host const &h, DhcpClient const *dhcp) {
    return {
        {"dhcp_hostname", dhcp != nullptr ? dhcp->hostname : std::string{}},
        {"client_id", dhcp != nullptr ? dhcp->client_id : std::string{}},
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
        auto const it = std::ranges::find_if(snap.dhcp.clients, [&h](DhcpClient const &c) { return c.mac == h.mac; });
        hosts.push_back(host_to_json(h, it == snap.dhcp.clients.end() ? nullptr : &*it));
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
    result["dhcp"] = dhcp_to_json(snap.dhcp);
    return result;
}
