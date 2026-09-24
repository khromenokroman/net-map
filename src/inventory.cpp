#include "inventory.hpp"

#include <fmt/format.h>

#include <algorithm>

namespace {

constexpr auto PURGE_AFTER = std::chrono::hours{24};

std::string host_label(Host const &h) {
    auto label = fmt::format("{} ({})", h.ip.to_string(), h.mac.to_string());
    if (!h.vendor.empty()) {
        label += fmt::format(", {}", h.vendor);
    }
    return label;
}

} // namespace

std::string_view event_name(EVENT kind) {
    switch (kind) {
        case EVENT::NEW_HOST:
            return "new_host";
        case EVENT::HOST_LOST:
            return "host_lost";
        case EVENT::HOST_BACK:
            return "host_back";
        case EVENT::MAC_CHANGED:
            return "mac_changed";
        case EVENT::IP_CONFLICT:
            return "ip_conflict";
        case EVENT::CONFLICT_RESOLVED:
            return "conflict_resolved";
        case EVENT::DHCP_SERVER:
            return "dhcp_server";
        case EVENT::DHCP_MULTIPLE_SERVERS:
            return "dhcp_multiple_servers";
        case EVENT::DHCP_SHARED_CLIENT_ID:
            break;
    }
    return "dhcp_shared_client_id";
}

Inventory::Inventory(std::chrono::seconds host_timeout, OuiDb const *oui) : m_timeout{host_timeout}, m_oui{oui} {}

Host Inventory::make_host(NetInterface const &iface, Observation const &obs, clock::time_point now) const {
    Host h;
    h.iface = iface.name;
    h.subnet = iface.subnet;
    h.ip = obs.ip;
    h.mac = obs.mac;
    h.first_seen = now;
    h.last_seen = now;
    h.online = true;
    h.local_mac = is_locally_administered(obs.mac);
    if (m_oui != nullptr) {
        h.vendor = m_oui->lookup(obs.mac);
    }
    return h;
}

std::vector<Event> Inventory::update(NetInterface const &iface, std::vector<Observation> const &seen, std::optional<Ipv4> gateway,
                                     clock::time_point now) {
    std::vector<Event> events;
    auto const emit = [&events, now](EVENT kind, Host const &h, std::string text) { events.push_back({std::move(text), now, h.mac, h.ip, kind}); };

    auto &self = m_hosts.try_emplace({iface.addr, iface.mac}, make_host(iface, {iface.mac, iface.addr}, now)).first->second;
    self.self = true;
    self.last_seen = now;

    for (auto const &obs : seen) {
        auto const key = std::pair{obs.ip, obs.mac};
        auto it = m_hosts.find(key);
        if (it == m_hosts.end()) {
            std::vector<Host const *> previous;
            for (auto const &[k, h] : m_hosts) {
                if (k.first == obs.ip && k.second != obs.mac) {
                    previous.push_back(&h);
                }
            }
            auto const any_online = std::ranges::any_of(previous, [](Host const *h) { return h->online; });
            it = m_hosts.emplace(key, make_host(iface, obs, now)).first;
            if (!previous.empty() && !any_online) {
                emit(EVENT::MAC_CHANGED, it->second,
                     fmt::format("{}: MAC сменился с {} на {}", obs.ip.to_string(), previous.back()->mac.to_string(), host_label(it->second)));
            } else {
                emit(EVENT::NEW_HOST, it->second, fmt::format("Новый хост {}", host_label(it->second)));
            }
            continue;
        }
        auto &h = it->second;
        if (!h.online) {
            emit(EVENT::HOST_BACK, h, fmt::format("Хост снова в сети: {}", host_label(h)));
        }
        h.online = true;
        h.last_seen = now;
    }

    std::map<Ipv4, std::vector<Host *>> online_by_ip;
    for (auto &[key, h] : m_hosts) {
        if (!(h.subnet == iface.subnet)) {
            continue;
        }
        h.gateway = gateway.has_value() && h.ip == *gateway;
        if (!h.self) {
            auto const online = now - h.last_seen < m_timeout;
            if (h.online && !online) {
                emit(EVENT::HOST_LOST, h, fmt::format("Хост не отвечает: {}", host_label(h)));
            }
            h.online = online;
        }
        if (h.online) {
            online_by_ip[h.ip].push_back(&h);
        }
    }

    for (auto &[ip, list] : online_by_ip) {
        auto const conflict = list.size() > 1;
        for (auto *h : list) {
            h->conflict = conflict;
        }
        if (conflict && !m_conflicts.contains(ip)) {
            m_conflicts.insert(ip);
            std::string macs;
            for (auto const *h : list) {
                macs += (macs.empty() ? "" : ", ") + host_label(*h);
            }
            emit(EVENT::IP_CONFLICT, *list.front(), fmt::format("Конфликт IP {}: отвечают {}", ip.to_string(), macs));
        }
    }
    for (auto it = m_conflicts.begin(); it != m_conflicts.end();) {
        auto const ol = online_by_ip.find(*it);
        if (iface.subnet.contains(*it) && (ol == online_by_ip.end() || ol->second.size() < 2)) {
            Host h;
            h.ip = *it;
            if (ol != online_by_ip.end()) {
                h.mac = ol->second.front()->mac;
            }
            emit(EVENT::CONFLICT_RESOLVED, h, fmt::format("Конфликт IP {} устранён", it->to_string()));
            for (auto &[key, host] : m_hosts) {
                if (key.first == *it) {
                    host.conflict = false;
                }
            }
            it = m_conflicts.erase(it);
        } else {
            ++it;
        }
    }

    std::erase_if(m_hosts,
                  [&](auto const &kv) { return kv.second.subnet == iface.subnet && !kv.second.self && now - kv.second.last_seen > PURGE_AFTER; });
    return events;
}

void Inventory::set_hostname(Ipv4 ip, std::string const &name) {
    for (auto &[key, h] : m_hosts) {
        if (key.first == ip) {
            h.hostname = name;
        }
    }
}

std::vector<Host> Inventory::hosts() const {
    std::vector<Host> result;
    result.reserve(m_hosts.size());
    for (auto const &[key, h] : m_hosts) {
        result.push_back(h);
    }
    std::ranges::sort(result, [](Host const &a, Host const &b) { return std::tie(a.subnet, a.ip, a.mac) < std::tie(b.subnet, b.ip, b.mac); });
    return result;
}
