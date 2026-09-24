#include "dhcp_inventory.hpp"

#include <fmt/format.h>

#include <algorithm>

namespace {

constexpr auto PURGE_AFTER = std::chrono::hours{24};

std::string server_label(DhcpServer const &s) {
    auto label = fmt::format("{} ({})", s.ip.to_string(), s.mac.to_string());
    if (!s.vendor.empty()) {
        label += fmt::format(", {}", s.vendor);
    }
    return label;
}

} // namespace

DhcpInventory::DhcpInventory(OuiDb const *oui) : m_oui{oui} {}

std::vector<Mac> DhcpInventory::macs_of(std::string const &client_id) const {
    std::vector<Mac> macs;
    for (auto const &[mac, c] : m_clients) {
        if (c.client_id == client_id) {
            macs.push_back(mac);
        }
    }
    return macs;
}

std::vector<Event> DhcpInventory::update(std::string const &iface, DhcpFrame const &frame, Mac const &probe, clock::time_point now) {
    std::vector<Event> events;

    if (frame.from_server) {
        auto const ip = frame.server_id.value_or(frame.src_ip);
        auto const key = std::pair{ip, frame.src_mac};
        auto const [it, inserted] = m_servers.try_emplace(key);
        auto &s = it->second;
        if (inserted) {
            s.iface = iface;
            s.ip = ip;
            s.mac = frame.src_mac;
            s.first_seen = now;
            if (m_oui != nullptr) {
                s.vendor = m_oui->lookup(frame.src_mac);
            }
        }
        s.last_seen = now;
        ++s.messages;
        if (frame.yiaddr.value != 0) {
            s.last_offered = frame.yiaddr;
        }
        s.router = frame.router ? frame.router : s.router;
        s.lease = frame.lease ? frame.lease : s.lease;
        s.prefix = frame.prefix ? frame.prefix : s.prefix;
        s.answered_probe = s.answered_probe || frame.chaddr == probe;

        if (inserted) {
            events.push_back({fmt::format("Обнаружен DHCP-сервер {} на {}", server_label(s), iface), now, s.mac, s.ip, EVENT::DHCP_SERVER});
            std::vector<DhcpServer const *> others;
            for (auto const &[k, other] : m_servers) {
                if (other.iface == iface && !(k == key)) {
                    others.push_back(&other);
                }
            }
            if (!others.empty()) {
                std::string list = server_label(s);
                for (auto const *o : others) {
                    list += ", " + server_label(*o);
                }
                events.push_back(
                    {fmt::format("В сегменте {} отвечают несколько DHCP-серверов: {}", iface, list), now, s.mac, s.ip, EVENT::DHCP_MULTIPLE_SERVERS});
            }
        }
        return events;
    }

    if (frame.chaddr == probe) {
        return events;
    }
    auto const [it, inserted] = m_clients.try_emplace(frame.chaddr);
    auto &c = it->second;
    if (inserted) {
        c.mac = frame.chaddr;
        c.first_seen = now;
    }
    auto const old_id = c.client_id;
    c.iface = iface;
    c.last_seen = now;
    c.last_type = frame.type;
    c.client_id = frame.client_id.empty() ? c.client_id : frame.client_id;
    c.hostname = frame.hostname.empty() ? c.hostname : frame.hostname;
    c.vendor_class = frame.vendor_class.empty() ? c.vendor_class : frame.vendor_class;
    if (frame.requested_ip) {
        c.requested_ip = frame.requested_ip;
    } else if (frame.ciaddr.value != 0) {
        c.requested_ip = frame.ciaddr;
    }
    c.server_id = frame.server_id ? frame.server_id : c.server_id;

    if (!c.client_id.empty() && c.client_id != old_id) {
        auto const macs = macs_of(c.client_id);
        if (macs.size() > 1) {
            std::string list;
            for (auto const &m : macs) {
                list += (list.empty() ? "" : ", ") + m.to_string();
            }
            events.push_back({fmt::format("DHCP Client-ID {} используют несколько MAC: {}. Такие узлы DHCP-сервер считает одним клиентом "
                                          "(часто это клоны с одинаковым /etc/machine-id)",
                                          c.client_id, list),
                              now, c.mac, c.requested_ip.value_or(Ipv4{}), EVENT::DHCP_SHARED_CLIENT_ID});
        }
    }
    return events;
}

void DhcpInventory::purge(clock::time_point now) {
    std::erase_if(m_servers, [now](auto const &kv) { return now - kv.second.last_seen > PURGE_AFTER; });
    std::erase_if(m_clients, [now](auto const &kv) { return now - kv.second.last_seen > PURGE_AFTER; });
}

DhcpSnapshot DhcpInventory::snapshot() const {
    DhcpSnapshot snap;
    for (auto const &[key, s] : m_servers) {
        snap.servers.push_back(s);
    }
    for (auto const &[mac, c] : m_clients) {
        snap.clients.push_back(c);
        if (!c.client_id.empty() && !snap.shared_client_ids.contains(c.client_id)) {
            auto macs = macs_of(c.client_id);
            if (macs.size() > 1) {
                snap.shared_client_ids.emplace(c.client_id, std::move(macs));
            }
        }
    }
    return snap;
}
