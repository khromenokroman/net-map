#include "inventory.hpp"

#include <gtest/gtest.h>

#include <algorithm>

namespace {

using namespace std::chrono_literals;
using clock_t_ = Inventory::clock;

Mac mac(char const *s) { return *Mac::parse(s); }
Ipv4 ip(char const *s) { return *Ipv4::parse(s); }

NetInterface iface() {
    NetInterface i;
    i.name = "eth0";
    i.addr = ip("10.0.0.1");
    i.mac = mac("02:00:00:00:00:01");
    i.subnet = Subnet::from(i.addr, 24);
    i.up = i.arp = true;
    return i;
}

std::vector<EVENT> kinds(std::vector<Event> const &events) {
    std::vector<EVENT> k;
    for (auto const &e : events) {
        k.push_back(e.kind);
    }
    return k;
}

Host const &find(std::vector<Host> const &hosts, char const *addr, char const *m) {
    auto const it = std::ranges::find_if(hosts, [&](Host const &h) { return h.ip == ip(addr) && h.mac == mac(m); });
    EXPECT_NE(it, hosts.end());
    return *it;
}

} // namespace

TEST(Inventory, NewLostBack) {
    OuiDb const oui;
    Inventory inv{60s, &oui};
    auto const t0 = clock_t_::now();
    Observation const gw{mac("d4:01:c3:b6:f2:ca"), ip("10.0.0.254")};

    EXPECT_EQ(kinds(inv.update(iface(), {gw}, ip("10.0.0.254"), t0)), (std::vector{EVENT::NEW_HOST}));
    auto hosts = inv.hosts();
    ASSERT_EQ(hosts.size(), 2U);
    EXPECT_TRUE(find(hosts, "10.0.0.1", "02:00:00:00:00:01").self);
    EXPECT_TRUE(find(hosts, "10.0.0.254", "d4:01:c3:b6:f2:ca").gateway);

    EXPECT_TRUE(inv.update(iface(), {}, ip("10.0.0.254"), t0 + 30s).empty());
    EXPECT_EQ(kinds(inv.update(iface(), {}, ip("10.0.0.254"), t0 + 61s)), (std::vector{EVENT::HOST_LOST}));
    hosts = inv.hosts();
    EXPECT_FALSE(find(hosts, "10.0.0.254", "d4:01:c3:b6:f2:ca").online);
    EXPECT_TRUE(find(hosts, "10.0.0.1", "02:00:00:00:00:01").online);

    EXPECT_EQ(kinds(inv.update(iface(), {gw}, ip("10.0.0.254"), t0 + 70s)), (std::vector{EVENT::HOST_BACK}));
    EXPECT_EQ(find(inv.hosts(), "10.0.0.254", "d4:01:c3:b6:f2:ca").first_seen, t0);
}

TEST(Inventory, MacChanged) {
    Inventory inv{60s, nullptr};
    auto const t0 = clock_t_::now();
    inv.update(iface(), {{mac("00:11:22:33:44:55"), ip("10.0.0.5")}}, std::nullopt, t0);
    inv.update(iface(), {}, std::nullopt, t0 + 61s);
    auto const ev = inv.update(iface(), {{mac("00:11:22:33:44:66"), ip("10.0.0.5")}}, std::nullopt, t0 + 62s);
    EXPECT_EQ(kinds(ev), (std::vector{EVENT::MAC_CHANGED}));
    EXPECT_NE(ev.front().text.find("00:11:22:33:44:55"), std::string::npos);
}

TEST(Inventory, ConflictAndResolve) {
    Inventory inv{60s, nullptr};
    auto const t0 = clock_t_::now();
    std::vector<Observation> const both{{mac("54:02:02:03:52:50"), ip("10.0.0.42")}, {mac("50:02:00:04:00:00"), ip("10.0.0.42")}};

    auto const ev = kinds(inv.update(iface(), both, std::nullopt, t0));
    EXPECT_EQ(std::ranges::count(ev, EVENT::NEW_HOST), 2);
    EXPECT_EQ(std::ranges::count(ev, EVENT::IP_CONFLICT), 1);
    EXPECT_TRUE(find(inv.hosts(), "10.0.0.42", "54:02:02:03:52:50").conflict);

    EXPECT_TRUE(inv.update(iface(), both, std::nullopt, t0 + 10s).empty());

    std::vector<Observation> const one{{mac("54:02:02:03:52:50"), ip("10.0.0.42")}};
    inv.update(iface(), one, std::nullopt, t0 + 50s);
    auto const resolved = kinds(inv.update(iface(), one, std::nullopt, t0 + 71s));
    EXPECT_EQ(std::ranges::count(resolved, EVENT::CONFLICT_RESOLVED), 1);
    EXPECT_FALSE(find(inv.hosts(), "10.0.0.42", "54:02:02:03:52:50").conflict);
}

TEST(Inventory, ConflictWithSelf) {
    Inventory inv{60s, nullptr};
    auto const ev = kinds(inv.update(iface(), {{mac("00:de:ad:be:ef:00"), ip("10.0.0.1")}}, std::nullopt, clock_t_::now()));
    EXPECT_EQ(std::ranges::count(ev, EVENT::IP_CONFLICT), 1);
}

TEST(Inventory, PurgeAndHostname) {
    Inventory inv{60s, nullptr};
    auto const t0 = clock_t_::now();
    inv.update(iface(), {{mac("00:11:22:33:44:55"), ip("10.0.0.5")}}, std::nullopt, t0);
    inv.set_hostname(ip("10.0.0.5"), "printer.lan");
    EXPECT_EQ(find(inv.hosts(), "10.0.0.5", "00:11:22:33:44:55").hostname, "printer.lan");
    inv.update(iface(), {}, std::nullopt, t0 + std::chrono::hours{25});
    EXPECT_EQ(inv.hosts().size(), 1U);
}

TEST(Inventory, EventNames) {
    EXPECT_EQ(event_name(EVENT::NEW_HOST), "new_host");
    EXPECT_EQ(event_name(EVENT::CONFLICT_RESOLVED), "conflict_resolved");
}
