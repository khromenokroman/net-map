#include "dhcp_inventory.hpp"

#include <gtest/gtest.h>

#include <algorithm>

namespace {

using namespace std::chrono_literals;

Mac mac(char const *s) { return *Mac::parse(s); }
Ipv4 ip(char const *s) { return *Ipv4::parse(s); }

DhcpFrame client(char const *m, std::string client_id, DHCP_TYPE type = DHCP_TYPE::DISCOVER) {
    DhcpFrame f;
    f.chaddr = f.src_mac = mac(m);
    f.client_id = std::move(client_id);
    f.type = type;
    f.hostname = "eve-img";
    return f;
}

DhcpFrame server(char const *m, char const *addr, DHCP_TYPE type = DHCP_TYPE::OFFER, char const *to = "02:00:00:00:00:99") {
    DhcpFrame f;
    f.from_server = true;
    f.src_mac = mac(m);
    f.src_ip = ip(addr);
    f.server_id = ip(addr);
    f.chaddr = mac(to);
    f.yiaddr = ip("10.0.0.100");
    f.router = ip("10.0.0.254");
    f.lease = 7200;
    f.prefix = 24;
    f.type = type;
    return f;
}

std::size_t count(std::vector<Event> const &ev, EVENT kind) {
    return static_cast<std::size_t>(std::ranges::count_if(ev, [kind](Event const &e) { return e.kind == kind; }));
}

Mac const PROBE = mac("02:00:00:00:00:99");
Mac const NO_PROBE = mac("02:ff:ff:ff:ff:ff");

} // namespace

TEST(DhcpInventory, ServersAndMultiple) {
    DhcpInventory inv{nullptr};
    auto const t0 = std::chrono::system_clock::now();
    auto ev = inv.update("eth0", server("00:0c:29:76:76:fa", "10.0.0.1"), PROBE, t0);
    EXPECT_EQ(count(ev, EVENT::DHCP_SERVER), 1U);
    EXPECT_EQ(count(ev, EVENT::DHCP_MULTIPLE_SERVERS), 0U);
    EXPECT_TRUE(inv.update("eth0", server("00:0c:29:76:76:fa", "10.0.0.1", DHCP_TYPE::ACK), PROBE, t0 + 1s).empty());

    ev = inv.update("eth0", server("f8:f0:82:79:06:4b", "10.0.0.1"), PROBE, t0 + 2s);
    EXPECT_EQ(count(ev, EVENT::DHCP_SERVER), 1U);
    EXPECT_EQ(count(ev, EVENT::DHCP_MULTIPLE_SERVERS), 1U);

    auto const snap = inv.snapshot();
    ASSERT_EQ(snap.servers.size(), 2U);
    auto const &s = snap.servers.front();
    EXPECT_EQ(s.ip.to_string(), "10.0.0.1");
    EXPECT_EQ(s.last_offered.to_string(), "10.0.0.100");
    EXPECT_EQ(s.router->to_string(), "10.0.0.254");
    EXPECT_TRUE(s.answered_probe);
    EXPECT_TRUE(snap.clients.empty());
}

TEST(DhcpInventory, OtherSegmentIsNotMultiple) {
    DhcpInventory inv{nullptr};
    auto const t0 = std::chrono::system_clock::now();
    inv.update("eth0", server("00:0c:29:76:76:fa", "10.0.0.1"), PROBE, t0);
    auto const ev = inv.update("eth1", server("00:0c:29:00:00:01", "10.1.0.1"), PROBE, t0);
    EXPECT_EQ(count(ev, EVENT::DHCP_MULTIPLE_SERVERS), 0U);
}

TEST(DhcpInventory, SharedClientId) {
    DhcpInventory inv{nullptr};
    auto const t0 = std::chrono::system_clock::now();
    std::string const id = "ff5cbbeb5e00020000ab11af86b5c9217d4733";
    EXPECT_TRUE(inv.update("eth0", client("54:02:02:03:52:50", id), NO_PROBE, t0).empty());
    EXPECT_TRUE(inv.update("eth0", client("54:02:02:03:52:50", id, DHCP_TYPE::REQUEST), NO_PROBE, t0 + 1s).empty());

    auto const ev = inv.update("eth0", client("50:02:00:04:00:00", id), NO_PROBE, t0 + 2s);
    ASSERT_EQ(count(ev, EVENT::DHCP_SHARED_CLIENT_ID), 1U);
    EXPECT_NE(ev.front().text.find("54:02:02:03:52:50"), std::string::npos);
    EXPECT_NE(ev.front().text.find("50:02:00:04:00:00"), std::string::npos);
    EXPECT_TRUE(inv.update("eth0", client("50:02:00:04:00:00", id, DHCP_TYPE::REQUEST), NO_PROBE, t0 + 3s).empty());

    auto const snap = inv.snapshot();
    ASSERT_EQ(snap.clients.size(), 2U);
    EXPECT_EQ(snap.clients.front().hostname, "eve-img");
    ASSERT_EQ(snap.shared_client_ids.size(), 1U);
    EXPECT_EQ(snap.shared_client_ids.at(id).size(), 2U);
}

TEST(DhcpInventory, ProbeIsNotClient) {
    DhcpInventory inv{nullptr};
    auto f = client("02:00:00:00:00:99", "");
    EXPECT_TRUE(inv.update("eth0", f, PROBE, std::chrono::system_clock::now()).empty());
    EXPECT_TRUE(inv.snapshot().clients.empty());
}

TEST(DhcpInventory, RequestedIpAndPurge) {
    DhcpInventory inv{nullptr};
    auto const t0 = std::chrono::system_clock::now();
    auto f = client("54:02:02:03:52:50", "01aa", DHCP_TYPE::REQUEST);
    f.requested_ip = ip("10.0.0.140");
    f.server_id = ip("10.0.0.1");
    inv.update("eth0", f, NO_PROBE, t0);
    inv.update("eth0", server("00:0c:29:76:76:fa", "10.0.0.1"), PROBE, t0);
    auto snap = inv.snapshot();
    ASSERT_EQ(snap.clients.size(), 1U);
    EXPECT_EQ(snap.clients.front().requested_ip->to_string(), "10.0.0.140");
    EXPECT_EQ(snap.clients.front().server_id->to_string(), "10.0.0.1");
    inv.purge(t0 + std::chrono::hours{25});
    snap = inv.snapshot();
    EXPECT_TRUE(snap.clients.empty());
    EXPECT_TRUE(snap.servers.empty());
}
