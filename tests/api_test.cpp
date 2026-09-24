#include "api.hpp"

#include <gtest/gtest.h>

TEST(Api, NetworkToJson) {
    NetSnapshot snap;
    NetInterface iface;
    iface.name = "eth0";
    iface.addr = *Ipv4::parse("10.0.0.1");
    iface.mac = *Mac::parse("02:00:00:00:00:01");
    iface.subnet = Subnet::from(iface.addr, 24);
    snap.targets = {iface};

    Host h;
    h.iface = "eth0";
    h.subnet = iface.subnet;
    h.ip = *Ipv4::parse("10.0.0.254");
    h.mac = *Mac::parse("d4:01:c3:b6:f2:ca");
    h.vendor = "Routerboard.com";
    h.gateway = h.online = true;
    h.last_seen = std::chrono::system_clock::time_point{std::chrono::milliseconds{1790000000123}};
    snap.hosts = {h};

    Event e;
    e.kind = EVENT::IP_CONFLICT;
    e.text = "Конфликт";
    e.ip = h.ip;
    snap.events = {e};
    snap.scans = 3;

    auto const j = network_to_json(snap, {{"eth0", *Ipv4::parse("10.0.0.254")}, {"eth1", *Ipv4::parse("192.168.1.1")}}, "f-15", 60);
    EXPECT_EQ(j.at("hostname"), "f-15");
    EXPECT_EQ(j.at("scan_interval_sec"), 60);
    EXPECT_EQ(j.at("scans"), 3);
    EXPECT_EQ(j.at("last_scan"), 0);
    ASSERT_EQ(j.at("subnets").size(), 1U);
    EXPECT_EQ(j.at("subnets")[0].at("subnet"), "10.0.0.0/24");
    EXPECT_EQ(j.at("subnets")[0].at("gateway"), "10.0.0.254");
    ASSERT_EQ(j.at("hosts").size(), 1U);
    auto const &jh = j.at("hosts")[0];
    EXPECT_EQ(jh.at("ip"), "10.0.0.254");
    EXPECT_EQ(jh.at("mac"), "d4:01:c3:b6:f2:ca");
    EXPECT_EQ(jh.at("vendor"), "Routerboard.com");
    EXPECT_EQ(jh.at("last_seen"), 1790000000123);
    EXPECT_TRUE(jh.at("gateway").get<bool>());
    EXPECT_FALSE(jh.at("conflict").get<bool>());
    ASSERT_EQ(j.at("events").size(), 1U);
    EXPECT_EQ(j.at("events")[0].at("kind"), "ip_conflict");
}

TEST(Api, GatewayOutsideSubnetIgnored) {
    NetSnapshot snap;
    NetInterface iface;
    iface.name = "eth0";
    iface.addr = *Ipv4::parse("10.0.0.1");
    iface.subnet = Subnet::from(iface.addr, 24);
    snap.targets = {iface};
    auto const j = network_to_json(snap, {{"eth0", *Ipv4::parse("10.9.9.9")}}, "h", 60);
    EXPECT_TRUE(j.at("subnets")[0].at("gateway").is_null());
}
