#include "netif.hpp"

#include <gtest/gtest.h>

#include <algorithm>

namespace {

NetInterface make(std::string name, std::string_view addr, std::uint8_t prefix, bool up = true, bool arp = true) {
    NetInterface i;
    i.name = std::move(name);
    i.addr = *Ipv4::parse(addr);
    i.subnet = Subnet::from(i.addr, prefix);
    i.up = up;
    i.arp = arp;
    return i;
}

} // namespace

TEST(PlanScan, AutoSelectsUpArpInterfaces) {
    std::vector<NetInterface> const all{make("lo", "127.0.0.1", 8, true, false), make("eth0", "192.168.1.10", 24),
                                        make("eth1", "10.0.0.1", 24, false), make("wg0", "10.9.0.1", 24, true, false)};
    auto const plan = plan_scan(all, {}, 4096);
    ASSERT_EQ(plan.targets.size(), 1U);
    EXPECT_EQ(plan.targets[0].iface.name, "eth0");
    EXPECT_TRUE(plan.warnings.empty());
}

TEST(PlanScan, ExplicitNamesAndWarnings) {
    std::vector<NetInterface> const all{make("eth0", "192.168.1.10", 24), make("eth1", "10.0.0.1", 16), make("eth2", "10.1.0.1", 24, false)};
    auto const plan = plan_scan(all, {"eth0", "eth1", "eth2", "eth9"}, 4096);
    ASSERT_EQ(plan.targets.size(), 1U);
    EXPECT_EQ(plan.targets[0].iface.name, "eth0");
    ASSERT_EQ(plan.warnings.size(), 3U);
    EXPECT_NE(plan.warnings[0].find("max_hosts"), std::string::npos);
    EXPECT_NE(plan.warnings[1].find("не поднят"), std::string::npos);
    EXPECT_NE(plan.warnings[2].find("не найден"), std::string::npos);
}

TEST(PlanScan, DeduplicatesSameSubnet) {
    std::vector<NetInterface> const all{make("eth0", "192.168.1.10", 24), make("eth0", "192.168.1.11", 24)};
    EXPECT_EQ(plan_scan(all, {}, 4096).targets.size(), 1U);
}

TEST(ListInterfaces, HasLoopback) {
    auto const all = list_interfaces();
    auto const it = std::ranges::find_if(all, [](NetInterface const &i) { return i.name == "lo"; });
    ASSERT_NE(it, all.end());
    EXPECT_EQ(it->addr.to_string(), "127.0.0.1");
    EXPECT_FALSE(it->arp);
}
