#include "ipv4.hpp"

#include <gtest/gtest.h>

TEST(Ipv4, Parse) {
    ASSERT_TRUE(Ipv4::parse("192.168.1.10"));
    EXPECT_EQ(Ipv4::parse("192.168.1.10")->value, 0xC0A8010AU);
    EXPECT_EQ(Ipv4::parse("0.0.0.0")->value, 0U);
    EXPECT_EQ(Ipv4::parse("255.255.255.255")->value, 0xFFFFFFFFU);
    EXPECT_EQ(Ipv4::parse("10.0.0.1")->to_string(), "10.0.0.1");
    for (auto const *bad : {"", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.a", "1..2.3", "1.2.3.4 ", "-1.2.3.4", "1234.1.1.1"}) {
        EXPECT_FALSE(Ipv4::parse(bad)) << bad;
    }
}

TEST(Subnet, Basics) {
    auto const s = Subnet::from(*Ipv4::parse("172.17.135.42"), 24);
    EXPECT_EQ(s.to_string(), "172.17.135.0/24");
    EXPECT_EQ(s.host_count(), 254U);
    EXPECT_EQ(s.first_host().to_string(), "172.17.135.1");
    EXPECT_EQ(s.last_host().to_string(), "172.17.135.254");
    EXPECT_TRUE(s.contains(*Ipv4::parse("172.17.135.200")));
    EXPECT_FALSE(s.contains(*Ipv4::parse("172.17.136.1")));
}

TEST(Subnet, EdgePrefixes) {
    auto const s30 = Subnet::from(*Ipv4::parse("10.0.0.5"), 30);
    EXPECT_EQ(s30.to_string(), "10.0.0.4/30");
    EXPECT_EQ(s30.host_count(), 2U);
    EXPECT_EQ(s30.first_host().to_string(), "10.0.0.5");
    EXPECT_EQ(s30.last_host().to_string(), "10.0.0.6");

    auto const s31 = Subnet::from(*Ipv4::parse("10.0.0.5"), 31);
    EXPECT_EQ(s31.host_count(), 2U);
    EXPECT_EQ(s31.first_host().to_string(), "10.0.0.4");
    EXPECT_EQ(s31.last_host().to_string(), "10.0.0.5");

    auto const s32 = Subnet::from(*Ipv4::parse("10.0.0.5"), 32);
    EXPECT_EQ(s32.host_count(), 1U);
    EXPECT_EQ(s32.first_host().to_string(), "10.0.0.5");

    auto const s0 = Subnet::from(*Ipv4::parse("10.0.0.5"), 0);
    EXPECT_EQ(s0.to_string(), "0.0.0.0/0");
    EXPECT_TRUE(s0.contains(*Ipv4::parse("8.8.8.8")));
}

TEST(Mac, ParseFormat) {
    auto const m = Mac::parse("54:02:02:03:52:50");
    ASSERT_TRUE(m);
    EXPECT_EQ(m->to_string(), "54:02:02:03:52:50");
    EXPECT_EQ(Mac::parse("AA-BB-CC-DD-EE-FF")->to_string(), "aa:bb:cc:dd:ee:ff");
    for (auto const *bad : {"", "54:02:02:03:52", "54:02:02:03:52:5g", "5402.0203.5250", "54:02:02:03:52:500"}) {
        EXPECT_FALSE(Mac::parse(bad)) << bad;
    }
}
