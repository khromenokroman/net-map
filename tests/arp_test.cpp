#include <gtest/gtest.h>

#include "arp_packet.hpp"
#include "arp_scanner.hpp"

namespace {

Mac mac(char const *s) { return *Mac::parse(s); }
Ipv4 ip(char const *s) { return *Ipv4::parse(s); }

} // namespace

TEST(ArpPacket, BuildRequest) {
    auto const f = build_arp_request(mac("54:02:02:03:52:50"), ip("172.17.135.42"), ip("172.17.135.1"));
    std::array<std::uint8_t, 42> const expected{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x54, 0x02, 0x02, 0x03, 0x52, 0x50, 0x08, 0x06, // Ethernet
        0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01,                                     // ARP: Ethernet/IPv4, запрос
        0x54, 0x02, 0x02, 0x03, 0x52, 0x50, 172,  17,   135,  42,                           // SHA, SPA
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 172,  17,   135,  1,                            // THA, TPA
    };
    EXPECT_TRUE(std::equal(expected.begin(), expected.end(), f.begin()));
    EXPECT_TRUE(std::all_of(f.begin() + 42, f.end(), [](std::uint8_t b) { return b == 0; }));
}

TEST(ArpPacket, ParseOwnRequest) {
    auto const f = build_arp_request(mac("54:02:02:03:52:50"), ip("172.17.135.42"), ip("172.17.135.1"));
    auto const s = parse_arp_frame(f);
    ASSERT_TRUE(s);
    EXPECT_EQ(s->op, ARP_OP::REQUEST);
    EXPECT_EQ(s->mac.to_string(), "54:02:02:03:52:50");
    EXPECT_EQ(s->ip.to_string(), "172.17.135.42");
    EXPECT_EQ(s->target_ip.to_string(), "172.17.135.1");
}

TEST(ArpPacket, ParseReply) {
    std::array<std::uint8_t, 42> const f{
        0x54, 0x02, 0x02, 0x03, 0x52, 0x50, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x06, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00,
        0x02, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 172,  17,   135,  1,    0x54, 0x02, 0x02, 0x03, 0x52, 0x50, 172,  17,   135,  42,
    };
    auto const s = parse_arp_frame(f);
    ASSERT_TRUE(s);
    EXPECT_EQ(s->op, ARP_OP::REPLY);
    EXPECT_EQ(s->mac.to_string(), "00:11:22:33:44:55");
    EXPECT_EQ(s->ip.to_string(), "172.17.135.1");
}

TEST(ArpPacket, RejectsGarbage) {
    auto f = build_arp_request(mac("00:11:22:33:44:55"), ip("10.0.0.1"), ip("10.0.0.2"));
    EXPECT_FALSE(parse_arp_frame(std::span{f.data(), 41}));
    auto ipv4 = f;
    ipv4[12] = 0x08;
    ipv4[13] = 0x00;
    EXPECT_FALSE(parse_arp_frame(ipv4));
    auto bad_op = f;
    bad_op[21] = 3;
    EXPECT_FALSE(parse_arp_frame(bad_op));
    auto bad_hlen = f;
    bad_hlen[18] = 8;
    EXPECT_FALSE(parse_arp_frame(bad_hlen));
}

TEST(FindConflicts, DetectsDuplicateIp) {
    std::vector<Observation> const hosts{
        {mac("54:02:02:03:52:50"), ip("172.17.135.42")},
        {mac("50:02:00:04:00:00"), ip("172.17.135.42")},
        {mac("50:02:00:04:00:00"), ip("172.17.135.47")},
        {mac("00:11:22:33:44:55"), ip("172.17.135.1")},
    };
    auto const c = find_conflicts(hosts);
    ASSERT_EQ(c.size(), 1U);
    EXPECT_EQ(c.begin()->first.to_string(), "172.17.135.42");
    EXPECT_EQ(c.begin()->second.size(), 2U);
    EXPECT_TRUE(find_conflicts({}).empty());
}
