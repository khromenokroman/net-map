#include "dhcp_packet.hpp"

#include <gtest/gtest.h>

#include <cstring>
#include <fstream>
#include <iterator>

namespace {

/// Читает кадры из pcap-файла (little-endian, Ethernet).
std::vector<std::vector<std::uint8_t>> read_pcap(std::string const &path) {
    std::ifstream in{path, std::ios::binary};
    std::vector<std::uint8_t> const data{std::istreambuf_iterator<char>{in}, {}};
    std::vector<std::vector<std::uint8_t>> frames;
    std::size_t pos = 24;
    while (pos + 16 <= data.size()) {
        std::uint32_t len{};
        std::memcpy(&len, data.data() + pos + 8, 4);
        pos += 16;
        if (pos + len > data.size()) {
            break;
        }
        frames.emplace_back(data.begin() + static_cast<std::ptrdiff_t>(pos), data.begin() + static_cast<std::ptrdiff_t>(pos + len));
        pos += len;
    }
    return frames;
}

std::uint16_t ip_checksum_ok(std::vector<std::uint8_t> const &f) {
    std::uint32_t sum = 0;
    for (std::size_t i = 14; i < 34; i += 2) {
        sum += static_cast<std::uint32_t>(f[i] << 8 | f[i + 1]);
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return static_cast<std::uint16_t>(sum);
}

constexpr char const *STAND_CLIENT_ID = "ff5cbbeb5e00020000ab11af86b5c9217d4733";

} // namespace

TEST(DhcpPacket, RealExchange) {
    auto const frames = read_pcap(std::string{TEST_DATA_DIR} + "/dhcp_exchange.pcap");
    ASSERT_EQ(frames.size(), 4U);

    auto const discover = parse_dhcp_frame(frames[0]);
    ASSERT_TRUE(discover);
    EXPECT_EQ(discover->type, DHCP_TYPE::DISCOVER);
    EXPECT_FALSE(discover->from_server);
    EXPECT_EQ(discover->chaddr.to_string(), "54:02:02:03:52:50");
    EXPECT_EQ(discover->src_mac.to_string(), "54:02:02:03:52:50");
    EXPECT_EQ(discover->client_id, STAND_CLIENT_ID);
    EXPECT_EQ(discover->hostname, "eve-img");
    EXPECT_EQ(discover->xid, 0xd22d7838U);

    auto const offer = parse_dhcp_frame(frames[1]);
    ASSERT_TRUE(offer);
    EXPECT_EQ(offer->type, DHCP_TYPE::OFFER);
    EXPECT_TRUE(offer->from_server);
    EXPECT_EQ(offer->src_mac.to_string(), "00:0c:29:76:76:fa");
    EXPECT_EQ(offer->src_ip.to_string(), "10.77.0.1");
    EXPECT_EQ(offer->yiaddr.to_string(), "10.77.0.140");
    ASSERT_TRUE(offer->server_id);
    EXPECT_EQ(offer->server_id->to_string(), "10.77.0.1");
    ASSERT_TRUE(offer->lease);
    EXPECT_EQ(*offer->lease, 43200U);
    ASSERT_TRUE(offer->router);
    EXPECT_EQ(offer->router->to_string(), "10.77.0.1");
    ASSERT_TRUE(offer->prefix);
    EXPECT_EQ(*offer->prefix, 24);

    auto const request = parse_dhcp_frame(frames[2]);
    ASSERT_TRUE(request);
    EXPECT_EQ(request->type, DHCP_TYPE::REQUEST);
    ASSERT_TRUE(request->requested_ip);
    EXPECT_EQ(request->requested_ip->to_string(), "10.77.0.140");
    EXPECT_EQ(request->server_id->to_string(), "10.77.0.1");

    auto const ack = parse_dhcp_frame(frames[3]);
    ASSERT_TRUE(ack);
    EXPECT_EQ(ack->type, DHCP_TYPE::ACK);
    EXPECT_EQ(ack->hostname, "eve-img");
}

TEST(DhcpPacket, BuildDiscover) {
    auto const src = *Mac::parse("54:02:02:03:52:50");
    auto const chaddr = probe_mac(src);
    auto const f = build_dhcp_discover(src, chaddr, 0x12345678);
    EXPECT_EQ(ip_checksum_ok(f), 0xffff);
    auto const d = parse_dhcp_frame(f);
    ASSERT_TRUE(d);
    EXPECT_EQ(d->type, DHCP_TYPE::DISCOVER);
    EXPECT_FALSE(d->from_server);
    EXPECT_EQ(d->xid, 0x12345678U);
    EXPECT_EQ(d->src_mac, src);
    EXPECT_EQ(d->chaddr, chaddr);
    EXPECT_EQ(d->vendor_class, "net-map");
    EXPECT_TRUE(d->client_id.empty());
    EXPECT_EQ((f[14 + 20 + 8 + 10] << 8 | f[14 + 20 + 8 + 11]), 0x8000);
}

TEST(DhcpPacket, ProbeMac) {
    auto const a = *Mac::parse("54:02:02:03:52:50");
    auto const p = probe_mac(a);
    EXPECT_NE(p, a);
    EXPECT_TRUE((p.bytes[0] & 0x02) != 0);
    EXPECT_TRUE((p.bytes[0] & 0x01) == 0);
    auto const laa = *Mac::parse("42:ec:2d:99:ca:ec");
    EXPECT_NE(probe_mac(laa), laa);
}

TEST(DhcpPacket, RejectsGarbage) {
    auto f = build_dhcp_discover(*Mac::parse("00:11:22:33:44:55"), *Mac::parse("02:11:22:33:44:55"), 1);
    EXPECT_FALSE(parse_dhcp_frame(std::span{f.data(), 100}));
    auto tcp = f;
    tcp[14 + 9] = 6;
    EXPECT_FALSE(parse_dhcp_frame(tcp));
    auto port = f;
    port[14 + 20 + 2] = 0;
    port[14 + 20 + 3] = 53;
    EXPECT_FALSE(parse_dhcp_frame(port));
    auto cookie = f;
    cookie[14 + 20 + 8 + 236] = 0;
    EXPECT_FALSE(parse_dhcp_frame(cookie));
    auto frag = f;
    frag[14 + 7] = 1;
    EXPECT_FALSE(parse_dhcp_frame(frag));
    auto truncated_opt = f;
    truncated_opt.resize(14 + 20 + 8 + 240 + 2);
    truncated_opt.back() = 50;
    EXPECT_TRUE(parse_dhcp_frame(truncated_opt));
}

TEST(DhcpPacket, BpfFilterShape) {
    auto const bpf = dhcp_bpf_filter();
    ASSERT_EQ(bpf.size(), 15U);
    EXPECT_EQ(bpf.back().code, 0x06);
    EXPECT_EQ(bpf.back().k, 0U);
}
