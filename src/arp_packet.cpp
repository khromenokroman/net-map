#include "arp_packet.hpp"

#include <algorithm>

namespace {

constexpr std::uint16_t ETHERTYPE_ARP = 0x0806;
constexpr std::uint16_t ETHERTYPE_IPV4 = 0x0800;
constexpr std::uint16_t HTYPE_ETHERNET = 1;
constexpr std::size_t ETH_HEADER_SIZE = 14;
constexpr std::size_t ARP_SIZE = 28;

void put16(std::uint8_t *p, std::uint16_t v) {
    p[0] = static_cast<std::uint8_t>(v >> 8);
    p[1] = static_cast<std::uint8_t>(v);
}

void put32(std::uint8_t *p, std::uint32_t v) {
    put16(p, static_cast<std::uint16_t>(v >> 16));
    put16(p + 2, static_cast<std::uint16_t>(v));
}

std::uint16_t get16(std::uint8_t const *p) { return static_cast<std::uint16_t>(p[0] << 8 | p[1]); }

std::uint32_t get32(std::uint8_t const *p) { return static_cast<std::uint32_t>(get16(p)) << 16 | get16(p + 2); }

} // namespace

std::array<std::uint8_t, ARP_FRAME_SIZE> build_arp_request(Mac const &src_mac, Ipv4 src_ip, Ipv4 target) {
    std::array<std::uint8_t, ARP_FRAME_SIZE> f{};
    auto *p = f.data();
    std::fill_n(p, 6, 0xff);
    std::ranges::copy(src_mac.bytes, p + 6);
    put16(p + 12, ETHERTYPE_ARP);

    auto *a = p + ETH_HEADER_SIZE;
    put16(a, HTYPE_ETHERNET);
    put16(a + 2, ETHERTYPE_IPV4);
    a[4] = 6;
    a[5] = 4;
    put16(a + 6, static_cast<std::uint16_t>(ARP_OP::REQUEST));
    std::ranges::copy(src_mac.bytes, a + 8);
    put32(a + 14, src_ip.value);
    put32(a + 24, target.value);
    return f;
}

std::optional<ArpSender> parse_arp_frame(std::span<std::uint8_t const> frame) {
    if (frame.size() < ETH_HEADER_SIZE + ARP_SIZE || get16(frame.data() + 12) != ETHERTYPE_ARP) {
        return std::nullopt;
    }
    auto const *a = frame.data() + ETH_HEADER_SIZE;
    if (get16(a) != HTYPE_ETHERNET || get16(a + 2) != ETHERTYPE_IPV4 || a[4] != 6 || a[5] != 4) {
        return std::nullopt;
    }
    auto const op = get16(a + 6);
    if (op != static_cast<std::uint16_t>(ARP_OP::REQUEST) && op != static_cast<std::uint16_t>(ARP_OP::REPLY)) {
        return std::nullopt;
    }
    ArpSender s;
    std::copy_n(a + 8, 6, s.mac.bytes.begin());
    s.ip = Ipv4{get32(a + 14)};
    s.target_ip = Ipv4{get32(a + 24)};
    s.op = static_cast<ARP_OP>(op);
    return s;
}
