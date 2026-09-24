#include "dhcp_packet.hpp"

#include <fmt/format.h>

#include <algorithm>
#include <array>
#include <bit>

namespace {

constexpr std::size_t ETH_SIZE = 14;
constexpr std::size_t UDP_SIZE = 8;
constexpr std::size_t BOOTP_SIZE = 236;
constexpr std::uint32_t MAGIC_COOKIE = 0x63825363;
constexpr std::uint16_t PORT_SERVER = 67;
constexpr std::uint16_t PORT_CLIENT = 68;

constexpr std::array<BpfInsn, 15> DHCP_BPF{{
    {0x28, 0, 0, 0x0000000c},  // ldh [12]            EtherType
    {0x15, 0, 12, 0x00000800}, // jeq IPv4
    {0x30, 0, 0, 0x00000017},  // ldb [23]            протокол
    {0x15, 0, 10, 0x00000011}, // jeq UDP
    {0x28, 0, 0, 0x00000014},  // ldh [20]            флаги и смещение фрагмента
    {0x45, 8, 0, 0x00001fff},  // jset фрагмент -> отбросить
    {0xb1, 0, 0, 0x0000000e},  // ldxb 4*([14]&0xf)   длина IP-заголовка
    {0x48, 0, 0, 0x0000000e},  // ldh [x+14]          порт источника
    {0x15, 4, 0, 0x00000043},  // jeq 67
    {0x15, 3, 0, 0x00000044},  // jeq 68
    {0x48, 0, 0, 0x00000010},  // ldh [x+16]          порт назначения
    {0x15, 1, 0, 0x00000043},  // jeq 67
    {0x15, 0, 1, 0x00000044},  // jeq 68
    {0x06, 0, 0, 0x00040000},  // ret принять
    {0x06, 0, 0, 0x00000000},  // ret отбросить
}};

std::uint16_t get16(std::uint8_t const *p) { return static_cast<std::uint16_t>(p[0] << 8 | p[1]); }
std::uint32_t get32(std::uint8_t const *p) { return static_cast<std::uint32_t>(get16(p)) << 16 | get16(p + 2); }

void put16(std::vector<std::uint8_t> &v, std::size_t at, std::uint16_t x) {
    v[at] = static_cast<std::uint8_t>(x >> 8);
    v[at + 1] = static_cast<std::uint8_t>(x);
}
void put32(std::vector<std::uint8_t> &v, std::size_t at, std::uint32_t x) {
    put16(v, at, static_cast<std::uint16_t>(x >> 16));
    put16(v, at + 2, static_cast<std::uint16_t>(x));
}

void add_option(std::vector<std::uint8_t> &opts, std::uint8_t code, std::initializer_list<std::uint8_t> value) {
    opts.push_back(code);
    opts.push_back(static_cast<std::uint8_t>(value.size()));
    opts.insert(opts.end(), value);
}

std::uint16_t ip_checksum(std::uint8_t const *p, std::size_t len) {
    std::uint32_t sum = 0;
    for (std::size_t i = 0; i + 1 < len; i += 2) {
        sum += get16(p + i);
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return static_cast<std::uint16_t>(~sum);
}

} // namespace

std::string_view dhcp_type_name(DHCP_TYPE type) {
    switch (type) {
        case DHCP_TYPE::DISCOVER:
            return "DISCOVER";
        case DHCP_TYPE::OFFER:
            return "OFFER";
        case DHCP_TYPE::REQUEST:
            return "REQUEST";
        case DHCP_TYPE::DECLINE:
            return "DECLINE";
        case DHCP_TYPE::ACK:
            return "ACK";
        case DHCP_TYPE::NAK:
            return "NAK";
        case DHCP_TYPE::RELEASE:
            return "RELEASE";
        case DHCP_TYPE::INFORM:
            return "INFORM";
        case DHCP_TYPE::NONE:
            break;
    }
    return "BOOTP";
}

std::optional<DhcpFrame> parse_dhcp_frame(std::span<std::uint8_t const> frame) {
    if (frame.size() < ETH_SIZE + 20 || get16(frame.data() + 12) != 0x0800) {
        return std::nullopt;
    }
    auto const *ip = frame.data() + ETH_SIZE;
    auto const ihl = static_cast<std::size_t>(ip[0] & 0x0f) * 4;
    if ((ip[0] >> 4) != 4 || ihl < 20 || ip[9] != 17 || (get16(ip + 6) & 0x1fff) != 0 || frame.size() < ETH_SIZE + ihl + UDP_SIZE) {
        return std::nullopt;
    }
    auto const *udp = ip + ihl;
    auto const sport = get16(udp);
    auto const dport = get16(udp + 2);
    auto const is_client = sport == PORT_CLIENT && dport == PORT_SERVER;
    auto const is_server = sport == PORT_SERVER && (dport == PORT_CLIENT || dport == PORT_SERVER);
    if (!is_client && !is_server) {
        return std::nullopt;
    }
    auto const *b = udp + UDP_SIZE;
    auto const end = frame.data() + frame.size();
    if (end - b < static_cast<std::ptrdiff_t>(BOOTP_SIZE + 4) || b[1] != 1 || b[2] != 6 || get32(b + BOOTP_SIZE) != MAGIC_COOKIE) {
        return std::nullopt;
    }

    DhcpFrame f;
    std::copy_n(frame.data() + 6, 6, f.src_mac.bytes.begin());
    f.src_ip = Ipv4{get32(ip + 12)};
    f.from_server = b[0] == 2;
    f.xid = get32(b + 4);
    f.ciaddr = Ipv4{get32(b + 12)};
    f.yiaddr = Ipv4{get32(b + 16)};
    std::copy_n(b + 28, 6, f.chaddr.bytes.begin());

    for (auto const *o = b + BOOTP_SIZE + 4; o < end;) {
        auto const code = o[0];
        if (code == 255) {
            break;
        }
        if (code == 0) {
            ++o;
            continue;
        }
        if (o + 2 > end || o + 2 + o[1] > end) {
            break;
        }
        auto const len = o[1];
        auto const *v = o + 2;
        switch (code) {
            case 53:
                if (len >= 1) {
                    f.type = static_cast<DHCP_TYPE>(v[0]);
                }
                break;
            case 54:
                if (len >= 4) {
                    f.server_id = Ipv4{get32(v)};
                }
                break;
            case 50:
                if (len >= 4) {
                    f.requested_ip = Ipv4{get32(v)};
                }
                break;
            case 3:
                if (len >= 4) {
                    f.router = Ipv4{get32(v)};
                }
                break;
            case 1:
                if (len >= 4) {
                    f.prefix = static_cast<std::uint8_t>(std::popcount(get32(v)));
                }
                break;
            case 51:
                if (len >= 4) {
                    f.lease = get32(v);
                }
                break;
            case 12:
                f.hostname.assign(reinterpret_cast<char const *>(v), len);
                break;
            case 60:
                f.vendor_class.assign(reinterpret_cast<char const *>(v), len);
                break;
            case 61:
                for (std::size_t i = 0; i < len; ++i) {
                    f.client_id += fmt::format("{:02x}", v[i]);
                }
                break;
            default:
                break;
        }
        o += 2 + len;
    }
    return f;
}

std::vector<std::uint8_t> build_dhcp_discover(Mac const &src_mac, Mac const &chaddr, std::uint32_t xid) {
    std::vector<std::uint8_t> opts;
    add_option(opts, 53, {static_cast<std::uint8_t>(DHCP_TYPE::DISCOVER)});
    add_option(opts, 55, {1, 3, 6, 51, 54});
    add_option(opts, 60, {'n', 'e', 't', '-', 'm', 'a', 'p'});
    opts.push_back(255);
    auto const bootp_len = BOOTP_SIZE + 4 + opts.size();
    auto const udp_len = UDP_SIZE + bootp_len;
    auto const ip_len = 20 + udp_len;
    std::vector<std::uint8_t> f(std::max<std::size_t>(ETH_SIZE + ip_len, 60), 0);

    std::fill_n(f.begin(), 6, 0xff);
    std::ranges::copy(src_mac.bytes, f.begin() + 6);
    put16(f, 12, 0x0800);

    auto const ip = ETH_SIZE;
    f[ip] = 0x45;
    put16(f, ip + 2, static_cast<std::uint16_t>(ip_len));
    f[ip + 8] = 64;
    f[ip + 9] = 17;
    put32(f, ip + 16, 0xffffffff);
    put16(f, ip + 10, ip_checksum(f.data() + ip, 20));

    auto const udp = ip + 20;
    put16(f, udp, PORT_CLIENT);
    put16(f, udp + 2, PORT_SERVER);
    put16(f, udp + 4, static_cast<std::uint16_t>(udp_len));

    auto const b = udp + UDP_SIZE;
    f[b] = 1;
    f[b + 1] = 1;
    f[b + 2] = 6;
    put32(f, b + 4, xid);
    put16(f, b + 10, 0x8000);
    std::ranges::copy(chaddr.bytes, f.begin() + static_cast<std::ptrdiff_t>(b + 28));
    put32(f, b + BOOTP_SIZE, MAGIC_COOKIE);
    std::ranges::copy(opts, f.begin() + static_cast<std::ptrdiff_t>(b + BOOTP_SIZE + 4));
    return f;
}

Mac probe_mac(Mac const &iface_mac) {
    Mac m = iface_mac;
    m.bytes[0] = static_cast<std::uint8_t>((m.bytes[0] | 0x02) & 0xfe);
    m.bytes[5] ^= 0x5a;
    return m;
}

std::span<BpfInsn const> dhcp_bpf_filter() { return DHCP_BPF; }
