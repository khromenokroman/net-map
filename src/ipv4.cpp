#include "ipv4.hpp"

#include <fmt/format.h>

#include <charconv>

std::optional<Ipv4> Ipv4::parse(std::string_view text) {
    std::uint32_t result{};
    for (int i = 0; i < 4; ++i) {
        unsigned octet{};
        auto const [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), octet);
        auto const len = static_cast<std::size_t>(ptr - text.data());
        if (ec != std::errc{} || octet > 255 || len == 0 || len > 3) {
            return std::nullopt;
        }
        result = (result << 8) | octet;
        text.remove_prefix(len);
        if (i < 3) {
            if (text.empty() || text.front() != '.') {
                return std::nullopt;
            }
            text.remove_prefix(1);
        }
    }
    if (!text.empty()) {
        return std::nullopt;
    }
    return Ipv4{result};
}

std::string Ipv4::to_string() const { return fmt::format("{}.{}.{}.{}", value >> 24, (value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff); }

Subnet Subnet::from(Ipv4 addr, std::uint8_t prefix) {
    Subnet s;
    s.prefix = prefix > 32 ? 32 : prefix;
    s.network = Ipv4{addr.value & s.mask()};
    return s;
}

std::uint32_t Subnet::mask() const { return prefix == 0 ? 0 : ~std::uint32_t{0} << (32 - prefix); }

bool Subnet::contains(Ipv4 addr) const { return (addr.value & mask()) == network.value; }

std::uint64_t Subnet::host_count() const {
    auto const total = std::uint64_t{1} << (32 - prefix);
    return prefix >= 31 ? total : total - 2;
}

Ipv4 Subnet::first_host() const { return prefix >= 31 ? network : Ipv4{network.value + 1}; }

Ipv4 Subnet::last_host() const {
    auto const broadcast = network.value | ~mask();
    return prefix >= 31 ? Ipv4{broadcast} : Ipv4{broadcast - 1};
}

std::string Subnet::to_string() const { return fmt::format("{}/{}", network.to_string(), prefix); }

std::optional<Mac> Mac::parse(std::string_view text) {
    if (text.size() != 17) {
        return std::nullopt;
    }
    Mac mac;
    for (std::size_t i = 0; i < 6; ++i) {
        auto const part = text.substr(i * 3, 2);
        unsigned byte{};
        auto const [ptr, ec] = std::from_chars(part.data(), part.data() + part.size(), byte, 16);
        if (ec != std::errc{} || ptr != part.data() + part.size()) {
            return std::nullopt;
        }
        if (i < 5 && text[i * 3 + 2] != ':' && text[i * 3 + 2] != '-') {
            return std::nullopt;
        }
        mac.bytes[i] = static_cast<std::uint8_t>(byte);
    }
    return mac;
}

std::string Mac::to_string() const {
    return fmt::format("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
}
