#include "oui.hpp"

#include <charconv>
#include <fstream>

std::optional<std::pair<std::uint32_t, std::string>> parse_oui_line(std::string_view line) {
    constexpr std::string_view MARKER{"(hex)"};
    auto const pos = line.find(MARKER);
    if (pos == std::string_view::npos || line.size() < 8 || line[2] != '-' || line[5] != '-') {
        return std::nullopt;
    }
    std::uint32_t prefix{};
    for (std::size_t i = 0; i < 3; ++i) {
        unsigned byte{};
        auto const part = line.substr(i * 3, 2);
        auto const [ptr, ec] = std::from_chars(part.data(), part.data() + 2, byte, 16);
        if (ec != std::errc{} || ptr != part.data() + 2) {
            return std::nullopt;
        }
        prefix = prefix << 8 | byte;
    }
    auto vendor = line.substr(pos + MARKER.size());
    auto const is_space = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
    while (!vendor.empty() && is_space(vendor.front())) {
        vendor.remove_prefix(1);
    }
    while (!vendor.empty() && is_space(vendor.back())) {
        vendor.remove_suffix(1);
    }
    if (vendor.empty()) {
        return std::nullopt;
    }
    return std::pair{prefix, std::string{vendor}};
}

bool is_locally_administered(Mac const &mac) { return (mac.bytes[0] & 0x02) != 0; }

std::size_t OuiDb::load(std::string const &path) {
    std::ifstream in{path};
    if (!in.is_open()) {
        return 0;
    }
    m_vendors.clear();
    for (std::string line; std::getline(in, line);) {
        if (auto entry = parse_oui_line(line)) {
            m_vendors.emplace(entry->first, std::move(entry->second));
        }
    }
    return m_vendors.size();
}

std::string_view OuiDb::lookup(Mac const &mac) const {
    auto const prefix = static_cast<std::uint32_t>(mac.bytes[0]) << 16 | static_cast<std::uint32_t>(mac.bytes[1]) << 8 | mac.bytes[2];
    auto const it = m_vendors.find(prefix);
    return it == m_vendors.end() ? std::string_view{} : std::string_view{it->second};
}
