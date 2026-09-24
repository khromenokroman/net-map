#include "config.hpp"

#include <gtest/gtest.h>

using nlohmann::json;

TEST(ParseConfig, Defaults) {
    auto const cfg = parse_config(json::object());
    EXPECT_EQ(cfg.listen_addr, "0.0.0.0");
    EXPECT_EQ(cfg.port, 8081);
    EXPECT_EQ(cfg.scan_interval_sec, 60);
    EXPECT_EQ(cfg.host_timeout_sec, 600);
    EXPECT_EQ(cfg.arp_timeout_ms, 1000);
    EXPECT_EQ(cfg.max_hosts, 4096U);
    EXPECT_TRUE(cfg.interfaces.empty());
}

TEST(ParseConfig, Values) {
    auto const cfg = parse_config(json::parse(R"({"port": 9000, "interfaces": ["eth0", "mgmt0"], "scan_interval_sec": 30, "max_hosts": 65536})"));
    EXPECT_EQ(cfg.port, 9000);
    EXPECT_EQ(cfg.interfaces, (std::vector<std::string>{"eth0", "mgmt0"}));
    EXPECT_EQ(cfg.scan_interval_sec, 30);
    EXPECT_EQ(cfg.max_hosts, 65536U);
}

TEST(ParseConfig, Errors) {
    for (auto const *bad : {R"([])", R"({"port": 0})", R"({"port": "80"})", R"({"port": 1.5})", R"({"log_level": 8})", R"({"scan_interval_sec": 1})",
                            R"({"arp_timeout_ms": 50})", R"({"max_hosts": 0})", R"({"max_hosts": 70000})", R"({"interfaces": "eth0"})",
                            R"({"interfaces": [""]})", R"({"interfaces": [1]})", R"({"listen_addr": 1})"}) {
        EXPECT_THROW((void)parse_config(json::parse(bad)), std::runtime_error) << bad;
    }
}

TEST(LoadConfig, MissingFile) { EXPECT_THROW((void)load_config("/nonexistent/cfg.json"), std::runtime_error); }
