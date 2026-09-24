#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>

#include "oui.hpp"
#include "route.hpp"

TEST(Oui, ParseLine) {
    auto const e = parse_oui_line("D4-01-C3   (hex)\t\tRouterboard.com\r");
    ASSERT_TRUE(e);
    EXPECT_EQ(e->first, 0xD401C3U);
    EXPECT_EQ(e->second, "Routerboard.com");
    EXPECT_FALSE(parse_oui_line("D401C3     (base 16)\t\tRouterboard.com"));
    EXPECT_FALSE(parse_oui_line("\t\t\t\tRiga  LV-1063"));
    EXPECT_FALSE(parse_oui_line("ZZ-01-C3   (hex)\t\tBad"));
    EXPECT_FALSE(parse_oui_line("D4-01-C3   (hex)\t\t  \r"));
}

TEST(Oui, LoadAndLookup) {
    auto const path = testing::TempDir() + "oui_test.txt";
    {
        std::ofstream f{path};
        f << "OUI/MA-L\t\t\tOrganization\r\n"
             "D4-01-C3   (hex)\t\tRouterboard.com\r\n"
             "D401C3     (base 16)\t\tRouterboard.com\r\n"
             "\t\t\t\tRiga  LV-1063\r\n"
             "00-50-56   (hex)\t\tVMware, Inc.\r\n";
    }
    OuiDb db;
    EXPECT_EQ(db.load(path), 2U);
    EXPECT_EQ(db.lookup(*Mac::parse("d4:01:c3:b6:f2:ca")), "Routerboard.com");
    EXPECT_EQ(db.lookup(*Mac::parse("00:50:56:aa:bb:cc")), "VMware, Inc.");
    EXPECT_EQ(db.lookup(*Mac::parse("42:ec:2d:99:ca:ec")), "");
    EXPECT_EQ(OuiDb{}.load("/nonexistent/oui.txt"), 0U);
    std::remove(path.c_str());
}

TEST(Oui, LocallyAdministered) {
    EXPECT_TRUE(is_locally_administered(*Mac::parse("42:ec:2d:99:ca:ec")));
    EXPECT_TRUE(is_locally_administered(*Mac::parse("da:9a:8f:87:b1:a8")));
    EXPECT_FALSE(is_locally_administered(*Mac::parse("d4:01:c3:b6:f2:ca")));
    EXPECT_FALSE(is_locally_administered(*Mac::parse("54:02:02:03:52:50")));
}

TEST(Route, DefaultGateways) {
    auto const gws = parse_default_gateways(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
        "wlp0s20f3\t00000000\t0158A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"
        "eth0\t00000000\t0187A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
        "eth0\t00000000\t0287A8C0\t0003\t0\t0\t50\t00000000\t0\t0\t0\n"
        "docker0\t00000A0A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
        "wlp0s20f3\t3D22496D\t0158A8C0\t0007\t0\t0\t50\tFFFFFFFF\t0\t0\t0\n"
        "eth1\t00000000\t0100000A\t0002\t0\t0\t0\t00000000\t0\t0\t0\n");
    ASSERT_EQ(gws.size(), 2U);
    EXPECT_EQ(gws.at("wlp0s20f3").to_string(), "192.168.88.1");
    EXPECT_EQ(gws.at("eth0").to_string(), "192.168.135.2");
    EXPECT_TRUE(parse_default_gateways("").empty());
}
