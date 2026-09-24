#include <cstdlib>
#include <iostream>

#include "arp_scanner.hpp"
#include "config.hpp"
#include "netif.hpp"

int main(int argc, char *argv[]) {
    try {
        std::string_view const cfg_path = argc > 1 ? argv[1] : "/etc/net-map/cfg.json";
        auto const cfg = load_config(cfg_path);
        auto const plan = plan_scan(list_interfaces(), cfg.interfaces, cfg.max_hosts);
        for (auto const &w : plan.warnings) {
            std::cout << "Пропущено: " << w << "\n";
        }
        for (auto const &t : plan.targets) {
            auto const started = std::chrono::steady_clock::now();
            auto const res = ArpScanner{t}.scan(std::chrono::milliseconds{cfg.arp_timeout_ms});
            auto const ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count();
            std::cout << "== " << t.iface.name << " " << t.iface.subnet.to_string() << ": запросов " << res.sent << ", хостов " << res.hosts.size()
                      << ", " << ms << " мс\n";
            auto const conflicts = find_conflicts(res.hosts);
            for (auto const &h : res.hosts) {
                std::cout << "  " << h.ip.to_string() << "\t" << h.mac.to_string() << (conflicts.contains(h.ip) ? "\tКОНФЛИКТ IP" : "") << "\n";
            }
        }
    } catch (std::exception const &ex) {
        std::cerr << "Ошибка во время выполнения: " << ex.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
