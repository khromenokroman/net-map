#include <cstdlib>
#include <iostream>

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
            std::cout << t.iface.name << " " << t.iface.addr.to_string() << " " << t.iface.mac.to_string() << " -> " << t.iface.subnet.to_string()
                      << " (" << t.iface.subnet.host_count() << " адресов: " << t.iface.subnet.first_host().to_string() << " - "
                      << t.iface.subnet.last_host().to_string() << ")\n";
        }
    } catch (std::exception const &ex) {
        std::cerr << "Ошибка во время выполнения: " << ex.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
