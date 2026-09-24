#include <signal.h>
#include <syslog.h>

#include <cstdlib>
#include <iostream>
#include <thread>

#include "config.hpp"
#include "net_monitor.hpp"
#include "web_server.hpp"

namespace {

void print(NetSnapshot const &s) {
    for (auto const &w : s.warnings) {
        std::cout << "Пропущено: " << w << "\n";
    }
    for (auto const &t : s.targets) {
        std::cout << "== " << t.name << " " << t.subnet.to_string() << "\n";
        for (auto const &h : s.hosts) {
            if (!(h.subnet == t.subnet)) {
                continue;
            }
            std::cout << "  " << h.ip.to_string() << "\t" << h.mac.to_string() << "\t"
                      << (h.vendor.empty() && h.local_mac ? "(локальный MAC)" : h.vendor) << "\t" << h.hostname << (h.self ? "\tЭТА МАШИНА" : "")
                      << (h.gateway ? "\tШЛЮЗ" : "") << (h.online ? "" : "\tНЕ ОТВЕЧАЕТ") << (h.conflict ? "\tКОНФЛИКТ IP" : "") << "\n";
        }
    }
    for (auto const &e : s.events) {
        std::cout << "  событие: " << e.text << "\n";
    }
    std::cout.flush();
}

} // namespace

int main(int argc, char *argv[]) {
    try {
        bool once = false;
        std::string_view cfg_path = "/etc/net-map/cfg.json";
        for (int i = 1; i < argc; ++i) {
            std::string_view const arg = argv[i];
            if (arg == "--once") {
                once = true;
            } else {
                cfg_path = arg;
            }
        }
        auto const cfg = load_config(cfg_path);
        setenv("RES_OPTIONS", "timeout:1 attempts:1", 0);
        openlog("net-map", LOG_PID | LOG_CONS, LOG_USER);
        setlogmask(LOG_UPTO(cfg.log_level));

        if (once) {
            NetMonitor monitor{cfg};
            monitor.scan_once();
            monitor.resolve_pending();
            print(monitor.snapshot());
            return EXIT_SUCCESS;
        }

        sigset_t signals;
        sigemptyset(&signals);
        sigaddset(&signals, SIGINT);
        sigaddset(&signals, SIGTERM);
        pthread_sigmask(SIG_BLOCK, &signals, nullptr);

        NetMonitor monitor{cfg};
        WebServer server{cfg, monitor};
        std::jthread signal_thread{[&server, &signals] {
            int sig{};
            sigwait(&signals, &sig);
            server.stop();
        }};
        monitor.start();
        try {
            server.run();
        } catch (...) {
            pthread_kill(signal_thread.native_handle(), SIGTERM);
            throw;
        }
        pthread_kill(signal_thread.native_handle(), SIGTERM);
        monitor.stop();
    } catch (std::exception const &ex) {
        std::cerr << "Ошибка во время выполнения: " << ex.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
