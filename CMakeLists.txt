cmake_minimum_required(VERSION 3.25.1)
project(net-map
        VERSION 0.8.0.0
        LANGUAGES CXX
        HOMEPAGE_URL "https://github.com/khromenokroman/net-map")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_TESTS "Собирать тесты" ON)

find_package(fmt REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(Threads REQUIRED)

include(GNUInstallDirs)

set(NET_MAP_CONFIG "/etc/${PROJECT_NAME}/cfg.json")

configure_file(Version.in Version @ONLY)
configure_file(systemd/${PROJECT_NAME}.service.in ${PROJECT_NAME}.service @ONLY)

add_library(${PROJECT_NAME}-core STATIC
        src/api.cpp
        src/arp_packet.cpp
        src/arp_scanner.cpp
        src/config.cpp
        src/dhcp_inventory.cpp
        src/dhcp_packet.cpp
        src/dhcp_watcher.cpp
        src/index_page.cpp
        src/ipv4.cpp
        src/inventory.cpp
        src/net_monitor.cpp
        src/netif.cpp
        src/oui.cpp
        src/route.cpp
        src/web_server.cpp
)
target_include_directories(${PROJECT_NAME}-core PUBLIC src)
target_include_directories(${PROJECT_NAME}-core SYSTEM PUBLIC third_party/httplib)
target_link_libraries(${PROJECT_NAME}-core PUBLIC fmt::fmt-header-only nlohmann_json::nlohmann_json Threads::Threads)

add_executable(${PROJECT_NAME}
        src/main.cpp
)
target_link_libraries(${PROJECT_NAME} PRIVATE ${PROJECT_NAME}-core)

if (BUILD_TESTS)
    enable_testing()
    find_package(GTest REQUIRED)
    add_executable(${PROJECT_NAME}-tests
            tests/api_test.cpp
            tests/arp_test.cpp
            tests/config_test.cpp
            tests/dhcp_inventory_test.cpp
            tests/dhcp_packet_test.cpp
            tests/inventory_test.cpp
            tests/ipv4_test.cpp
            tests/netif_test.cpp
            tests/oui_route_test.cpp
    )
    target_link_libraries(${PROJECT_NAME}-tests PRIVATE ${PROJECT_NAME}-core GTest::gtest_main)
    target_compile_definitions(${PROJECT_NAME}-tests PRIVATE TEST_DATA_DIR="${CMAKE_SOURCE_DIR}/tests/data")
    include(GoogleTest)
    gtest_discover_tests(${PROJECT_NAME}-tests)
    add_test(NAME netns_scan COMMAND ${CMAKE_SOURCE_DIR}/tests/integration/netns_scan.sh $<TARGET_FILE:${PROJECT_NAME}>)
    set_tests_properties(netns_scan PROPERTIES SKIP_RETURN_CODE 77 TIMEOUT 60)
endif ()

install(TARGETS ${PROJECT_NAME}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.service
        DESTINATION lib/systemd/system
)
install(FILES configuration/cfg.json
        DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/${PROJECT_NAME}
)
install(FILES debian/copyright
        DESTINATION ${CMAKE_INSTALL_DOCDIR}
)

set(CPACK_PACKAGE_NAME "${PROJECT_NAME}")
set(CPACK_PACKAGE_VENDOR "khromenokroman")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_CONTACT "khromenokroman <roma55592@yandex.ru>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Web map of hosts in local subnets discovered by ARP")
set(CPACK_PACKAGE_DESCRIPTION "Scans local IPv4 subnets with ARP requests and shows a web map of hosts\nwith IP and MAC addresses, vendors, host names, default gateway and\nIP address conflicts, with an event log and JSON API.")
set(CPACK_PACKAGE_HOMEPAGE_URL "${PROJECT_HOMEPAGE_URL}")

set(CPACK_GENERATOR "DEB")
set(CPACK_STRIP_FILES ON)
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "${CPACK_PACKAGE_CONTACT}")
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_PACKAGE_DEPENDS "systemd")
set(CPACK_DEBIAN_PACKAGE_RECOMMENDS "ieee-data")
set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
        "${CMAKE_SOURCE_DIR}/debian/postinst"
        "${CMAKE_SOURCE_DIR}/debian/prerm"
        "${CMAKE_SOURCE_DIR}/debian/postrm"
        "${CMAKE_SOURCE_DIR}/debian/conffiles"
)
set(CPACK_DEBIAN_PACKAGE_CONTROL_STRICT_PERMISSION ON)
set(CPACK_INSTALL_DEFAULT_DIRECTORY_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

include(CPack)
