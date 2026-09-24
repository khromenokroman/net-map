cmake_minimum_required(VERSION 3.25.1)
project(net-map
        VERSION 0.2.0.0
        LANGUAGES CXX
        HOMEPAGE_URL "https://github.com/khromenokroman/net-map")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_TESTS "Собирать тесты" ON)

find_package(fmt REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(Threads REQUIRED)

include(GNUInstallDirs)

configure_file(Version.in Version @ONLY)

add_library(${PROJECT_NAME}-core STATIC
        src/config.cpp
        src/ipv4.cpp
        src/netif.cpp
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
            tests/config_test.cpp
            tests/ipv4_test.cpp
            tests/netif_test.cpp
    )
    target_link_libraries(${PROJECT_NAME}-tests PRIVATE ${PROJECT_NAME}-core GTest::gtest_main)
    include(GoogleTest)
    gtest_discover_tests(${PROJECT_NAME}-tests)
endif ()
