#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

/**
 * @brief IPv4-адрес в порядке байт хоста.
 */
struct Ipv4 {
    std::uint32_t value{}; ///< Адрес, старший байт — первый октет.

    /**
     * @brief Разбирает адрес вида "192.168.1.10".
     * @param text Строка с адресом.
     * @return Адрес или std::nullopt, если строка не является IPv4-адресом.
     */
    [[nodiscard]] static std::optional<Ipv4> parse(std::string_view text);

    /**
     * @brief Возвращает адрес в виде "192.168.1.10".
     */
    [[nodiscard]] std::string to_string() const;

    auto operator<=>(Ipv4 const &) const = default;
};

/**
 * @brief IPv4-подсеть: адрес сети и длина префикса.
 */
struct Subnet {
    Ipv4 network{};        ///< Адрес сети (биты хоста обнулены).
    std::uint8_t prefix{}; ///< Длина префикса, 0–32.

    /**
     * @brief Строит подсеть по адресу интерфейса и длине префикса.
     * @param addr Любой адрес из подсети.
     * @param prefix Длина префикса, 0–32.
     */
    [[nodiscard]] static Subnet from(Ipv4 addr, std::uint8_t prefix);

    /**
     * @brief Возвращает маску подсети.
     */
    [[nodiscard]] std::uint32_t mask() const;

    /**
     * @brief Проверяет, входит ли адрес в подсеть.
     * @param addr Проверяемый адрес.
     */
    [[nodiscard]] bool contains(Ipv4 addr) const;

    /**
     * @brief Возвращает число адресов хостов (без адреса сети и широковещательного для префиксов до /30).
     */
    [[nodiscard]] std::uint64_t host_count() const;

    /**
     * @brief Возвращает первый адрес хоста.
     */
    [[nodiscard]] Ipv4 first_host() const;

    /**
     * @brief Возвращает последний адрес хоста.
     */
    [[nodiscard]] Ipv4 last_host() const;

    /**
     * @brief Возвращает подсеть в виде "192.168.1.0/24".
     */
    [[nodiscard]] std::string to_string() const;

    auto operator<=>(Subnet const &) const = default;
};

/**
 * @brief MAC-адрес.
 */
struct Mac {
    std::array<std::uint8_t, 6> bytes{}; ///< Байты адреса.

    /**
     * @brief Разбирает адрес вида "aa:bb:cc:dd:ee:ff" (регистр не важен, допускается разделитель '-').
     * @param text Строка с адресом.
     * @return Адрес или std::nullopt при ошибке формата.
     */
    [[nodiscard]] static std::optional<Mac> parse(std::string_view text);

    /**
     * @brief Возвращает адрес в виде "aa:bb:cc:dd:ee:ff".
     */
    [[nodiscard]] std::string to_string() const;

    auto operator<=>(Mac const &) const = default;
};
