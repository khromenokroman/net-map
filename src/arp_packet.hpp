#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <span>

#include "ipv4.hpp"

/**
 * @brief Операция ARP.
 */
enum class ARP_OP : std::uint16_t {
    REQUEST = 1, ///< Запрос «у кого этот IP».
    REPLY = 2,   ///< Ответ.
};

/**
 * @brief Отправитель ARP-пакета: по нему видно, что хост с таким IP и MAC есть в сети.
 */
struct ArpSender {
    Mac mac;        ///< MAC отправителя (поле SHA).
    Ipv4 ip;        ///< IP отправителя (поле SPA).
    Ipv4 target_ip; ///< Запрашиваемый IP (поле TPA).
    ARP_OP op{};    ///< Операция.
};

/**
 * @brief Размер Ethernet-кадра с ARP-запросом, дополненного до минимальной длины Ethernet (без FCS).
 */
constexpr std::size_t ARP_FRAME_SIZE = 60;

/**
 * @brief Собирает широковещательный Ethernet-кадр с ARP-запросом.
 * @param src_mac MAC интерфейса-отправителя.
 * @param src_ip IP интерфейса-отправителя.
 * @param target Запрашиваемый IP.
 * @return Кадр, готовый к отправке через AF_PACKET/SOCK_RAW.
 */
[[nodiscard]] std::array<std::uint8_t, ARP_FRAME_SIZE> build_arp_request(Mac const &src_mac, Ipv4 src_ip, Ipv4 target);

/**
 * @brief Разбирает Ethernet-кадр с ARP-пакетом (Ethernet/IPv4).
 * @param frame Кадр, начиная с Ethernet-заголовка.
 * @return Отправитель пакета или std::nullopt, если это не ARP для Ethernet/IPv4.
 */
[[nodiscard]] std::optional<ArpSender> parse_arp_frame(std::span<std::uint8_t const> frame);
