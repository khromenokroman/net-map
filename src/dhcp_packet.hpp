#pragma once
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "ipv4.hpp"

/**
 * @brief Тип DHCP-сообщения (опция 53).
 */
enum class DHCP_TYPE : std::uint8_t {
    NONE = 0,     ///< Опции 53 нет (BOOTP).
    DISCOVER = 1, ///< Клиент ищет серверы.
    OFFER = 2,    ///< Сервер предлагает адрес.
    REQUEST = 3,  ///< Клиент запрашивает или продлевает адрес.
    DECLINE = 4,  ///< Клиент отказывается от адреса (адрес занят).
    ACK = 5,      ///< Сервер подтверждает аренду.
    NAK = 6,      ///< Сервер отказывает.
    RELEASE = 7,  ///< Клиент освобождает адрес.
    INFORM = 8,   ///< Клиент запрашивает только параметры.
};

/**
 * @brief Возвращает имя типа DHCP-сообщения ("DISCOVER", "OFFER" и т.д.).
 */
[[nodiscard]] std::string_view dhcp_type_name(DHCP_TYPE type);

/**
 * @brief DHCP-сообщение, извлечённое из Ethernet-кадра.
 */
struct DhcpFrame {
    std::string client_id;              ///< Опция 61 в виде hex-строки без разделителей; пусто, если нет.
    std::string hostname;               ///< Опция 12.
    std::string vendor_class;           ///< Опция 60.
    std::optional<Ipv4> server_id;      ///< Опция 54.
    std::optional<Ipv4> requested_ip;   ///< Опция 50.
    std::optional<Ipv4> router;         ///< Опция 3 (первый адрес).
    std::optional<std::uint32_t> lease; ///< Опция 51, секунд.
    std::optional<std::uint8_t> prefix; ///< Опция 1 в виде длины префикса.
    Mac src_mac;                        ///< MAC отправителя кадра.
    Mac chaddr;                         ///< MAC клиента из заголовка BOOTP.
    Ipv4 src_ip;                        ///< IP отправителя.
    Ipv4 ciaddr;                        ///< Текущий адрес клиента.
    Ipv4 yiaddr;                        ///< Адрес, который сервер выдаёт клиенту.
    std::uint32_t xid{};                ///< Идентификатор транзакции.
    DHCP_TYPE type{};                   ///< Тип сообщения.
    bool from_server{};                 ///< Сообщение сервера (BOOTREPLY), иначе клиента.
};

/**
 * @brief Разбирает Ethernet-кадр с DHCP-сообщением (IPv4/UDP, порты 67 и 68).
 * @param frame Кадр, начиная с Ethernet-заголовка.
 * @return Сообщение или std::nullopt, если это не DHCP.
 */
[[nodiscard]] std::optional<DhcpFrame> parse_dhcp_frame(std::span<std::uint8_t const> frame);

/**
 * @brief Собирает широковещательный Ethernet-кадр с DHCPDISCOVER для поиска серверов.
 *
 * Флаг broadcast установлен, чтобы серверы отвечали широковещательно. Запрос REQUEST
 * никогда не отправляется, поэтому аренда не занимается.
 *
 * @param src_mac MAC интерфейса (отправитель кадра).
 * @param chaddr MAC клиента в заголовке BOOTP.
 * @param xid Идентификатор транзакции.
 * @return Кадр, готовый к отправке через AF_PACKET/SOCK_RAW.
 */
[[nodiscard]] std::vector<std::uint8_t> build_dhcp_discover(Mac const &src_mac, Mac const &chaddr, std::uint32_t xid);

/**
 * @brief Возвращает MAC для поиска DHCP-серверов: локально администрируемый, производный от MAC интерфейса.
 *
 * Отдельный MAC в заголовке BOOTP нужен, чтобы запрос не затрагивал аренду самого интерфейса.
 */
[[nodiscard]] Mac probe_mac(Mac const &iface_mac);

/**
 * @brief Классическая BPF-программа ядра: только IPv4/UDP с портом 67 или 68 (без фрагментов).
 */
struct BpfInsn {
    std::uint16_t code; ///< Код инструкции.
    std::uint8_t jt;    ///< Переход при истине.
    std::uint8_t jf;    ///< Переход при лжи.
    std::uint32_t k;    ///< Аргумент.
};

/**
 * @brief Возвращает BPF-фильтр DHCP для сокета AF_PACKET (аналог tcpdump "ip and udp and (port 67 or port 68)").
 */
[[nodiscard]] std::span<BpfInsn const> dhcp_bpf_filter();
