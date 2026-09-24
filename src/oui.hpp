#pragma once
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

#include "ipv4.hpp"

/**
 * @brief Разбирает строку базы OUI формата IEEE ("D4-01-C3   (hex)\t\tRouterboard.com").
 * @param line Строка файла oui.txt.
 * @return Префикс MAC (первые 3 байта) и название производителя или std::nullopt, если строка другого вида.
 */
[[nodiscard]] std::optional<std::pair<std::uint32_t, std::string>> parse_oui_line(std::string_view line);

/**
 * @brief Проверяет, что MAC-адрес локально администрируемый (второй бит первого байта).
 *
 * Такие адреса не принадлежат производителю: их назначают вручную, генерируют виртуальные
 * машины и контейнеры, а телефоны используют их как случайные MAC.
 */
[[nodiscard]] bool is_locally_administered(Mac const &mac);

/**
 * @brief База производителей сетевых устройств по префиксу MAC-адреса (OUI).
 */
class OuiDb {
   public:
    /**
     * @brief Загружает базу из файла формата IEEE oui.txt (пакет ieee-data).
     * @param path Путь к файлу.
     * @return Число загруженных записей; 0, если файл не открылся.
     */
    std::size_t load(std::string const &path);

    /**
     * @brief Возвращает производителя по MAC-адресу.
     * @param mac MAC-адрес.
     * @return Название производителя или пустая строка, если префикс неизвестен.
     */
    [[nodiscard]] std::string_view lookup(Mac const &mac) const;

   private:
    std::unordered_map<std::uint32_t, std::string> m_vendors; // 56
};
