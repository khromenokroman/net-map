#pragma once
#include <string_view>

/**
 * @brief Возвращает HTML страницы с картой сети.
 *
 * Страница статическая: стили и скрипт встроены, данные подгружаются из /api/network.
 *
 * @return HTML-код страницы.
 */
[[nodiscard]] std::string_view index_page();
