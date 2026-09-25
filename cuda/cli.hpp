#pragma once

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace salsa_search {

struct Options {
    bool blocks = false;
    std::array<uint8_t, 64> state{};
    std::vector<unsigned> offsets;
    std::vector<uint8_t> target;
    uint64_t start = 0;
    uint64_t count = 0;
    uint64_t batch_count = uint64_t{1} << 24;
    double max_seconds = 0;
    unsigned device = 0;
    unsigned threads = 256;
};

inline uint64_t number(const std::string& value, uint64_t maximum) {
    if (value.empty()) throw std::invalid_argument("Пустое число");
    uint64_t result = 0;
    for (const char c : value) {
        if (c < '0' || c > '9') throw std::invalid_argument("Ожидалось целое неотрицательное число");
        const unsigned digit = static_cast<unsigned>(c - '0');
        if (digit > maximum || result > (maximum - digit) / 10)
            throw std::invalid_argument("Число вне допустимого диапазона");
        result = result * 10 + digit;
    }
    return result;
}

inline std::vector<uint8_t> hex(const std::string& text) {
    if (text.empty() || text.size() % 2 != 0 || text.size() > 128)
        throw std::invalid_argument("Некорректная длина hex");
    auto nibble = [](char c) -> unsigned {
        if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
        if (c >= 'a' && c <= 'f') return static_cast<unsigned>(c - 'a' + 10);
        if (c >= 'A' && c <= 'F') return static_cast<unsigned>(c - 'A' + 10);
        throw std::invalid_argument("Некорректный символ hex");
    };
    std::vector<uint8_t> result;
    for (size_t i = 0; i < text.size(); i += 2)
        result.push_back(static_cast<uint8_t>((nibble(text[i]) << 4) | nibble(text[i + 1])));
    return result;
}

inline Options parse(const std::vector<std::string>& args) {
    if (args.empty() || (args[0] != "search" && args[0] != "blocks"))
        throw std::invalid_argument("Режим должен быть search или blocks");
    Options result;
    result.blocks = args[0] == "blocks";
    if ((!result.blocks && (args.size() < 6 || args.size() > 10)) ||
        (result.blocks && (args.size() < 5 || args.size() > 6)))
        throw std::invalid_argument("Некорректное число аргументов");
    const auto state = hex(args[1]);
    if (state.size() != 64) throw std::invalid_argument("Состояние должно содержать 64 байта");
    std::copy(state.begin(), state.end(), result.state.begin());
    std::array<bool, 64> seen{};
    size_t begin = 0;
    while (true) {
        const size_t end = args[2].find(',', begin);
        const unsigned offset = static_cast<unsigned>(number(args[2].substr(begin, end - begin), 63));
        if (seen[offset]) throw std::invalid_argument("Повторяющееся смещение");
        seen[offset] = true;
        result.offsets.push_back(offset);
        if (result.offsets.size() > 5) throw std::invalid_argument("Допустимо не более 5 смещений");
        if (end == std::string::npos) break;
        begin = end + 1;
    }
    const uint64_t space = uint64_t{1} << (8 * result.offsets.size());
    const size_t first = result.blocks ? 3 : 4;
    if (!result.blocks) result.target = hex(args[3]);
    result.start = number(args[first], space);
    result.count = number(args[first + 1], space - result.start);
    if (result.blocks) {
        if (result.count > 256) throw std::invalid_argument("Режим blocks ограничен 256 кандидатами");
        if (args.size() == 6) result.device = static_cast<unsigned>(number(args[5], 2147483647));
    } else {
        if (args.size() >= 7) result.batch_count = number(args[6], std::numeric_limits<uint32_t>::max());
        if (result.batch_count == 0) throw std::invalid_argument("Размер пакета должен быть положительным");
        if (args.size() >= 8) {
            if (args[7].empty()) throw std::invalid_argument("Пустой лимит времени");
            for (const char c : args[7])
                if ((c < '0' || c > '9') && c != '.') throw std::invalid_argument("Некорректный лимит времени");
            char* end = nullptr;
            result.max_seconds = std::strtod(args[7].c_str(), &end);
            if (end != args[7].c_str() + args[7].size() || !std::isfinite(result.max_seconds) || result.max_seconds < 0)
                throw std::invalid_argument("Некорректный лимит времени");
        }
        if (args.size() >= 9) result.device = static_cast<unsigned>(number(args[8], 2147483647));
        if (args.size() >= 10) result.threads = static_cast<unsigned>(number(args[9], 1024));
        if (result.threads < 32 || result.threads % 32 != 0)
            throw std::invalid_argument("THREADS должен быть кратен 32 и лежать в диапазоне 32..1024");
    }
    return result;
}

}
