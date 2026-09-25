#include "cli.hpp"
#include "salsa.hpp"

#include <cassert>
#include <iostream>

using namespace salsa_search;

int main() {
    const std::string zero_state(128, '0');
    const std::vector<std::string> basic{"search", zero_state, "63,0,31,17,42", "01020304", "0", "1099511627776"};
    auto parsed = parse(basic);
    assert(parsed.offsets == std::vector<unsigned>({63,0,31,17,42}));
    assert(parsed.count == (uint64_t{1} << 40));
    assert(parsed.target == std::vector<uint8_t>({1,2,3,4}));
    auto ending = basic;
    ending[4] = "1099511627776";
    ending[5] = "0";
    assert(parse(ending).count == 0);
    auto upper = basic;
    upper[4] = "1099511627775";
    upper[5] = "1";
    assert(parse(upper).start == (uint64_t{1} << 40) - 1);
    auto options = basic;
    options.insert(options.end(), {"67108864", "0.25", "2", "512"});
    parsed = parse(options);
    assert(parsed.batch_count == (uint64_t{1} << 26));
    assert(parsed.max_seconds == 0.25 && parsed.device == 2 && parsed.threads == 512);

    unsigned rejected = 0;
    auto reject = [&](std::vector<std::string> args) {
        bool caught = false;
        try { (void)parse(args); } catch (const std::invalid_argument&) { caught = true; }
        assert(caught);
        ++rejected;
    };
    reject({});
    reject({"unknown"});
    for (const auto& offsets : {"", "0,", ",0", "0,,1", "0,0", "-1", "64", "0,1,2,3,4,5", " 1"}) {
        auto args = basic; args[2] = offsets; reject(args);
    }
    for (const auto& state : {std::string{}, std::string(126,'0'), std::string(130,'0'), std::string(128,'g')}) {
        auto args = basic; args[1] = state; reject(args);
    }
    for (const auto& target : {std::string{}, std::string("0"), std::string("gg"), std::string(130,'0')}) {
        auto args = basic; args[3] = target; reject(args);
    }
    for (const auto& start : {"-1", "+1", "1 ", "1099511627777", "184467440737095516160"}) {
        auto args = basic; args[4] = start; reject(args);
    }
    for (const auto& count : {"-1", "1099511627777", "184467440737095516160"}) {
        auto args = basic; args[5] = count; reject(args);
    }
    auto crossing = upper; crossing[5] = "2"; reject(crossing);
    for (const auto& batch : {"0", "-1", "4294967296"}) {
        auto args = options; args[6] = batch; reject(args);
    }
    for (const auto& seconds : {"-1", "nan", "inf", ".", "1.1.1", " 1", "1e9", ""}) {
        auto args = options; args[7] = seconds; reject(args);
    }
    for (const auto& threads : {"0", "31", "33", "2048", "-1"}) {
        auto args = options; args[9] = threads; reject(args);
    }
    auto extra = options; extra.push_back("extra"); reject(extra);
    auto small_space = basic; small_space[2] = "0"; small_space[5] = "257"; reject(small_space);
    assert(parse({"blocks", zero_state, "0", "0", "256"}).count == 256);
    reject({"blocks", zero_state, "0,1", "0", "257"});
    reject({"blocks", zero_state, "0", "256", "1"});

    State state{};
    uint32_t words[16]{};
    store(block(state), words);
    for (uint32_t word : words) assert(word == 0);
    for (unsigned i = 0; i < 64; ++i) set_byte(state, i, i);
    store(block(state), words);
    const auto expected = hex("3c561d323c15ba1eb897f3ebdb284b5dfbb93822038c6739d0e8b9efc8c801853c9f62090ad37bf7066293aae2e8a758a43a1fd5619c1e8929c9f40c819a44d4");
    for (unsigned i = 0; i < 64; ++i) assert(((words[i/4] >> (8*(i%4))) & 255) == expected[i]);
    for (unsigned i = 0; i < 64; ++i) set_byte(state, i, 255);
    store(block(state), words);
    const auto all_ones = hex("88f9c03950885f562ad01a0fb71a2dd7b71a2dd788f9c03950885f562ad01a0f2ad01a0fb71a2dd788f9c03950885f5650885f562ad01a0fb71a2dd788f9c039");
    for (unsigned i = 0; i < 64; ++i) assert(((words[i/4] >> (8*(i%4))) & 255) == all_ones[i]);
    for (unsigned i = 0; i < 64; ++i) {
        state = {};
        set_byte(state, i, 0xa5);
        store(state, words);
        for (unsigned b = 0; b < 64; ++b)
            assert(((words[b/4] >> (8*(b%4))) & 255) == (b == i ? 0xa5 : 0));
    }
    std::cout << "Проверки пройдены: " << rejected << " недопустимых аргументов, границы диапазонов, 3 вектора Salsa20, 64 позиции байтов\n";
}
