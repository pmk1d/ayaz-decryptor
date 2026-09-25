#include "cli.hpp"
#include "salsa.hpp"

#include <cuda_runtime.h>
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace {
using namespace salsa_search;
constexpr unsigned hit_capacity = 4096;

struct Config {
    State state;
    unsigned offsets[5];
    unsigned offset_count;
    uint32_t target[16];
    unsigned target_length;
};

__constant__ Config config;

__device__ __forceinline__ State candidate_state(uint64_t candidate) {
    State state = config.state;
#pragma unroll
    for (unsigned i = 0; i < 5; ++i)
        if (i < config.offset_count)
            set_byte(state, config.offsets[i], static_cast<uint32_t>((candidate >> (8 * i)) & 255));
    return state;
}

template<bool FourBytes>
__device__ __forceinline__ bool matches(const State& output) {
    if constexpr (FourBytes) return output.x0 == config.target[0];
    else {
#define MATCH(i) \
        if (config.target_length > 4 * i) { \
            const unsigned remaining = config.target_length - 4 * i; \
            const uint32_t mask = remaining >= 4 ? UINT32_MAX : (uint32_t{1} << (remaining * 8)) - 1; \
            if ((output.x##i & mask) != config.target[i]) return false; \
        }
        MATCH(0) MATCH(1) MATCH(2) MATCH(3) MATCH(4) MATCH(5) MATCH(6) MATCH(7)
        MATCH(8) MATCH(9) MATCH(10) MATCH(11) MATCH(12) MATCH(13) MATCH(14) MATCH(15)
#undef MATCH
        return true;
    }
}

template<bool FourBytes>
__global__ void search_kernel(uint64_t start, uint64_t count, uint64_t* hits,
                              unsigned* hit_count, unsigned* overflow) {
    const uint64_t first = uint64_t{blockIdx.x} * blockDim.x + threadIdx.x;
    const uint64_t stride = uint64_t{gridDim.x} * blockDim.x;
    for (uint64_t i = first; i < count; i += stride) {
        const uint64_t candidate = start + i;
        const State output = block(candidate_state(candidate));
        if (matches<FourBytes>(output)) {
            const unsigned position = atomicAdd(hit_count, 1U);
            if (position < hit_capacity) hits[position] = candidate;
            else atomicExch(overflow, 1U);
        }
    }
}

__global__ void blocks_kernel(uint64_t start, uint64_t count, uint32_t* output) {
    const unsigned i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < count) store(block(candidate_state(start + i)), output + i * 16);
}

void check(cudaError_t code, const char* operation) {
    if (code != cudaSuccess)
        throw std::runtime_error(std::string(operation) + ": " + cudaGetErrorString(code));
}

template<class T> class DeviceBuffer {
public:
    T* pointer = nullptr;
    explicit DeviceBuffer(size_t count) {
        check(cudaMalloc(reinterpret_cast<void**>(&pointer), count * sizeof(T)), "cudaMalloc");
    }
    DeviceBuffer(const DeviceBuffer&) = delete;
    DeviceBuffer& operator=(const DeviceBuffer&) = delete;
    ~DeviceBuffer() { if (pointer) cudaFree(pointer); }
};

class Event {
public:
    cudaEvent_t event{};
    Event() { check(cudaEventCreate(&event), "cudaEventCreate"); }
    Event(const Event&) = delete;
    Event& operator=(const Event&) = delete;
    ~Event() { cudaEventDestroy(event); }
};

std::string quote(const std::string& value) {
    std::ostringstream output;
    output << '"';
    for (unsigned char c : value) {
        if (c == '\\' || c == '"') output << '\\' << c;
        else if (c < 32) output << "\\u" << std::hex << std::setw(4) << std::setfill('0') << unsigned{c};
        else output << c;
    }
    output << '"';
    return output.str();
}

Config make_config(const Options& options) {
    Config result{};
    uint32_t words[16]{};
    for (unsigned i = 0; i < 64; ++i)
        words[i / 4] |= uint32_t{options.state[i]} << (8 * (i % 4));
    result.state = {words[0], words[1], words[2], words[3], words[4], words[5], words[6], words[7],
                    words[8], words[9], words[10], words[11], words[12], words[13], words[14], words[15]};
    result.offset_count = static_cast<unsigned>(options.offsets.size());
    for (unsigned i = 0; i < result.offset_count; ++i) result.offsets[i] = options.offsets[i];
    result.target_length = static_cast<unsigned>(options.target.size());
    for (unsigned i = 0; i < result.target_length; ++i)
        result.target[i / 4] |= uint32_t{options.target[i]} << (8 * (i % 4));
    return result;
}

void blocks(const Options& options) {
    if (options.count == 0) return;
    DeviceBuffer<uint32_t> output(options.count * 16);
    blocks_kernel<<<1, 256>>>(options.start, options.count, output.pointer);
    check(cudaGetLastError(), "blocks kernel launch");
    check(cudaDeviceSynchronize(), "blocks kernel completion");
    std::vector<uint32_t> host(options.count * 16);
    check(cudaMemcpy(host.data(), output.pointer, host.size() * sizeof(uint32_t), cudaMemcpyDeviceToHost), "blocks copy");
    for (uint64_t i = 0; i < options.count; ++i) {
        std::ostringstream hex;
        hex << std::hex << std::setfill('0');
        for (unsigned b = 0; b < 64; ++b)
            hex << std::setw(2) << ((host[i * 16 + b / 4] >> (8 * (b % 4))) & 255U);
        std::cout << "{\"type\":\"block\",\"candidate\":" << options.start + i
                  << ",\"hex\":\"" << hex.str() << "\"}\n";
    }
    std::cout.flush();
}

int search(const Options& options, const cudaDeviceProp& properties) {
    DeviceBuffer<uint64_t> hits(hit_capacity);
    DeviceBuffer<unsigned> hit_count(1), overflow(1);
    Event begin_event, end_event;
    const auto begin = std::chrono::steady_clock::now();
    auto elapsed = [&]() {
        return std::chrono::duration<double>(std::chrono::steady_clock::now() - begin).count();
    };
    uint64_t next = options.start;
    const uint64_t end = options.start + options.count;
    const unsigned grid = static_cast<unsigned>(properties.multiProcessorCount) * 16;
    while (next < end) {
        if (options.max_seconds > 0 && elapsed() >= options.max_seconds) break;
        const uint64_t count = std::min(options.batch_count, end - next);
        check(cudaMemset(hit_count.pointer, 0, sizeof(unsigned)), "clear hit counter");
        check(cudaMemset(overflow.pointer, 0, sizeof(unsigned)), "clear overflow");
        check(cudaEventRecord(begin_event.event), "start timing");
        if (options.target.size() == 4)
            search_kernel<true><<<grid, options.threads>>>(next, count, hits.pointer, hit_count.pointer, overflow.pointer);
        else
            search_kernel<false><<<grid, options.threads>>>(next, count, hits.pointer, hit_count.pointer, overflow.pointer);
        check(cudaGetLastError(), "search kernel launch");
        check(cudaEventRecord(end_event.event), "end timing");
        check(cudaEventSynchronize(end_event.event), "search kernel completion");
        float milliseconds = 0;
        check(cudaEventElapsedTime(&milliseconds, begin_event.event, end_event.event), "read timing");
        unsigned found = 0, overflowed = 0;
        check(cudaMemcpy(&found, hit_count.pointer, sizeof(unsigned), cudaMemcpyDeviceToHost), "read hit counter");
        check(cudaMemcpy(&overflowed, overflow.pointer, sizeof(unsigned), cudaMemcpyDeviceToHost), "read overflow");
        if (overflowed || found > hit_capacity) {
            std::cout << "{\"type\":\"error\",\"message\":\"hit buffer overflow\"}" << std::endl;
            std::cerr << "Переполнение результатов: пакет не опубликован; уменьшите BATCH_COUNT\n";
            return 4;
        }
        std::vector<uint64_t> host(found);
        if (found) check(cudaMemcpy(host.data(), hits.pointer, found * sizeof(uint64_t), cudaMemcpyDeviceToHost), "read hits");
        std::sort(host.begin(), host.end());
        std::cout << "{\"type\":\"batch\",\"start\":" << next << ",\"count\":" << count
                  << ",\"elapsed_seconds\":" << milliseconds / 1000.0 << ",\"hits\":[";
        for (unsigned i = 0; i < found; ++i) std::cout << (i ? "," : "") << host[i];
        std::cout << "],\"overflow\":false}" << std::endl;
        if (!std::cout) throw std::runtime_error("Ошибка записи JSONL");
        next += count;
    }
    const double seconds = elapsed();
    const uint64_t tested = next - options.start;
    std::cout << "{\"type\":\"summary\",\"start\":" << options.start << ",\"next_candidate\":" << next
              << ",\"tested\":" << tested << ",\"elapsed_seconds\":" << seconds
              << ",\"rate\":" << (seconds > 0 ? tested / seconds : 0)
              << ",\"completed\":" << (next == end ? "true" : "false")
              << ",\"stop_reason\":\"" << (next == end ? "completed" : "max_seconds") << "\"}" << std::endl;
    if (!std::cout) throw std::runtime_error("Ошибка записи JSONL");
    return 0;
}
}

int main(int argc, char** argv) {
    try {
        std::vector<std::string> args(argv + 1, argv + argc);
        const auto options = salsa_search::parse(args);
        int devices = 0;
        check(cudaGetDeviceCount(&devices), "cudaGetDeviceCount");
        if (options.device >= static_cast<unsigned>(devices)) throw std::invalid_argument("GPU с таким номером отсутствует");
        check(cudaSetDevice(static_cast<int>(options.device)), "cudaSetDevice");
        cudaDeviceProp properties{};
        check(cudaGetDeviceProperties(&properties, static_cast<int>(options.device)), "cudaGetDeviceProperties");
        if (options.threads > static_cast<unsigned>(properties.maxThreadsPerBlock))
            throw std::invalid_argument("THREADS превышает предел выбранной GPU");
        const Config host_config = make_config(options);
        check(cudaMemcpyToSymbol(config, &host_config, sizeof(host_config)), "copy configuration");
        std::cout << std::setprecision(12);
        if (options.blocks) { blocks(options); return std::cout ? 0 : 3; }
        std::cout << "{\"type\":\"device\",\"device\":" << options.device << ",\"name\":" << quote(properties.name)
                  << ",\"compute_capability\":\"" << properties.major << '.' << properties.minor
                  << "\",\"multiprocessors\":" << properties.multiProcessorCount
                  << ",\"threads\":" << options.threads << "}" << std::endl;
        return search(options, properties);
    } catch (const std::invalid_argument& error) {
        std::cerr << "Аргументы: " << error.what() << '\n';
        return 2;
    } catch (const std::exception& error) {
        std::cerr << "Ошибка: " << error.what() << '\n';
        return 3;
    }
}
