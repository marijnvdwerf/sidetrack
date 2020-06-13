
#include <cstdint>
template<typename T>
constexpr T &mem(uintptr_t address) {
    return *((T *) address);
}

constexpr uint8_t LSB(uint32_t arg) {
    return arg & 1;
}
