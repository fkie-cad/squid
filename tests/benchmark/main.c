#include <stdint.h>

#define MEM_SIZE (16 * 1024 * 1024)
char data[MEM_SIZE];

uint64_t state = 0x12345;
static inline __attribute__((always_inline)) uint64_t rand (void) {
	uint64_t x = state;
	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	return state = x;
}

int main (void) {
    for (unsigned long i = 0; i < (1UL << 28); ++i) {
        uint64_t index = rand() % (MEM_SIZE - 8);
        
        switch (rand() % 4) {
            case 0: {
                uint8_t* p = (uint8_t*) &data[index];
                *p = (uint8_t) rand();
                break;
            }
            
            case 1: {
                uint16_t* p = (uint16_t*) &data[index];
                *p = (uint16_t) rand();
                break;
            }
            
            case 2: {
                uint32_t* p = (uint32_t*) &data[index];
                *p = (uint32_t) rand();
                break;
            }
            
            case 3: {
                uint64_t* p = (uint64_t*) &data[index];
                *p = (uint64_t) rand();
                break;
            }
            
            default: {
                __builtin_unreachable();
            }
        }
    }
    
    __builtin_trap();
}
