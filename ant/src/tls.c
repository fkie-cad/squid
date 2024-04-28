
#include "common.h"

typedef struct {
    unsigned long int ti_module;
    unsigned long int ti_offset;
} tls_index;

VISIBLE
void* __tls_get_addr (tls_index* ti) {
    (void) ti;
    
    __builtin_trap();
}

VISIBLE
void _dl_deallocate_tls (void) {
    __builtin_trap();
}

VISIBLE
void _dl_allocate_tls (void) {
    __builtin_trap();
}

VISIBLE
void _dl_get_tls_static_info (void) {
    __builtin_trap();
}

VISIBLE
void _dl_allocate_tls_init (void) {
    __builtin_trap();
}
