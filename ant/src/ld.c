
#include "common.h"

VISIBLE
unsigned long long __stack_chk_guard = 0x1234;

VISIBLE
void _dl_fatal_printf (void) {
    __builtin_trap();
}

VISIBLE
void _dl_exception_create (void) {
    __builtin_trap();
}

VISIBLE
void __tunable_get_val (void) {
    __builtin_trap();
}

VISIBLE
void _dl_find_dso_for_object (void) {
    __builtin_trap();
}

VISIBLE
char _rtld_global[4120];
VISIBLE
char _rtld_global_ro[304];

VISIBLE
int __libc_enable_secure = 0;

VISIBLE
void* __libc_stack_end;

VISIBLE
char** _dl_argv;

VISIBLE
void _dl_make_stack_executable (void) {
    __builtin_trap();
}
