#include <stddef.h>

// From syscall.s
int sys_write (int fd, char* buf, size_t len);
int sys_exit_group (int code);

int main (void) {
    sys_write(1, "Hello World!\n", 13);
    sys_exit_group(123);
    __builtin_unreachable();
}
