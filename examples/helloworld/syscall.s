.text

sys_write: 
    li a7, 64
    ecall
    jr ra

sys_exit_group:
    li a7, 94
    ecall
    jr ra

.global sys_write
.global sys_exit_group
