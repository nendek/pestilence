global ft_strcat

section .text

ft_strcat:
    push rdi 
first_loop:
    cmp [rdi], byte 0
    je append
    inc rdi 
    jmp first_loop
append:
    cmp [rsi], byte 0
    je end 
    mov r8, [rsi]
    mov [rdi], r8
    inc rdi 
    inc rsi 
    jmp append
end:
    pop rax 
    ret
