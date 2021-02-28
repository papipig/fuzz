

    push rax
    push rbx
    push rcx
    lahf
    seto al
    mov ebx, dword [rel C]           ; __afl_prev_loc @ .cov+0x10000
    xor ebx, 0x1234
    lea rcx, [rel C]
    add rcx, rbx
    inc byte [rcx]              ; __afl_area_ptr @ .cov
    mov dword [rel C], 0x9876
    add al, 127
    sahf
    pop rcx
    pop rbx
    pop rax

C:
	db 0