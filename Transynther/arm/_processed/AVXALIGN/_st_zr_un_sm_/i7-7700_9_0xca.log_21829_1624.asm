.global s_prepare_buffers
s_prepare_buffers:
push %r12
push %r13
push %r8
push %rbx
push %rcx
push %rdi
push %rsi
lea addresses_WC_ht+0x1747f, %rsi
lea addresses_UC_ht+0x4751, %rdi
nop
nop
nop
nop
and %rbx, %rbx
mov $13, %rcx
rep movsq
nop
nop
cmp %r12, %r12
lea addresses_D_ht+0xd43f, %r13
nop
nop
nop
dec %r8
mov (%r13), %edi
nop
nop
nop
and $29003, %rbx
pop %rsi
pop %rdi
pop %rcx
pop %rbx
pop %r8
pop %r13
pop %r12
ret

    .global s_faulty_load
s_faulty_load:
push %r12
push %r14
push %r8
push %rbp
push %rbx
push %rdi
push %rsi

// Store
lea addresses_PSE+0xdb03, %rbp
nop
cmp %r14, %r14
mov $0x5152535455565758, %r8
movq %r8, %xmm7
movups %xmm7, (%rbp)
nop
nop
nop
nop
nop
add %rsi, %rsi

// Store
mov $0x5bcd09000000087f, %rdi
nop
nop
add %r12, %r12
movw $0x5152, (%rdi)
nop
nop
nop
xor %rbx, %rbx

// Faulty Load
mov $0x5bcd09000000087f, %r8
nop
nop
nop
nop
nop
add $7956, %rbx
movb (%r8), %r12b
lea oracles, %rbp
and $0xff, %r12
shlq $12, %r12
mov (%rbp,%r12,1), %r12
pop %rsi
pop %rdi
pop %rbx
pop %rbp
pop %r8
pop %r14
pop %r12
ret

/*
<gen_faulty_load>
[REF]
{'src': {'congruent': 0, 'AVXalign': False, 'same': False, 'size': 32, 'NT': False, 'type': 'addresses_NC'}, 'OP': 'LOAD'}
{'OP': 'STOR', 'dst': {'congruent': 2, 'AVXalign': False, 'same': False, 'size': 16, 'NT': False, 'type': 'addresses_PSE'}}
{'OP': 'STOR', 'dst': {'congruent': 0, 'AVXalign': False, 'same': True, 'size': 2, 'NT': False, 'type': 'addresses_NC'}}
[Faulty Load]
{'src': {'congruent': 0, 'AVXalign': True, 'same': True, 'size': 1, 'NT': False, 'type': 'addresses_NC'}, 'OP': 'LOAD'}
<gen_prepare_buffer>
{'src': {'congruent': 10, 'same': False, 'type': 'addresses_WC_ht'}, 'OP': 'REPM', 'dst': {'congruent': 0, 'same': False, 'type': 'addresses_UC_ht'}}
{'src': {'congruent': 3, 'AVXalign': False, 'same': False, 'size': 4, 'NT': False, 'type': 'addresses_D_ht'}, 'OP': 'LOAD'}
{'d0': 314, '00': 8457, '52': 13058}
52 52 52 52 00 52 52 00 00 52 d0 52 52 52 00 00 52 00 52 52 d0 52 00 00 00 00 00 52 52 00 52 00 00 52 52 52 00 00 52 00 52 52 00 00 d0 52 52 00 52 52 00 52 52 00 52 52 00 52 00 52 52 52 52 52 00 52 00 00 52 00 52 00 52 00 52 00 52 52 52 00 52 52 00 52 00 52 52 52 52 52 52 52 52 52 00 52 52 52 52 00 52 52 00 52 52 52 52 52 00 52 52 00 52 52 52 00 52 52 52 52 52 52 00 52 52 00 00 52 52 52 52 52 00 52 52 52 52 52 00 52 52 52 52 52 d0 52 00 52 00 52 00 52 00 00 52 00 52 00 52 00 52 00 00 00 52 52 52 52 52 00 52 52 00 52 00 52 00 00 00 52 52 52 52 52 52 00 52 00 52 52 52 52 00 52 00 00 52 00 52 52 52 52 00 52 00 52 52 00 52 52 52 52 52 00 52 00 52 52 00 00 00 52 00 00 00 00 52 52 00 00 00 00 00 d0 00 00 00 00 00 00 00 52 00 52 00 00 00 52 52 52 00 52 00 52 00 52 00 52 00 52 00 52 52 52 52 00 52 52 00 00 52 52 52 00 52 52 00 52 52 00 52 52 00 52 52 00 00 00 00 52 00 00 00 52 52 52 00 00 52 52 00 52 00 52 52 52 00 52 00 52 52 52 00 00 52 00 52 52 00 00 00 00 52 00 52 00 00 52 00 00 00 00 00 52 52 00 00 52 52 00 52 52 52 00 52 00 52 00 52 52 52 52 00 52 52 00 00 52 00 52 52 52 00 52 00 52 52 00 00 00 00 00 00 00 00 00 00 52 00 52 52 00 00 52 00 00 00 00 52 52 00 52 00 52 00 52 52 52 00 52 52 52 52 00 00 52 00 52 00 52 00 00 52 52 52 52 52 00 52 00 00 52 52 00 52 00 00 52 52 52 52 00 52 00 52 00 00 52 52 00 00 00 52 00 52 00 52 52 52 52 52 52 52 52 00 52 52 52 00 00 00 00 52 00 00 52 52 00 52 52 52 52 00 52 00 52 52 00 52 52 52 52 52 00 00 52 52 00 52 52 52 52 52 00 52 52 52 52 52 00 52 00 52 52 52 00 52 52 00 52 52 00 00 00 52 52 52 52 00 00 52 00 52 52 52 52 00 52 52 52 52 00 52 00 00 00 52 00 52 d0 00 00 52 52 52 00 52 52 00 52 00 52 00 52 52 52 00 52 00 52 52 00 52 00 52 52 00 52 00 52 52 52 52 00 52 00 00 52 00 52 52 00 52 52 00 00 52 00 52 00 00 52 00 52 00 52 00 52 00 52 52 00 52 52 52 00 52 52 52 52 52 52 00 52 52 00 52 52 52 00 00 52 00 52 52 00 52 52 52 52 00 52 00 52 52 00 00 52 52 52 52 00 52 00 52 52 52 00 52 52 00 52 00 00 d0 00 52 52 00 52 52 52 00 52 52 00 52 00 52 52 d0 52 00 00 00 52 00 52 d0 52 00 52 52 52 52 52 52 00 52 00 52 52 52 00 52 52 00 52 52 00 52 52 00 52 00 00 52 52 00 00 52 52 52 52 52 00 52 52 52 52 52 52 52 00 52 00 52 52 00 52 00 52 52 00 52 52 00 52 52 00 52 52 00 52 52 00 52 00 52 52 52 52 00 52 00 52 00 52 00 52 00 52 52 52 00 00 52 52 52 52 00 52 52 52 00 52 52 00 52 52 52 52 52 52 52 52 00 52 00 52 00 00 52 52 52 00 52 d0 52 52 52 00 52 52 00 00 52 52 d0 52 00 52 00 52 00 52 00 52 52 00 52 00 52 52 52 00 52 00 52 00 52 00 00 52 52 00 00 52 52 52 00 52 00 52 52 00 52 52 52 00 52 52 52 00 00 52 52 52 52 52 00 52 00 52 52 52 00 00 52 00 52 52 00 52 00 52 52 52 52 00 52 00 52 52 00 52 52 52 52 00 52 52 52 00 52 52 52 52 52 00 52 00 52 52 52 00 52 00 52 00 52 00 52 52 52 52 00 52 52 52 00 52 00 52 52 00 52 52 00 52 52 00 52 52 00 52 00 52 00 52 52 52 00 00 d0 00 00 00 52 00 52 52 52 00 00 52 00 52 00 52 52 00 52 52 00 52 00 52 52 52 52 00 52 00 52 00 52 52 00 52 52 00 52 52 d0 52 52 52 52 00 52 52 52 00 52 52 00 52 00 52
*/