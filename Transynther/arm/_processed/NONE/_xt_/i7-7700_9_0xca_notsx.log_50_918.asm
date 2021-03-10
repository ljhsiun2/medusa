.global s_prepare_buffers
s_prepare_buffers:
push %r10
push %r9
push %rax
push %rcx
push %rdi
push %rsi
lea addresses_normal_ht+0x1590a, %rcx
nop
nop
and $23579, %r10
mov (%rcx), %si
nop
nop
nop
dec %rdi
lea addresses_A_ht+0xec6a, %rcx
nop
add $53292, %rax
movb (%rcx), %r9b
nop
cmp %rax, %rax
pop %rsi
pop %rdi
pop %rcx
pop %rax
pop %r9
pop %r10
ret

    .global s_faulty_load
s_faulty_load:
push %r12
push %r13
push %r14
push %r15
push %rbp
push %rcx
push %rdi

// Store
lea addresses_A+0xba6a, %rdi
nop
nop
nop
nop
nop
cmp $46768, %r13
movl $0x51525354, (%rdi)

// Exception!!!
nop
nop
mov (0), %r13
nop
cmp %rdi, %rdi

// Store
lea addresses_normal+0x1aa6a, %r14
nop
nop
inc %rbp
mov $0x5152535455565758, %r12
movq %r12, %xmm6
movups %xmm6, (%r14)
nop
nop
nop
inc %rbp

// Load
lea addresses_RW+0x5c6a, %r14
nop
and $4177, %rcx
mov (%r14), %r13

// Exception!!!
nop
nop
nop
nop
mov (0), %r14
nop
nop
xor %r15, %r15

// Store
lea addresses_WC+0x660e, %r13
nop
nop
add %r15, %r15
movb $0x51, (%r13)
nop
nop
nop
nop
nop
and %r14, %r14

// Load
lea addresses_normal+0x32aa, %r15
clflush (%r15)
nop
nop
nop
sub %rcx, %rcx
vmovups (%r15), %ymm2
vextracti128 $1, %ymm2, %xmm2
vpextrq $1, %xmm2, %rdi
add $31248, %r12

// Faulty Load
lea addresses_A+0xba6a, %rcx
dec %r15
movups (%rcx), %xmm3
vpextrq $1, %xmm3, %r13
lea oracles, %r12
and $0xff, %r13
shlq $12, %r13
mov (%r12,%r13,1), %r13
pop %rdi
pop %rcx
pop %rbp
pop %r15
pop %r14
pop %r13
pop %r12
ret

/*
<gen_faulty_load>
[REF]
{'src': {'NT': False, 'AVXalign': False, 'size': 8, 'congruent': 0, 'same': False, 'type': 'addresses_A'}, 'OP': 'LOAD'}
{'dst': {'NT': False, 'AVXalign': False, 'size': 4, 'congruent': 0, 'same': True, 'type': 'addresses_A'}, 'OP': 'STOR'}
{'dst': {'NT': False, 'AVXalign': False, 'size': 16, 'congruent': 11, 'same': False, 'type': 'addresses_normal'}, 'OP': 'STOR'}
{'src': {'NT': False, 'AVXalign': False, 'size': 8, 'congruent': 9, 'same': False, 'type': 'addresses_RW'}, 'OP': 'LOAD'}
{'dst': {'NT': False, 'AVXalign': False, 'size': 1, 'congruent': 0, 'same': False, 'type': 'addresses_WC'}, 'OP': 'STOR'}
{'src': {'NT': False, 'AVXalign': False, 'size': 32, 'congruent': 6, 'same': False, 'type': 'addresses_normal'}, 'OP': 'LOAD'}
[Faulty Load]
{'src': {'NT': False, 'AVXalign': False, 'size': 16, 'congruent': 0, 'same': True, 'type': 'addresses_A'}, 'OP': 'LOAD'}
<gen_prepare_buffer>
{'src': {'NT': False, 'AVXalign': False, 'size': 2, 'congruent': 5, 'same': False, 'type': 'addresses_normal_ht'}, 'OP': 'LOAD'}
{'src': {'NT': False, 'AVXalign': False, 'size': 1, 'congruent': 9, 'same': False, 'type': 'addresses_A_ht'}, 'OP': 'LOAD'}
{'35': 50}
35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35
*/
