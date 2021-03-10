.global s_prepare_buffers
s_prepare_buffers:
push %r14
push %r8
push %r9
push %rax
push %rbp
push %rcx
push %rdi
push %rsi
lea addresses_A_ht+0x59f5, %rdi
nop
nop
nop
and %r9, %r9
mov (%rdi), %si
nop
nop
nop
nop
nop
xor $7082, %rax
lea addresses_D_ht+0x154a5, %rsi
nop
nop
cmp $22413, %r14
mov (%rsi), %bp
nop
nop
sub $3269, %rax
lea addresses_D_ht+0xb735, %r9
cmp %r8, %r8
mov $0x6162636465666768, %r14
movq %r14, %xmm4
movups %xmm4, (%r9)
nop
nop
nop
nop
cmp $53294, %rsi
lea addresses_UC_ht+0x8535, %rsi
lea addresses_WC_ht+0xc4b5, %rdi
nop
nop
nop
nop
nop
add %r14, %r14
mov $106, %rcx
rep movsb
nop
nop
xor %rsi, %rsi
lea addresses_A_ht+0xb5b5, %rsi
lea addresses_D_ht+0x1f75, %rdi
sub $15043, %r14
mov $79, %rcx
rep movsb
nop
sub $23578, %r8
lea addresses_WC_ht+0x83c5, %rcx
nop
nop
nop
nop
sub %rbp, %rbp
mov (%rcx), %rsi
xor %rcx, %rcx
lea addresses_UC_ht+0x11ac3, %rsi
dec %r14
mov $0x6162636465666768, %rax
movq %rax, %xmm7
movups %xmm7, (%rsi)
nop
nop
nop
dec %rsi
pop %rsi
pop %rdi
pop %rcx
pop %rbp
pop %rax
pop %r9
pop %r8
pop %r14
ret

    .global s_faulty_load
s_faulty_load:
push %r10
push %r12
push %r13
push %r8
push %r9
push %rdi
push %rsi

// Store
mov $0xf35, %r13
dec %r9
mov $0x5152535455565758, %r8
movq %r8, %xmm1
vmovups %ymm1, (%r13)
nop
nop
nop
sub %r9, %r9

// Store
lea addresses_WC+0x10335, %rsi
nop
nop
nop
nop
xor $45773, %rdi
movw $0x5152, (%rsi)
nop
nop
nop
nop
nop
sub %rdi, %rdi

// Store
lea addresses_normal+0x12b35, %r8
clflush (%r8)
nop
nop
sub %r10, %r10
movw $0x5152, (%r8)
nop
and %rdi, %rdi

// Store
lea addresses_A+0x2899, %r10
nop
nop
nop
nop
nop
inc %r13
movb $0x51, (%r10)
nop
nop
nop
inc %rdi

// Store
mov $0x805, %r10
nop
nop
nop
nop
nop
sub %rdi, %rdi
movw $0x5152, (%r10)
nop
nop
sub $16073, %r10

// Store
mov $0x124b6d0000000e05, %r10
nop
nop
add %rsi, %rsi
movb $0x51, (%r10)
nop
nop
nop
nop
nop
xor %rdi, %rdi

// Store
lea addresses_A+0x1935, %r13
nop
nop
nop
nop
add $33442, %rdi
movb $0x51, (%r13)
nop
nop
nop
nop
nop
and $55143, %r9

// Store
lea addresses_RW+0x10335, %r8
nop
nop
nop
nop
and %r13, %r13
movw $0x5152, (%r8)
nop
dec %rdi

// Store
lea addresses_WC+0xfb35, %r12
nop
add $58641, %r8
movb $0x51, (%r12)
nop
nop
nop
nop
dec %r8

// Faulty Load
lea addresses_normal+0x12b35, %rdi
nop
nop
nop
nop
nop
sub $54561, %r13
movb (%rdi), %r10b
lea oracles, %r13
and $0xff, %r10
shlq $12, %r10
mov (%r13,%r10,1), %r10
pop %rsi
pop %rdi
pop %r9
pop %r8
pop %r13
pop %r12
pop %r10
ret

/*
<gen_faulty_load>
[REF]
{'OP': 'LOAD', 'src': {'type': 'addresses_normal', 'size': 1, 'AVXalign': False, 'NT': False, 'congruent': 0, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_P', 'size': 32, 'AVXalign': False, 'NT': False, 'congruent': 9, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_WC', 'size': 2, 'AVXalign': True, 'NT': False, 'congruent': 11, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_normal', 'size': 2, 'AVXalign': False, 'NT': False, 'congruent': 0, 'same': True}}
{'OP': 'STOR', 'dst': {'type': 'addresses_A', 'size': 1, 'AVXalign': False, 'NT': True, 'congruent': 2, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_P', 'size': 2, 'AVXalign': False, 'NT': False, 'congruent': 4, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_NC', 'size': 1, 'AVXalign': False, 'NT': False, 'congruent': 2, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_A', 'size': 1, 'AVXalign': False, 'NT': False, 'congruent': 6, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_RW', 'size': 2, 'AVXalign': False, 'NT': False, 'congruent': 8, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_WC', 'size': 1, 'AVXalign': False, 'NT': False, 'congruent': 8, 'same': False}}
[Faulty Load]
{'OP': 'LOAD', 'src': {'type': 'addresses_normal', 'size': 1, 'AVXalign': False, 'NT': False, 'congruent': 0, 'same': True}}
<gen_prepare_buffer>
{'OP': 'LOAD', 'src': {'type': 'addresses_A_ht', 'size': 2, 'AVXalign': False, 'NT': False, 'congruent': 5, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_D_ht', 'size': 2, 'AVXalign': False, 'NT': False, 'congruent': 3, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_D_ht', 'size': 16, 'AVXalign': False, 'NT': False, 'congruent': 10, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_UC_ht', 'congruent': 8, 'same': False}, 'dst': {'type': 'addresses_WC_ht', 'congruent': 6, 'same': True}}
{'OP': 'REPM', 'src': {'type': 'addresses_A_ht', 'congruent': 7, 'same': False}, 'dst': {'type': 'addresses_D_ht', 'congruent': 3, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_WC_ht', 'size': 8, 'AVXalign': False, 'NT': False, 'congruent': 4, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_UC_ht', 'size': 16, 'AVXalign': False, 'NT': False, 'congruent': 1, 'same': False}}
{'52': 88}
52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52 52
*/
