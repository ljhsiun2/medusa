.global s_prepare_buffers
s_prepare_buffers:
push %r10
push %r13
push %r14
push %r15
push %rax
push %rbx
push %rcx
push %rdi
push %rdx
push %rsi
lea addresses_normal_ht+0x987c, %rdx
nop
nop
add $14846, %r10
mov (%rdx), %r14d
nop
and %r15, %r15
lea addresses_UC_ht+0x1830c, %rbx
nop
nop
nop
nop
inc %rax
movb $0x61, (%rbx)
nop
nop
nop
nop
nop
sub %rbx, %rbx
lea addresses_D_ht+0x11202, %rsi
lea addresses_WC_ht+0x14dcc, %rdi
clflush (%rdi)
nop
nop
nop
nop
nop
add %rdx, %rdx
mov $13, %rcx
rep movsq
nop
nop
nop
nop
and %rdx, %rdx
lea addresses_WT_ht+0xf16c, %rsi
lea addresses_D_ht+0xa61c, %rdi
clflush (%rdi)
nop
nop
nop
cmp %r15, %r15
mov $41, %rcx
rep movsl
nop
nop
nop
inc %r10
lea addresses_normal_ht+0x1a3cc, %r13
nop
nop
sub %r14, %r14
mov (%r13), %edx
nop
nop
nop
nop
dec %rcx
lea addresses_WT_ht+0xd5cc, %rcx
nop
nop
nop
inc %r10
mov (%rcx), %r14
nop
nop
add %r14, %r14
lea addresses_WC_ht+0xea0c, %r13
nop
nop
nop
nop
nop
and %r14, %r14
movw $0x6162, (%r13)
nop
nop
nop
nop
nop
xor %r13, %r13
lea addresses_D_ht+0x1a1cc, %rbx
nop
nop
nop
lfence
movl $0x61626364, (%rbx)
nop
sub %rax, %rax
lea addresses_WT_ht+0xa894, %rcx
nop
nop
nop
nop
nop
xor $13369, %r15
mov $0x6162636465666768, %r14
movq %r14, (%rcx)
nop
add $15912, %rcx
lea addresses_UC_ht+0x15d2, %rsi
lea addresses_normal_ht+0x1ea0c, %rdi
nop
nop
nop
nop
sub %r13, %r13
mov $50, %rcx
rep movsq
nop
nop
nop
nop
sub %r14, %r14
lea addresses_normal_ht+0x151cc, %rsi
lea addresses_UC_ht+0xf04c, %rdi
nop
nop
nop
nop
nop
and $48260, %r10
mov $59, %rcx
rep movsl
nop
nop
add %rax, %rax
lea addresses_WT_ht+0xd1cc, %rsi
lea addresses_A_ht+0x171cc, %rdi
clflush (%rdi)
nop
nop
nop
nop
nop
dec %r10
mov $89, %rcx
rep movsl
nop
sub $52697, %rdi
pop %rsi
pop %rdx
pop %rdi
pop %rcx
pop %rbx
pop %rax
pop %r15
pop %r14
pop %r13
pop %r10
ret

    .global s_faulty_load
s_faulty_load:
push %r11
push %r12
push %r14
push %rbp
push %rcx
push %rdi
push %rsi

// REPMOV
lea addresses_UC+0x1717c, %rsi
lea addresses_UC+0x1d4cc, %rdi
nop
and %r14, %r14
mov $8, %rcx
rep movsl
cmp %rbp, %rbp

// Store
lea addresses_normal+0x18db2, %rcx
nop
nop
cmp $38850, %r11
mov $0x5152535455565758, %r14
movq %r14, %xmm6
vmovups %ymm6, (%rcx)
nop
nop
xor $5250, %r12

// Faulty Load
lea addresses_RW+0x1a9cc, %r14
nop
add $459, %r11
vmovups (%r14), %ymm2
vextracti128 $0, %ymm2, %xmm2
vpextrq $0, %xmm2, %rsi
lea oracles, %rcx
and $0xff, %rsi
shlq $12, %rsi
mov (%rcx,%rsi,1), %rsi
pop %rsi
pop %rdi
pop %rcx
pop %rbp
pop %r14
pop %r12
pop %r11
ret

/*
<gen_faulty_load>
[REF]
{'OP': 'LOAD', 'src': {'type': 'addresses_RW', 'size': 4, 'AVXalign': False, 'NT': False, 'congruent': 0, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_UC', 'congruent': 4, 'same': False}, 'dst': {'type': 'addresses_UC', 'congruent': 7, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_normal', 'size': 32, 'AVXalign': False, 'NT': False, 'congruent': 1, 'same': False}}
[Faulty Load]
{'OP': 'LOAD', 'src': {'type': 'addresses_RW', 'size': 32, 'AVXalign': False, 'NT': False, 'congruent': 0, 'same': True}}
<gen_prepare_buffer>
{'OP': 'LOAD', 'src': {'type': 'addresses_normal_ht', 'size': 4, 'AVXalign': False, 'NT': False, 'congruent': 2, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_UC_ht', 'size': 1, 'AVXalign': False, 'NT': False, 'congruent': 5, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_D_ht', 'congruent': 0, 'same': False}, 'dst': {'type': 'addresses_WC_ht', 'congruent': 10, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_WT_ht', 'congruent': 5, 'same': False}, 'dst': {'type': 'addresses_D_ht', 'congruent': 4, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_normal_ht', 'size': 4, 'AVXalign': False, 'NT': False, 'congruent': 9, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_WT_ht', 'size': 8, 'AVXalign': False, 'NT': False, 'congruent': 10, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_WC_ht', 'size': 2, 'AVXalign': True, 'NT': False, 'congruent': 6, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_D_ht', 'size': 4, 'AVXalign': False, 'NT': False, 'congruent': 11, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_WT_ht', 'size': 8, 'AVXalign': False, 'NT': False, 'congruent': 3, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_UC_ht', 'congruent': 1, 'same': False}, 'dst': {'type': 'addresses_normal_ht', 'congruent': 3, 'same': True}}
{'OP': 'REPM', 'src': {'type': 'addresses_normal_ht', 'congruent': 10, 'same': False}, 'dst': {'type': 'addresses_UC_ht', 'congruent': 6, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_WT_ht', 'congruent': 11, 'same': False}, 'dst': {'type': 'addresses_A_ht', 'congruent': 9, 'same': False}}
{'32': 15732}
32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32
*/
