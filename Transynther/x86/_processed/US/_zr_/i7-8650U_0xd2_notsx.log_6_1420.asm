.global s_prepare_buffers
s_prepare_buffers:
push %r12
push %r8
push %r9
push %rax
push %rbx
push %rcx
push %rdi
push %rdx
push %rsi
lea addresses_WC_ht+0xf26d, %rdx
nop
nop
nop
cmp %rbx, %rbx
mov (%rdx), %ax
nop
nop
nop
nop
nop
inc %r8
lea addresses_D_ht+0x139cd, %r9
nop
and $25756, %r12
movw $0x6162, (%r9)
nop
nop
add $47721, %rax
lea addresses_normal_ht+0x84bd, %rsi
lea addresses_WC_ht+0x83dd, %rdi
nop
nop
nop
nop
nop
cmp $62693, %r12
mov $45, %rcx
rep movsw
nop
nop
nop
add $33632, %r8
lea addresses_WC_ht+0x1b43d, %rsi
lea addresses_WT_ht+0x1980d, %rdi
nop
dec %rax
mov $8, %rcx
rep movsb
dec %rax
lea addresses_D_ht+0x1783d, %r9
nop
nop
nop
nop
nop
dec %rdx
mov $0x6162636465666768, %rbx
movq %rbx, %xmm4
movups %xmm4, (%r9)
nop
nop
inc %r8
lea addresses_A_ht+0x1763d, %rdi
nop
nop
cmp $64664, %rdx
mov $0x6162636465666768, %rsi
movq %rsi, %xmm4
movups %xmm4, (%rdi)
nop
nop
nop
nop
nop
sub $37611, %rbx
lea addresses_UC_ht+0x1c1dd, %rcx
nop
nop
nop
nop
nop
inc %r9
mov (%rcx), %rax
nop
nop
cmp $51895, %rbx
lea addresses_WT_ht+0x143f7, %r8
nop
cmp $58024, %rax
mov $0x6162636465666768, %rdi
movq %rdi, %xmm2
and $0xffffffffffffffc0, %r8
vmovaps %ymm2, (%r8)
nop
nop
nop
nop
and $39944, %rbx
pop %rsi
pop %rdx
pop %rdi
pop %rcx
pop %rbx
pop %rax
pop %r9
pop %r8
pop %r12
ret

    .global s_faulty_load
s_faulty_load:
push %r11
push %r13
push %r14
push %rax
push %rcx
push %rdi
push %rsi

// Load
lea addresses_D+0xa13d, %rdi
nop
nop
nop
nop
xor $27856, %rcx
movb (%rdi), %r13b
nop
nop
nop
nop
nop
inc %rcx

// Faulty Load
lea addresses_US+0x183d, %rax
nop
nop
nop
nop
nop
and %rdi, %rdi
mov (%rax), %r14
lea oracles, %r11
and $0xff, %r14
shlq $12, %r14
mov (%r11,%r14,1), %r14
pop %rsi
pop %rdi
pop %rcx
pop %rax
pop %r14
pop %r13
pop %r11
ret

/*
<gen_faulty_load>
[REF]
{'OP': 'LOAD', 'src': {'type': 'addresses_US', 'size': 8, 'AVXalign': False, 'NT': False, 'congruent': 0, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_D', 'size': 1, 'AVXalign': False, 'NT': False, 'congruent': 7, 'same': False}}
[Faulty Load]
{'OP': 'LOAD', 'src': {'type': 'addresses_US', 'size': 8, 'AVXalign': False, 'NT': False, 'congruent': 0, 'same': True}}
<gen_prepare_buffer>
{'OP': 'LOAD', 'src': {'type': 'addresses_WC_ht', 'size': 2, 'AVXalign': False, 'NT': False, 'congruent': 3, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_D_ht', 'size': 2, 'AVXalign': False, 'NT': False, 'congruent': 4, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_normal_ht', 'congruent': 5, 'same': False}, 'dst': {'type': 'addresses_WC_ht', 'congruent': 3, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_WC_ht', 'congruent': 8, 'same': False}, 'dst': {'type': 'addresses_WT_ht', 'congruent': 3, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_D_ht', 'size': 16, 'AVXalign': False, 'NT': False, 'congruent': 10, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_A_ht', 'size': 16, 'AVXalign': False, 'NT': False, 'congruent': 8, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_UC_ht', 'size': 8, 'AVXalign': False, 'NT': False, 'congruent': 5, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_WT_ht', 'size': 32, 'AVXalign': True, 'NT': False, 'congruent': 0, 'same': True}}
{'00': 6}
00 00 00 00 00 00
*/
