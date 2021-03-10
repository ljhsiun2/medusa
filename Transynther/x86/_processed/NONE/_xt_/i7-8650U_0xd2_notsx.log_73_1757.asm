.global s_prepare_buffers
s_prepare_buffers:
push %r11
push %r12
push %r14
push %r8
push %rbp
push %rcx
push %rdi
push %rsi
lea addresses_normal_ht+0x1a9be, %rsi
lea addresses_WC_ht+0x3dde, %rdi
nop
nop
nop
sub $60333, %r11
mov $107, %rcx
rep movsq
nop
nop
nop
nop
nop
add %rcx, %rcx
lea addresses_WC_ht+0x179be, %r11
nop
xor %rdi, %rdi
vmovups (%r11), %ymm5
vextracti128 $1, %ymm5, %xmm5
vpextrq $1, %xmm5, %r12
nop
nop
sub %r12, %r12
lea addresses_D_ht+0x1ad5e, %r12
nop
nop
nop
sub %rcx, %rcx
mov $0x6162636465666768, %r11
movq %r11, (%r12)
nop
nop
add $41466, %r11
lea addresses_A_ht+0x5dbe, %r14
dec %rbp
mov $0x6162636465666768, %r12
movq %r12, %xmm7
and $0xffffffffffffffc0, %r14
vmovaps %ymm7, (%r14)
add %r12, %r12
lea addresses_normal_ht+0x85be, %rcx
nop
add %rdi, %rdi
mov $0x6162636465666768, %r11
movq %r11, %xmm0
vmovups %ymm0, (%rcx)
nop
nop
nop
xor $12790, %r14
lea addresses_WC_ht+0x41be, %rsi
lea addresses_WC_ht+0x143a6, %rdi
nop
nop
nop
nop
sub $60249, %r8
mov $17, %rcx
rep movsb
nop
nop
nop
nop
cmp %r8, %r8
lea addresses_A_ht+0x139be, %rcx
nop
nop
nop
and $38384, %rdi
movb (%rcx), %r14b
nop
and %rbp, %rbp
lea addresses_D_ht+0x1a5be, %rsi
lea addresses_D_ht+0x34fe, %rdi
nop
nop
nop
nop
cmp $40561, %r14
mov $68, %rcx
rep movsw
cmp %r12, %r12
lea addresses_D_ht+0x188fe, %rsi
nop
nop
inc %r14
mov $0x6162636465666768, %rbp
movq %rbp, (%rsi)
xor %rsi, %rsi
lea addresses_normal_ht+0x1c9be, %rcx
nop
nop
nop
inc %r8
movl $0x61626364, (%rcx)
nop
nop
nop
nop
nop
sub %rbp, %rbp
lea addresses_WC_ht+0xd43e, %rcx
nop
nop
nop
nop
sub $11495, %r11
and $0xffffffffffffffc0, %rcx
movntdqa (%rcx), %xmm1
vpextrq $0, %xmm1, %r12
nop
nop
nop
and $2663, %rbp
pop %rsi
pop %rdi
pop %rcx
pop %rbp
pop %r8
pop %r14
pop %r12
pop %r11
ret

    .global s_faulty_load
s_faulty_load:
push %r11
push %r12
push %r14
push %r8
push %rbx
push %rdx
push %rsi

// Store
lea addresses_PSE+0x1b53e, %r12
nop
nop
nop
nop
inc %rdx
mov $0x5152535455565758, %rsi
movq %rsi, %xmm6
movups %xmm6, (%r12)
nop
nop
nop
sub $63566, %r8

// Store
lea addresses_US+0x1f96e, %r11
clflush (%r11)
nop
nop
nop
nop
nop
cmp %rbx, %rbx
movl $0x51525354, (%r11)
nop
sub $38427, %rsi

// Store
lea addresses_D+0x14684, %rdx
nop
and $16621, %rsi
mov $0x5152535455565758, %r12
movq %r12, %xmm7
vmovaps %ymm7, (%rdx)
nop
nop
and $41240, %rbx

// Store
lea addresses_D+0x16dee, %rdx
sub $64842, %r11
mov $0x5152535455565758, %r8
movq %r8, %xmm1
movups %xmm1, (%rdx)
nop
nop
and $50885, %rsi

// Store
lea addresses_RW+0x1a5be, %r8
inc %r14
movw $0x5152, (%r8)
nop
nop
and $62180, %rsi

// Load
lea addresses_D+0x1cdbe, %rbx
inc %r8
mov (%rbx), %r11
nop
nop
cmp %rbx, %rbx

// Faulty Load
lea addresses_normal+0xb1be, %r14
nop
nop
nop
nop
dec %r11
mov (%r14), %rbx
lea oracles, %rdx
and $0xff, %rbx
shlq $12, %rbx
mov (%rdx,%rbx,1), %rbx
pop %rsi
pop %rdx
pop %rbx
pop %r8
pop %r14
pop %r12
pop %r11
ret

/*
<gen_faulty_load>
[REF]
{'OP': 'LOAD', 'src': {'type': 'addresses_normal', 'size': 32, 'AVXalign': False, 'NT': False, 'congruent': 0, 'same': True}}
{'OP': 'STOR', 'dst': {'type': 'addresses_PSE', 'size': 16, 'AVXalign': False, 'NT': False, 'congruent': 7, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_US', 'size': 4, 'AVXalign': False, 'NT': False, 'congruent': 3, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_D', 'size': 32, 'AVXalign': True, 'NT': False, 'congruent': 1, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_D', 'size': 16, 'AVXalign': False, 'NT': False, 'congruent': 4, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_RW', 'size': 2, 'AVXalign': False, 'NT': False, 'congruent': 10, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_D', 'size': 8, 'AVXalign': False, 'NT': False, 'congruent': 9, 'same': False}}
[Faulty Load]
{'OP': 'LOAD', 'src': {'type': 'addresses_normal', 'size': 8, 'AVXalign': False, 'NT': False, 'congruent': 0, 'same': True}}
<gen_prepare_buffer>
{'OP': 'REPM', 'src': {'type': 'addresses_normal_ht', 'congruent': 11, 'same': False}, 'dst': {'type': 'addresses_WC_ht', 'congruent': 5, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_WC_ht', 'size': 32, 'AVXalign': False, 'NT': False, 'congruent': 10, 'same': True}}
{'OP': 'STOR', 'dst': {'type': 'addresses_D_ht', 'size': 8, 'AVXalign': False, 'NT': False, 'congruent': 5, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_A_ht', 'size': 32, 'AVXalign': True, 'NT': False, 'congruent': 10, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_normal_ht', 'size': 32, 'AVXalign': False, 'NT': False, 'congruent': 10, 'same': True}}
{'OP': 'REPM', 'src': {'type': 'addresses_WC_ht', 'congruent': 11, 'same': False}, 'dst': {'type': 'addresses_WC_ht', 'congruent': 3, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_A_ht', 'size': 1, 'AVXalign': False, 'NT': False, 'congruent': 11, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_D_ht', 'congruent': 10, 'same': False}, 'dst': {'type': 'addresses_D_ht', 'congruent': 3, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_D_ht', 'size': 8, 'AVXalign': False, 'NT': False, 'congruent': 5, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_normal_ht', 'size': 4, 'AVXalign': False, 'NT': False, 'congruent': 10, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_WC_ht', 'size': 16, 'AVXalign': False, 'NT': True, 'congruent': 3, 'same': False}}
{'34': 73}
34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34 34
*/
