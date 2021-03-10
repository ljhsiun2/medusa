.global s_prepare_buffers
s_prepare_buffers:
push %r12
push %r14
push %r15
push %rax
push %rbx
push %rcx
push %rdi
push %rsi
lea addresses_WT_ht+0x11bd6, %rcx
nop
add %r14, %r14
movb $0x61, (%rcx)
nop
nop
nop
nop
nop
add %rax, %rax
lea addresses_normal_ht+0x12376, %rbx
nop
nop
nop
nop
cmp $41002, %rsi
movb (%rbx), %r14b
cmp %rcx, %rcx
lea addresses_A_ht+0xdab6, %rsi
lea addresses_D_ht+0x10ab6, %rdi
nop
nop
nop
nop
nop
xor %r15, %r15
mov $34, %rcx
rep movsw
nop
nop
nop
and $16047, %rax
lea addresses_UC_ht+0x92b6, %rdi
nop
nop
nop
nop
nop
and $32627, %r12
mov $0x6162636465666768, %rbx
movq %rbx, %xmm3
movups %xmm3, (%rdi)
nop
nop
nop
nop
dec %r15
lea addresses_WC_ht+0x15db6, %rax
nop
nop
nop
nop
nop
cmp %rcx, %rcx
movl $0x61626364, (%rax)
nop
nop
sub %rcx, %rcx
lea addresses_WT_ht+0xeeb6, %rsi
lea addresses_D_ht+0xb6, %rdi
sub $16660, %rax
mov $39, %rcx
rep movsl
nop
nop
nop
nop
nop
cmp %rsi, %rsi
lea addresses_D_ht+0x58b6, %rcx
nop
cmp %rax, %rax
mov (%rcx), %di
nop
nop
nop
xor $22777, %r15
lea addresses_WT_ht+0xeeb6, %r14
nop
nop
nop
nop
nop
xor $26418, %rbx
movw $0x6162, (%r14)
nop
nop
nop
inc %r15
lea addresses_normal_ht+0xaeb6, %rbx
and %r15, %r15
movups (%rbx), %xmm7
vpextrq $1, %xmm7, %rax
nop
and $3034, %r12
lea addresses_UC_ht+0x18f32, %rbx
clflush (%rbx)
nop
nop
nop
nop
xor $38900, %r15
movb $0x61, (%rbx)
add %r15, %r15
pop %rsi
pop %rdi
pop %rcx
pop %rbx
pop %rax
pop %r15
pop %r14
pop %r12
ret

    .global s_faulty_load
s_faulty_load:
push %r15
push %r9
push %rax
push %rbx
push %rcx
push %rdi
push %rsi

// REPMOV
lea addresses_UC+0x81d6, %rsi
lea addresses_UC+0xbd96, %rdi
nop
nop
cmp $2646, %r9
mov $30, %rcx
rep movsl
nop
inc %rbx

// Faulty Load
lea addresses_RW+0x1beb6, %rbx
nop
nop
nop
inc %r15
vmovups (%rbx), %ymm0
vextracti128 $0, %ymm0, %xmm0
vpextrq $1, %xmm0, %rcx
lea oracles, %rdi
and $0xff, %rcx
shlq $12, %rcx
mov (%rdi,%rcx,1), %rcx
pop %rsi
pop %rdi
pop %rcx
pop %rbx
pop %rax
pop %r9
pop %r15
ret

/*
<gen_faulty_load>
[REF]
{'OP': 'LOAD', 'src': {'type': 'addresses_RW', 'AVXalign': False, 'congruent': 0, 'size': 4, 'same': False, 'NT': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_UC', 'congruent': 5, 'same': False}, 'dst': {'type': 'addresses_UC', 'congruent': 4, 'same': False}}
[Faulty Load]
{'OP': 'LOAD', 'src': {'type': 'addresses_RW', 'AVXalign': False, 'congruent': 0, 'size': 32, 'same': True, 'NT': False}}
<gen_prepare_buffer>
{'OP': 'STOR', 'dst': {'type': 'addresses_WT_ht', 'AVXalign': False, 'congruent': 1, 'size': 1, 'same': False, 'NT': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_normal_ht', 'AVXalign': False, 'congruent': 5, 'size': 1, 'same': False, 'NT': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_A_ht', 'congruent': 9, 'same': False}, 'dst': {'type': 'addresses_D_ht', 'congruent': 10, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_UC_ht', 'AVXalign': False, 'congruent': 10, 'size': 16, 'same': False, 'NT': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_WC_ht', 'AVXalign': False, 'congruent': 8, 'size': 4, 'same': False, 'NT': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_WT_ht', 'congruent': 11, 'same': False}, 'dst': {'type': 'addresses_D_ht', 'congruent': 8, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_D_ht', 'AVXalign': False, 'congruent': 7, 'size': 2, 'same': False, 'NT': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_WT_ht', 'AVXalign': False, 'congruent': 11, 'size': 2, 'same': True, 'NT': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_normal_ht', 'AVXalign': False, 'congruent': 11, 'size': 16, 'same': False, 'NT': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_UC_ht', 'AVXalign': False, 'congruent': 2, 'size': 1, 'same': False, 'NT': False}}
{'32': 1}
32
*/
