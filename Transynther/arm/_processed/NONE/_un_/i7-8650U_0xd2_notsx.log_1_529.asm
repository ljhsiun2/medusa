.global s_prepare_buffers
s_prepare_buffers:
push %r10
push %r13
push %r15
push %r9
push %rax
push %rcx
push %rdi
push %rsi
lea addresses_D_ht+0x51cc, %rdi
nop
nop
nop
nop
nop
sub %rcx, %rcx
movb $0x61, (%rdi)
nop
and %rax, %rax
lea addresses_D_ht+0x52b0, %r15
nop
nop
add $27355, %r10
movups (%r15), %xmm5
vpextrq $0, %xmm5, %r9
nop
xor %r15, %r15
lea addresses_A_ht+0xb24, %rsi
lea addresses_WC_ht+0x16e14, %rdi
nop
nop
add $39263, %rax
mov $83, %rcx
rep movsl
and %r13, %r13
lea addresses_D_ht+0x75cc, %r15
nop
nop
nop
nop
nop
and $60203, %rsi
mov $0x6162636465666768, %r9
movq %r9, (%r15)
nop
nop
nop
nop
nop
add %rax, %rax
lea addresses_UC_ht+0x1409c, %r15
nop
and %rsi, %rsi
movb (%r15), %al
nop
nop
nop
add %r15, %r15
lea addresses_A_ht+0x1104, %rsi
clflush (%rsi)
nop
xor %r10, %r10
movl $0x61626364, (%rsi)
nop
nop
nop
nop
sub %rsi, %rsi
lea addresses_D_ht+0x12cc, %r9
clflush (%r9)
and $22321, %rax
mov (%r9), %ecx
nop
nop
nop
nop
xor $42574, %r15
lea addresses_WT_ht+0x17ff4, %r10
nop
nop
nop
inc %r15
mov $0x6162636465666768, %r13
movq %r13, (%r10)
nop
inc %rcx
lea addresses_normal_ht+0xc434, %rcx
nop
nop
nop
xor $7193, %r9
mov $0x6162636465666768, %rdi
movq %rdi, %xmm1
vmovups %ymm1, (%rcx)
sub %rdi, %rdi
lea addresses_A_ht+0xecc5, %rsi
lea addresses_UC_ht+0xe7cc, %rdi
nop
xor $36712, %rax
mov $3, %rcx
rep movsw
nop
nop
nop
inc %r10
lea addresses_WC_ht+0x1c94c, %rdi
inc %rcx
mov $0x6162636465666768, %r9
movq %r9, %xmm0
vmovups %ymm0, (%rdi)
nop
nop
nop
nop
inc %rdi
lea addresses_D_ht+0xa14c, %rcx
nop
nop
nop
nop
and $56691, %r15
movb (%rcx), %al
nop
cmp %rdi, %rdi
lea addresses_UC_ht+0x18c6c, %rsi
nop
nop
and %rax, %rax
mov $0x6162636465666768, %r9
movq %r9, %xmm0
vmovups %ymm0, (%rsi)
add %rcx, %rcx
lea addresses_normal_ht+0x1842c, %rsi
lea addresses_WT_ht+0x1ad06, %rdi
clflush (%rdi)
nop
nop
nop
nop
nop
add $37016, %r10
mov $57, %rcx
rep movsq
nop
nop
nop
and $20681, %rcx
pop %rsi
pop %rdi
pop %rcx
pop %rax
pop %r9
pop %r15
pop %r13
pop %r10
ret

    .global s_faulty_load
s_faulty_load:
push %r10
push %r13
push %r8
push %rbx
push %rcx
push %rdi
push %rsi

// REPMOV
mov $0x2cc, %rsi
lea addresses_normal+0xe5cc, %rdi
clflush (%rdi)
cmp $42999, %rbx
mov $68, %rcx
rep movsw
nop
nop
sub $65534, %rdi

// Faulty Load
lea addresses_A+0x95cc, %r8
and $43292, %rbx
mov (%r8), %r10w
lea oracles, %rsi
and $0xff, %r10
shlq $12, %r10
mov (%rsi,%r10,1), %r10
pop %rsi
pop %rdi
pop %rcx
pop %rbx
pop %r8
pop %r13
pop %r10
ret

/*
<gen_faulty_load>
[REF]
{'OP': 'LOAD', 'src': {'type': 'addresses_A', 'size': 16, 'AVXalign': False, 'NT': False, 'congruent': 0, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_P', 'congruent': 8, 'same': False}, 'dst': {'type': 'addresses_normal', 'congruent': 10, 'same': False}}
[Faulty Load]
{'OP': 'LOAD', 'src': {'type': 'addresses_A', 'size': 2, 'AVXalign': False, 'NT': False, 'congruent': 0, 'same': True}}
<gen_prepare_buffer>
{'OP': 'STOR', 'dst': {'type': 'addresses_D_ht', 'size': 1, 'AVXalign': False, 'NT': False, 'congruent': 5, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_D_ht', 'size': 16, 'AVXalign': False, 'NT': False, 'congruent': 2, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_A_ht', 'congruent': 1, 'same': False}, 'dst': {'type': 'addresses_WC_ht', 'congruent': 2, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_D_ht', 'size': 8, 'AVXalign': False, 'NT': False, 'congruent': 10, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_UC_ht', 'size': 1, 'AVXalign': False, 'NT': True, 'congruent': 2, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_A_ht', 'size': 4, 'AVXalign': False, 'NT': False, 'congruent': 3, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_D_ht', 'size': 4, 'AVXalign': False, 'NT': False, 'congruent': 7, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_WT_ht', 'size': 8, 'AVXalign': False, 'NT': False, 'congruent': 0, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_normal_ht', 'size': 32, 'AVXalign': False, 'NT': False, 'congruent': 3, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_A_ht', 'congruent': 0, 'same': False}, 'dst': {'type': 'addresses_UC_ht', 'congruent': 9, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_WC_ht', 'size': 32, 'AVXalign': False, 'NT': False, 'congruent': 5, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_D_ht', 'size': 1, 'AVXalign': False, 'NT': False, 'congruent': 6, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_UC_ht', 'size': 32, 'AVXalign': False, 'NT': False, 'congruent': 5, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_normal_ht', 'congruent': 5, 'same': False}, 'dst': {'type': 'addresses_WT_ht', 'congruent': 1, 'same': False}}
{'24': 1}
24
*/
