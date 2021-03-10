.global s_prepare_buffers
s_prepare_buffers:
push %r10
push %rax
push %rbp
push %rbx
push %rcx
push %rdi
push %rsi
lea addresses_D_ht+0x96ae, %rsi
lea addresses_normal_ht+0x78de, %rdi
dec %rbp
mov $21, %rcx
rep movsw
sub %rbx, %rbx
lea addresses_A_ht+0x109ae, %r10
nop
nop
nop
cmp %rax, %rax
mov $0x6162636465666768, %rbx
movq %rbx, %xmm2
vmovups %ymm2, (%r10)
nop
nop
nop
cmp $20477, %rax
lea addresses_normal_ht+0x15c5e, %rbx
nop
nop
nop
nop
nop
inc %rsi
movl $0x61626364, (%rbx)
cmp $63446, %rcx
lea addresses_WC_ht+0x18c6e, %rbx
nop
nop
dec %rax
mov $0x6162636465666768, %rdi
movq %rdi, (%rbx)
nop
nop
nop
sub %rcx, %rcx
lea addresses_normal_ht+0x1a7ae, %rbx
nop
nop
nop
inc %rbp
mov (%rbx), %di
nop
nop
nop
nop
nop
add %rax, %rax
pop %rsi
pop %rdi
pop %rcx
pop %rbx
pop %rbp
pop %rax
pop %r10
ret

    .global s_faulty_load
s_faulty_load:
push %r10
push %r12
push %r15
push %r8
push %r9
push %rax
push %rcx

// Store
lea addresses_UC+0x1800e, %r10
nop
and %r8, %r8
mov $0x5152535455565758, %r15
movq %r15, %xmm0
movups %xmm0, (%r10)
nop
nop
nop
nop
dec %rcx

// Store
lea addresses_RW+0x133ae, %rax
xor %r12, %r12
mov $0x5152535455565758, %r8
movq %r8, %xmm7
movups %xmm7, (%rax)
cmp %rax, %rax

// Store
mov $0x6ae, %r12
clflush (%r12)
nop
nop
nop
nop
nop
cmp %rax, %rax
mov $0x5152535455565758, %rcx
movq %rcx, (%r12)
nop
nop
nop
nop
and %r8, %r8

// Store
mov $0x20acee0000000eae, %r12
nop
nop
nop
nop
sub %rcx, %rcx
mov $0x5152535455565758, %r15
movq %r15, %xmm0
movups %xmm0, (%r12)
nop
nop
nop
sub %r10, %r10

// Faulty Load
mov $0xbae, %r8
add %r10, %r10
vmovntdqa (%r8), %ymm4
vextracti128 $0, %ymm4, %xmm4
vpextrq $0, %xmm4, %rax
lea oracles, %r10
and $0xff, %rax
shlq $12, %rax
mov (%r10,%rax,1), %rax
pop %rcx
pop %rax
pop %r9
pop %r8
pop %r15
pop %r12
pop %r10
ret

/*
<gen_faulty_load>
[REF]
{'OP': 'LOAD', 'src': {'type': 'addresses_P', 'size': 4, 'AVXalign': False, 'NT': True, 'congruent': 0, 'same': True}}
{'OP': 'STOR', 'dst': {'type': 'addresses_UC', 'size': 16, 'AVXalign': False, 'NT': False, 'congruent': 3, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_RW', 'size': 16, 'AVXalign': False, 'NT': False, 'congruent': 11, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_P', 'size': 8, 'AVXalign': False, 'NT': False, 'congruent': 4, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_NC', 'size': 16, 'AVXalign': False, 'NT': False, 'congruent': 4, 'same': False}}
[Faulty Load]
{'OP': 'LOAD', 'src': {'type': 'addresses_P', 'size': 32, 'AVXalign': False, 'NT': True, 'congruent': 0, 'same': True}}
<gen_prepare_buffer>
{'OP': 'REPM', 'src': {'type': 'addresses_D_ht', 'congruent': 7, 'same': False}, 'dst': {'type': 'addresses_normal_ht', 'congruent': 1, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_A_ht', 'size': 32, 'AVXalign': False, 'NT': False, 'congruent': 9, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_normal_ht', 'size': 4, 'AVXalign': False, 'NT': False, 'congruent': 2, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_WC_ht', 'size': 8, 'AVXalign': False, 'NT': False, 'congruent': 6, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_normal_ht', 'size': 2, 'AVXalign': False, 'NT': False, 'congruent': 8, 'same': True}}
{'00': 176}
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
*/
