.global s_prepare_buffers
s_prepare_buffers:
push %r10
push %r11
push %r12
push %r15
push %rax
push %rcx
push %rdi
push %rsi
lea addresses_WT_ht+0x953e, %r10
nop
nop
sub $26678, %r15
mov $0x6162636465666768, %r11
movq %r11, %xmm3
vmovups %ymm3, (%r10)
nop
nop
nop
nop
xor %rax, %rax
lea addresses_WC_ht+0x5ff6, %rsi
lea addresses_WT_ht+0x1eb48, %rdi
clflush (%rsi)
nop
nop
nop
xor $43951, %r12
mov $7, %rcx
rep movsl
nop
nop
nop
xor $56217, %r12
lea addresses_D_ht+0x142fe, %rsi
lea addresses_normal_ht+0x172b4, %rdi
nop
nop
nop
add %r15, %r15
mov $98, %rcx
rep movsl
nop
nop
nop
cmp $57394, %rcx
lea addresses_UC_ht+0x1d0be, %r11
nop
nop
nop
nop
nop
sub %rcx, %rcx
movb (%r11), %r12b
nop
nop
nop
nop
nop
xor $35609, %rax
lea addresses_WT_ht+0x167be, %rsi
lea addresses_D_ht+0x250e, %rdi
clflush (%rdi)
nop
nop
nop
nop
dec %r15
mov $28, %rcx
rep movsl
nop
nop
nop
and $36614, %r12
lea addresses_UC_ht+0x18be, %rsi
and %r11, %r11
movl $0x61626364, (%rsi)
nop
nop
nop
nop
add %r10, %r10
lea addresses_normal_ht+0x161fe, %rsi
lea addresses_A_ht+0x13d92, %rdi
nop
nop
sub %r11, %r11
mov $0, %rcx
rep movsb
cmp $64834, %r10
lea addresses_WT_ht+0xc53e, %r11
nop
nop
cmp %rax, %rax
mov (%r11), %r10
nop
and %r11, %r11
lea addresses_WC_ht+0x1cea2, %rsi
lea addresses_D_ht+0x1d67e, %rdi
nop
nop
nop
and %r12, %r12
mov $127, %rcx
rep movsb
nop
nop
nop
add $44188, %r15
lea addresses_WC_ht+0x1dcbe, %rsi
lea addresses_A_ht+0x7497, %rdi
nop
nop
cmp $65218, %rax
mov $29, %rcx
rep movsw
nop
nop
nop
nop
nop
add %r11, %r11
lea addresses_D_ht+0x7e76, %rsi
lea addresses_A_ht+0xe4be, %rdi
xor %r11, %r11
mov $31, %rcx
rep movsl
nop
nop
nop
nop
nop
xor $20746, %rsi
lea addresses_A_ht+0x56ae, %rsi
lea addresses_WC_ht+0x120be, %rdi
nop
nop
nop
nop
nop
add $22317, %r15
mov $73, %rcx
rep movsb
nop
nop
nop
nop
dec %rax
lea addresses_WT_ht+0x116be, %rsi
lea addresses_D_ht+0x1e4be, %rdi
nop
nop
xor $40390, %rax
mov $58, %rcx
rep movsl
sub $41579, %r12
lea addresses_A_ht+0x1e63e, %rcx
nop
dec %rdi
mov $0x6162636465666768, %rax
movq %rax, %xmm3
movups %xmm3, (%rcx)
nop
nop
cmp %r12, %r12
lea addresses_WT_ht+0x13cbe, %r11
clflush (%r11)
nop
nop
nop
nop
cmp %rcx, %rcx
vmovups (%r11), %ymm6
vextracti128 $1, %ymm6, %xmm6
vpextrq $1, %xmm6, %rdi
nop
nop
nop
nop
xor $58233, %rcx
pop %rsi
pop %rdi
pop %rcx
pop %rax
pop %r15
pop %r12
pop %r11
pop %r10
ret

    .global s_faulty_load
s_faulty_load:
push %r14
push %r8
push %r9
push %rbp
push %rcx
push %rdx

// Store
lea addresses_UC+0x146be, %rdx
nop
sub $58188, %r8
mov $0x5152535455565758, %r9
movq %r9, (%rdx)

// Exception!!!
nop
nop
nop
nop
nop
mov (0), %r9
nop
nop
xor %rcx, %rcx

// Store
mov $0x670b0700000008be, %r14
nop
and $5599, %rbp
mov $0x5152535455565758, %r8
movq %r8, (%r14)
nop
nop
nop
nop
nop
cmp $41208, %r9

// Faulty Load
lea addresses_US+0xe4be, %rcx
nop
xor %rbp, %rbp
mov (%rcx), %r9
lea oracles, %r14
and $0xff, %r9
shlq $12, %r9
mov (%r14,%r9,1), %r9
pop %rdx
pop %rcx
pop %rbp
pop %r9
pop %r8
pop %r14
ret

/*
<gen_faulty_load>
[REF]
{'src': {'type': 'addresses_US', 'same': False, 'size': 1, 'congruent': 0, 'NT': False, 'AVXalign': False}, 'OP': 'LOAD'}
{'dst': {'type': 'addresses_UC', 'same': False, 'size': 8, 'congruent': 8, 'NT': False, 'AVXalign': False}, 'OP': 'STOR'}
{'dst': {'type': 'addresses_NC', 'same': False, 'size': 8, 'congruent': 8, 'NT': False, 'AVXalign': False}, 'OP': 'STOR'}
[Faulty Load]
{'src': {'type': 'addresses_US', 'same': True, 'size': 8, 'congruent': 0, 'NT': False, 'AVXalign': False}, 'OP': 'LOAD'}
<gen_prepare_buffer>
{'dst': {'type': 'addresses_WT_ht', 'same': False, 'size': 32, 'congruent': 7, 'NT': False, 'AVXalign': False}, 'OP': 'STOR'}
{'src': {'type': 'addresses_WC_ht', 'congruent': 3, 'same': False}, 'dst': {'type': 'addresses_WT_ht', 'congruent': 0, 'same': False}, 'OP': 'REPM'}
{'src': {'type': 'addresses_D_ht', 'congruent': 5, 'same': False}, 'dst': {'type': 'addresses_normal_ht', 'congruent': 1, 'same': False}, 'OP': 'REPM'}
{'src': {'type': 'addresses_UC_ht', 'same': False, 'size': 1, 'congruent': 6, 'NT': False, 'AVXalign': False}, 'OP': 'LOAD'}
{'src': {'type': 'addresses_WT_ht', 'congruent': 6, 'same': False}, 'dst': {'type': 'addresses_D_ht', 'congruent': 1, 'same': False}, 'OP': 'REPM'}
{'dst': {'type': 'addresses_UC_ht', 'same': False, 'size': 4, 'congruent': 10, 'NT': False, 'AVXalign': False}, 'OP': 'STOR'}
{'src': {'type': 'addresses_normal_ht', 'congruent': 6, 'same': False}, 'dst': {'type': 'addresses_A_ht', 'congruent': 1, 'same': True}, 'OP': 'REPM'}
{'src': {'type': 'addresses_WT_ht', 'same': False, 'size': 8, 'congruent': 4, 'NT': False, 'AVXalign': True}, 'OP': 'LOAD'}
{'src': {'type': 'addresses_WC_ht', 'congruent': 2, 'same': False}, 'dst': {'type': 'addresses_D_ht', 'congruent': 6, 'same': False}, 'OP': 'REPM'}
{'src': {'type': 'addresses_WC_ht', 'congruent': 10, 'same': False}, 'dst': {'type': 'addresses_A_ht', 'congruent': 0, 'same': False}, 'OP': 'REPM'}
{'src': {'type': 'addresses_D_ht', 'congruent': 3, 'same': False}, 'dst': {'type': 'addresses_A_ht', 'congruent': 11, 'same': False}, 'OP': 'REPM'}
{'src': {'type': 'addresses_A_ht', 'congruent': 4, 'same': False}, 'dst': {'type': 'addresses_WC_ht', 'congruent': 7, 'same': False}, 'OP': 'REPM'}
{'src': {'type': 'addresses_WT_ht', 'congruent': 8, 'same': False}, 'dst': {'type': 'addresses_D_ht', 'congruent': 9, 'same': False}, 'OP': 'REPM'}
{'dst': {'type': 'addresses_A_ht', 'same': False, 'size': 16, 'congruent': 7, 'NT': False, 'AVXalign': False}, 'OP': 'STOR'}
{'src': {'type': 'addresses_WT_ht', 'same': True, 'size': 32, 'congruent': 11, 'NT': False, 'AVXalign': False}, 'OP': 'LOAD'}
{'e3': 365, 'ff': 6, '28': 85, '1a': 1, '45': 30, '67': 882, '50': 2, 'd0': 21, '3c': 1, '47': 6, '48': 10, '80': 49, '49': 63, '46': 49, '00': 20251, 'a0': 6, '2e': 1, 'c0': 1}
00 00 00 00 00 00 00 00 00 e3 00 00 00 00 e3 00 00 80 00 00 00 00 e3 49 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 67 00 00 00 67 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 e3 00 00 00 00 00 00 00 00 00 00 00 00 49 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 67 00 00 00 e3 00 67 e3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 46 00 00 00 00 00 00 00 67 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 e3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 e3 00 00 00 00 00 00 00 00 00 67 00 00 00 00 00 00 00 00 00 00 e3 00 00 00 00 00 00 00 67 00 e3 67 00 00 00 00 00 00 00 e3 00 00 00 e3 e3 00 00 00 00 00 00 00 67 67 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 67 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 67 00 67 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 e3 67 00 00 00 00 45 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 28 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 e3 00 00 00 00 00 00 00 00 00 00 00 00 67 00 00 00 00 00 00 00 e3 00 00 00 00 67 00 00 00 00 00 00 00 d0 00 00 00 00 00 00 00 00 00 28 00 00 00 00 00 00 67 00 00 00 e3 00 e3 00 00 e3 00 00 00 00 67 00 67 00 00 46 00 00 00 00 67 00 00 00 00 67 28 00 00 00 67 00 00 00 00 00 00 00 00 00 00 e3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 e3 00 00 00 00 00 00 67 00 e3 00 00 00 00 00 67 00 00 00 00 00 00 00 00 00 00 00 00 67 49 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 e3 00 00 67 00 00 00 67 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 67 00 00 00 00 00 00 00 e3 00 00 00 00 00 00 00 00 00 00 00 00 00 e3 45 00 00 00 00 67 00 00 e3 00 00 00 00 00 00 00 00 00 67 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 e3 00 00 00 00 00 00 00 00 00 00 67 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 28 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 00 00 00 00 67 00 28 00 00 00 00 00 e3 00 00 00 00 00 67 00 00 00 00 67 00 00 00 00 00 00 00 00 00 00 00 00 00 00 67 00 00 67 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 67 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 e3 00 67 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 67 00 00 00 00 00 e3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 d0 00 00 00 00 67 00 00 00 00 00 00 00 00 00 00 00 00 28 00 00 00 00 00 67 00 00 00 00 67 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
*/
