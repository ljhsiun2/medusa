.global s_prepare_buffers
s_prepare_buffers:
push %r10
push %r12
push %r15
push %rax
push %rbp
push %rcx
push %rdi
push %rsi
lea addresses_WC_ht+0x1b109, %rsi
lea addresses_normal_ht+0x10009, %rdi
clflush (%rsi)
nop
nop
nop
nop
dec %r12
mov $109, %rcx
rep movsq
nop
and %r10, %r10
lea addresses_A_ht+0xcc09, %rcx
nop
sub $57594, %rbp
movl $0x61626364, (%rcx)
nop
nop
nop
nop
nop
and %rcx, %rcx
lea addresses_UC_ht+0x7b20, %rsi
lea addresses_WT_ht+0x209, %rdi
and %r15, %r15
mov $51, %rcx
rep movsb
nop
nop
nop
nop
nop
xor %rbp, %rbp
lea addresses_A_ht+0x12009, %r12
nop
inc %r10
movl $0x61626364, (%r12)
nop
and $34991, %r15
lea addresses_normal_ht+0xde89, %rcx
nop
nop
nop
sub $19300, %rdi
movw $0x6162, (%rcx)
nop
nop
nop
nop
nop
and %r10, %r10
lea addresses_UC_ht+0x3e09, %rsi
lea addresses_WC_ht+0x17761, %rdi
nop
nop
nop
nop
xor %r10, %r10
mov $67, %rcx
rep movsq
nop
nop
nop
cmp $27270, %r15
lea addresses_WC_ht+0x4be1, %rsi
lea addresses_normal_ht+0x1dd49, %rdi
and $12050, %rax
mov $8, %rcx
rep movsw
nop
add $49993, %rbp
lea addresses_D_ht+0xfc29, %rbp
nop
sub %rcx, %rcx
mov $0x6162636465666768, %r15
movq %r15, (%rbp)
nop
nop
nop
nop
nop
cmp %rbp, %rbp
lea addresses_A_ht+0x17e09, %rsi
lea addresses_A_ht+0xa609, %rdi
nop
sub %rbp, %rbp
mov $32, %rcx
rep movsq
nop
nop
nop
and $20133, %rax
lea addresses_WC_ht+0x1c09, %rsi
lea addresses_D_ht+0x3462, %rdi
clflush (%rdi)
nop
nop
nop
nop
nop
cmp $2045, %r15
mov $21, %rcx
rep movsl
nop
nop
nop
mfence
lea addresses_WT_ht+0x11f01, %rdi
nop
sub $34859, %rcx
vmovups (%rdi), %ymm6
vextracti128 $1, %ymm6, %xmm6
vpextrq $1, %xmm6, %rbp
add $18734, %r10
lea addresses_D_ht+0x17859, %rsi
nop
nop
nop
and %r12, %r12
movl $0x61626364, (%rsi)
nop
nop
nop
nop
and $60950, %rax
lea addresses_UC_ht+0x11b78, %rsi
clflush (%rsi)
nop
nop
nop
cmp $21862, %r15
mov $0x6162636465666768, %rbp
movq %rbp, %xmm5
movups %xmm5, (%rsi)
nop
nop
nop
xor %r15, %r15
lea addresses_WT_ht+0x13609, %rsi
lea addresses_D_ht+0x164a1, %rdi
nop
nop
nop
nop
dec %r15
mov $58, %rcx
rep movsl
nop
nop
nop
and $9404, %rdi
pop %rsi
pop %rdi
pop %rcx
pop %rbp
pop %rax
pop %r15
pop %r12
pop %r10
ret

    .global s_faulty_load
s_faulty_load:
push %r13
push %r14
push %r9
push %rbp
push %rbx
push %rcx
push %rdi

// Load
lea addresses_PSE+0x8331, %rcx
clflush (%rcx)
nop
nop
nop
nop
nop
cmp %r9, %r9
movb (%rcx), %r13b
nop
nop
nop
nop
nop
cmp %rbx, %rbx

// Load
lea addresses_WC+0x1ecb9, %rbx
nop
add %rdi, %rdi
vmovups (%rbx), %ymm5
vextracti128 $1, %ymm5, %xmm5
vpextrq $0, %xmm5, %r13
nop
nop
nop
nop
sub $22747, %r14

// Faulty Load
mov $0x14eeac0000000609, %rbx
nop
nop
nop
nop
nop
xor %r9, %r9
movups (%rbx), %xmm7
vpextrq $1, %xmm7, %rcx
lea oracles, %r13
and $0xff, %rcx
shlq $12, %rcx
mov (%r13,%rcx,1), %rcx
pop %rdi
pop %rcx
pop %rbx
pop %rbp
pop %r9
pop %r14
pop %r13
ret

/*
<gen_faulty_load>
[REF]
{'OP': 'LOAD', 'src': {'type': 'addresses_NC', 'size': 1, 'AVXalign': False, 'NT': False, 'congruent': 0, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_PSE', 'size': 1, 'AVXalign': True, 'NT': False, 'congruent': 2, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_WC', 'size': 32, 'AVXalign': False, 'NT': False, 'congruent': 4, 'same': False}}
[Faulty Load]
{'OP': 'LOAD', 'src': {'type': 'addresses_NC', 'size': 16, 'AVXalign': False, 'NT': False, 'congruent': 0, 'same': True}}
<gen_prepare_buffer>
{'OP': 'REPM', 'src': {'type': 'addresses_WC_ht', 'congruent': 7, 'same': False}, 'dst': {'type': 'addresses_normal_ht', 'congruent': 9, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_A_ht', 'size': 4, 'AVXalign': False, 'NT': False, 'congruent': 9, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_UC_ht', 'congruent': 0, 'same': False}, 'dst': {'type': 'addresses_WT_ht', 'congruent': 8, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_A_ht', 'size': 4, 'AVXalign': False, 'NT': False, 'congruent': 9, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_normal_ht', 'size': 2, 'AVXalign': False, 'NT': False, 'congruent': 3, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_UC_ht', 'congruent': 11, 'same': False}, 'dst': {'type': 'addresses_WC_ht', 'congruent': 3, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_WC_ht', 'congruent': 3, 'same': False}, 'dst': {'type': 'addresses_normal_ht', 'congruent': 5, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_D_ht', 'size': 8, 'AVXalign': False, 'NT': False, 'congruent': 5, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_A_ht', 'congruent': 11, 'same': False}, 'dst': {'type': 'addresses_A_ht', 'congruent': 9, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_WC_ht', 'congruent': 8, 'same': False}, 'dst': {'type': 'addresses_D_ht', 'congruent': 0, 'same': True}}
{'OP': 'LOAD', 'src': {'type': 'addresses_WT_ht', 'size': 32, 'AVXalign': False, 'NT': False, 'congruent': 3, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_D_ht', 'size': 4, 'AVXalign': False, 'NT': False, 'congruent': 1, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_UC_ht', 'size': 16, 'AVXalign': False, 'NT': False, 'congruent': 0, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_WT_ht', 'congruent': 10, 'same': False}, 'dst': {'type': 'addresses_D_ht', 'congruent': 2, 'same': False}}
{'00': 17184, '48': 4466, '45': 120, '49': 42, '0b': 12, '3e': 4, 'd1': 1}
00 00 00 00 00 00 00 48 00 00 00 00 00 00 00 00 48 00 00 00 00 00 00 48 00 48 00 00 48 00 00 00 00 48 00 00 48 00 00 48 00 48 00 00 00 00 00 00 00 00 00 00 48 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 48 00 48 48 00 00 00 00 00 48 00 00 00 00 48 00 00 00 00 00 00 48 00 45 00 00 00 00 48 00 00 48 00 00 00 00 00 45 00 00 48 00 00 00 00 00 00 00 00 00 00 00 00 48 00 48 00 00 00 48 00 48 00 00 00 00 48 00 00 00 00 00 00 48 00 00 00 00 00 00 48 00 00 00 48 00 48 00 00 48 00 48 00 00 00 00 00 00 00 00 45 00 00 00 00 00 00 00 00 00 00 00 00 48 00 00 00 00 00 48 00 48 00 00 00 00 00 00 00 00 00 00 48 00 48 48 00 00 00 00 48 00 00 48 00 00 00 00 48 00 00 00 00 48 00 48 00 00 00 48 00 00 00 48 48 00 48 48 00 48 00 00 48 00 00 48 00 00 00 00 00 00 00 00 00 48 00 00 48 00 48 00 48 00 00 00 00 48 00 00 00 00 00 00 00 00 00 00 00 00 48 00 00 00 00 48 00 00 48 00 00 00 48 00 00 00 48 00 00 00 00 00 48 00 00 00 48 00 00 00 00 00 00 00 00 00 00 48 00 00 48 00 00 48 00 00 00 00 00 00 48 00 00 48 00 48 00 00 00 00 00 00 00 00 00 48 00 00 00 00 00 00 00 00 00 48 00 00 00 48 00 48 00 00 00 00 00 00 00 00 00 48 00 00 48 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 48 00 00 00 48 00 00 00 00 00 00 00 00 00 48 00 00 00 48 00 48 48 00 00 48 00 00 00 00 00 00 00 00 00 48 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 48 00 00 48 00 48 00 00 48 00 00 00 00 00 00 00 48 00 00 00 00 00 00 48 00 00 00 00 00 48 00 00 48 00 00 00 00 00 48 00 00 00 00 00 00 48 00 00 00 00 00 00 00 00 00 00 00 00 48 00 00 48 00 48 00 00 00 00 48 00 00 00 00 00 00 00 00 00 00 00 48 00 00 00 48 00 00 00 00 48 00 48 00 48 00 00 00 00 00 48 00 00 00 00 00 00 00 48 00 00 00 00 00 00 00 00 00 00 48 00 00 48 00 00 00 00 00 00 00 00 00 00 48 00 00 00 00 48 00 00 00 00 00 00 00 00 00 48 00 00 00 00 00 00 00 00 00 00 00 48 00 00 48 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 48 00 00 00 00 48 00 00 00 00 00 00 00 48 00 00 00 48 00 00 48 00 00 00 48 00 48 48 00 00 00 48 00 00 00 00 48 00 48 00 00 00 00 00 00 00 00 48 00 00 48 00 00 48 00 00 00 00 48 00 48 00 00 00 48 00 00 48 00 00 00 00 00 00 48 00 48 48 00 00 00 48 00 00 00 00 48 00 00 00 48 00 00 00 00 00 00 48 00 00 00 00 00 48 00 48 00 00 00 00 00 00 00 00 00 00 00 48 00 00 00 00 48 00 00 00 00 00 00 00 00 00 00 00 00 00 48 00 00 00 00 00 00 00 00 48 00 00 00 00 00 00 00 00 00 00 00 48 00 48 00 00 00 00 48 00 00 48 00 00 00 00 48 00 00 00 00 00 00 48 00 00 48 00 00 48 00 00 00 48 00 00 00 48 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 48 00 00 00 00 00 00 00 48 00 00 00 00 00 00 48 00 00 00 00 48 00 00 00 00 48 00 48 48 00 00 00 00 00 00 00 00 00 00 48 00 00 00 00 00 00 00 48 00 48 00 00 48 48 00 00 00 00 00 00 00 48 48 00 00 00 00 00 00 48 00 00 00 00 00 00 00 00 00 00 00 00 00 00 48 00 00 00 00 00 00 48 00 00 00 48 48 00 48 00 00 00 00 00 00 00 00 48 48 00 48 00 00 00 00 48 00 00 00 48 00 00 00 00 00 48 00 00 00 00 00 00 00 00 00 00 00 48 48 00 00 00 48 00 48 00 00 00 48 00 48 00 00 48 00 00 00
*/
