.global s_prepare_buffers
s_prepare_buffers:
push %r12
push %r8
push %r9
push %rax
push %rbp
push %rcx
push %rdi
push %rsi
lea addresses_WC_ht+0x1a3a9, %rsi
lea addresses_A_ht+0x13e61, %rdi
nop
nop
nop
and $7903, %r8
mov $62, %rcx
rep movsw
nop
nop
nop
cmp $49296, %r12
lea addresses_A_ht+0x93a9, %rsi
lea addresses_normal_ht+0x175a9, %rdi
nop
nop
nop
nop
inc %rbp
mov $107, %rcx
rep movsl
nop
nop
mfence
lea addresses_A_ht+0xe5, %r8
nop
nop
nop
cmp %rax, %rax
movb $0x61, (%r8)
nop
nop
nop
nop
xor %rbp, %rbp
lea addresses_WT_ht+0x71a9, %rdi
nop
nop
nop
nop
sub %rsi, %rsi
movb (%rdi), %r12b
nop
nop
inc %rdi
lea addresses_A_ht+0x25dd, %rcx
nop
nop
cmp %rdi, %rdi
and $0xffffffffffffffc0, %rcx
movaps (%rcx), %xmm2
vpextrq $0, %xmm2, %rbp
nop
inc %rbp
lea addresses_WC_ht+0x19ba9, %r8
nop
nop
nop
nop
add %rsi, %rsi
movb $0x61, (%r8)
and %rbp, %rbp
lea addresses_A_ht+0xabd9, %rax
nop
nop
nop
add %r12, %r12
movups (%rax), %xmm5
vpextrq $1, %xmm5, %rbp
nop
nop
nop
nop
nop
and $40239, %rax
lea addresses_D_ht+0x161a9, %r12
nop
nop
nop
nop
nop
add $7447, %rax
movw $0x6162, (%r12)
nop
nop
nop
sub %r12, %r12
lea addresses_D_ht+0x18aa9, %rax
nop
nop
cmp %r12, %r12
movl $0x61626364, (%rax)
sub %rax, %rax
lea addresses_UC_ht+0x1afc9, %r8
nop
nop
nop
add $22759, %rcx
movups (%r8), %xmm4
vpextrq $0, %xmm4, %rsi
nop
and $622, %rbp
lea addresses_UC_ht+0xf2a9, %r8
add %rax, %rax
movups (%r8), %xmm0
vpextrq $0, %xmm0, %r12
nop
cmp %r12, %r12
lea addresses_WT_ht+0x12125, %rsi
lea addresses_D_ht+0x79b9, %rdi
xor %r9, %r9
mov $96, %rcx
rep movsb
nop
nop
nop
nop
sub $46462, %r12
lea addresses_UC_ht+0x42a9, %rsi
lea addresses_WC_ht+0x101a9, %rdi
nop
nop
nop
nop
nop
sub $55504, %r8
mov $0, %rcx
rep movsb
nop
nop
nop
nop
and $47414, %rax
pop %rsi
pop %rdi
pop %rcx
pop %rbp
pop %rax
pop %r9
pop %r8
pop %r12
ret

    .global s_faulty_load
s_faulty_load:
push %r10
push %r9
push %rax
push %rbx
push %rcx
push %rdi
push %rdx

// Load
lea addresses_D+0xf005, %rbx
clflush (%rbx)
nop
nop
sub $50801, %r10
movb (%rbx), %r9b
nop
cmp %r10, %r10

// Faulty Load
mov $0x7a03e30000000ba9, %rcx
nop
nop
nop
nop
xor %rdx, %rdx
mov (%rcx), %r9w
lea oracles, %rcx
and $0xff, %r9
shlq $12, %r9
mov (%rcx,%r9,1), %r9
pop %rdx
pop %rdi
pop %rcx
pop %rbx
pop %rax
pop %r9
pop %r10
ret

/*
<gen_faulty_load>
[REF]
{'src': {'type': 'addresses_NC', 'AVXalign': False, 'size': 1, 'NT': True, 'same': False, 'congruent': 0}, 'OP': 'LOAD'}
{'src': {'type': 'addresses_D', 'AVXalign': False, 'size': 1, 'NT': False, 'same': False, 'congruent': 0}, 'OP': 'LOAD'}
[Faulty Load]
{'src': {'type': 'addresses_NC', 'AVXalign': False, 'size': 2, 'NT': False, 'same': True, 'congruent': 0}, 'OP': 'LOAD'}
<gen_prepare_buffer>
{'src': {'type': 'addresses_WC_ht', 'congruent': 5, 'same': False}, 'OP': 'REPM', 'dst': {'type': 'addresses_A_ht', 'congruent': 1, 'same': False}}
{'src': {'type': 'addresses_A_ht', 'congruent': 11, 'same': False}, 'OP': 'REPM', 'dst': {'type': 'addresses_normal_ht', 'congruent': 9, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_A_ht', 'AVXalign': False, 'size': 1, 'NT': False, 'same': False, 'congruent': 2}}
{'src': {'type': 'addresses_WT_ht', 'AVXalign': True, 'size': 1, 'NT': False, 'same': False, 'congruent': 9}, 'OP': 'LOAD'}
{'src': {'type': 'addresses_A_ht', 'AVXalign': True, 'size': 16, 'NT': False, 'same': False, 'congruent': 1}, 'OP': 'LOAD'}
{'OP': 'STOR', 'dst': {'type': 'addresses_WC_ht', 'AVXalign': False, 'size': 1, 'NT': False, 'same': False, 'congruent': 10}}
{'src': {'type': 'addresses_A_ht', 'AVXalign': False, 'size': 16, 'NT': False, 'same': False, 'congruent': 2}, 'OP': 'LOAD'}
{'OP': 'STOR', 'dst': {'type': 'addresses_D_ht', 'AVXalign': False, 'size': 2, 'NT': True, 'same': False, 'congruent': 9}}
{'OP': 'STOR', 'dst': {'type': 'addresses_D_ht', 'AVXalign': False, 'size': 4, 'NT': False, 'same': False, 'congruent': 7}}
{'src': {'type': 'addresses_UC_ht', 'AVXalign': False, 'size': 16, 'NT': False, 'same': False, 'congruent': 4}, 'OP': 'LOAD'}
{'src': {'type': 'addresses_UC_ht', 'AVXalign': False, 'size': 16, 'NT': False, 'same': False, 'congruent': 8}, 'OP': 'LOAD'}
{'src': {'type': 'addresses_WT_ht', 'congruent': 0, 'same': False}, 'OP': 'REPM', 'dst': {'type': 'addresses_D_ht', 'congruent': 3, 'same': False}}
{'src': {'type': 'addresses_UC_ht', 'congruent': 7, 'same': False}, 'OP': 'REPM', 'dst': {'type': 'addresses_WC_ht', 'congruent': 8, 'same': False}}
{'00': 222}
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
*/
