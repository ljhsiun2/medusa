.global s_prepare_buffers
s_prepare_buffers:
push %r12
push %r14
push %rbp
push %rbx
push %rcx
push %rdi
push %rdx
push %rsi
lea addresses_D_ht+0x35a8, %rsi
lea addresses_UC_ht+0x113a8, %rdi
clflush (%rdi)
nop
nop
nop
nop
and $35688, %rbp
mov $78, %rcx
rep movsl
cmp %rbx, %rbx
lea addresses_normal_ht+0x1e398, %r12
nop
inc %rbx
movw $0x6162, (%r12)
nop
nop
nop
cmp %rsi, %rsi
lea addresses_WC_ht+0x1da8, %rsi
lea addresses_A_ht+0x1c4a8, %rdi
dec %rdx
mov $30, %rcx
rep movsb
nop
nop
nop
nop
sub $4197, %rdx
lea addresses_A_ht+0x130dc, %rsi
lea addresses_A_ht+0x4428, %rdi
clflush (%rsi)
nop
nop
nop
nop
nop
sub %rdx, %rdx
mov $32, %rcx
rep movsl
nop
nop
nop
dec %rdx
lea addresses_D_ht+0x7c48, %rsi
nop
sub %rbp, %rbp
mov (%rsi), %ecx
nop
nop
nop
sub %rsi, %rsi
lea addresses_normal_ht+0x15fa8, %rsi
lea addresses_WC_ht+0x8114, %rdi
nop
nop
nop
nop
nop
and $31672, %r14
mov $59, %rcx
rep movsb
nop
nop
add %r12, %r12
lea addresses_WC_ht+0xeb88, %rsi
lea addresses_A_ht+0xe858, %rdi
nop
nop
nop
nop
sub %rbx, %rbx
mov $31, %rcx
rep movsq
nop
nop
nop
nop
cmp %r12, %r12
lea addresses_D_ht+0x89c8, %r12
and %r14, %r14
and $0xffffffffffffffc0, %r12
movntdqa (%r12), %xmm4
vpextrq $1, %xmm4, %rdi
nop
nop
nop
nop
add $47388, %rbp
lea addresses_D_ht+0x159b, %rsi
nop
nop
nop
nop
cmp %rbx, %rbx
mov (%rsi), %r12w
nop
nop
nop
nop
cmp %r12, %r12
lea addresses_D_ht+0x121a8, %rsi
nop
and $38091, %r14
movw $0x6162, (%rsi)
nop
sub %rbp, %rbp
lea addresses_WT_ht+0x15a8, %rsi
lea addresses_WC_ht+0x1e84c, %rdi
nop
nop
nop
sub $64841, %r14
mov $54, %rcx
rep movsb
nop
nop
dec %r12
lea addresses_A_ht+0x6d08, %rsi
lea addresses_WC_ht+0x37e8, %rdi
nop
nop
xor $20757, %r12
mov $108, %rcx
rep movsl
add %rcx, %rcx
pop %rsi
pop %rdx
pop %rdi
pop %rcx
pop %rbx
pop %rbp
pop %r14
pop %r12
ret

    .global s_faulty_load
s_faulty_load:
push %r11
push %r14
push %r8
push %rbx
push %rcx
push %rdx
push %rsi

// Store
lea addresses_WT+0xb528, %r8
nop
nop
nop
sub $58429, %rdx
movw $0x5152, (%r8)
nop
nop
xor %rbx, %rbx

// Store
lea addresses_D+0x4fa8, %r14
nop
nop
nop
nop
nop
xor %r11, %r11
movl $0x51525354, (%r14)
nop
nop
nop
add %r14, %r14

// Store
lea addresses_WT+0x3871, %rcx
nop
nop
nop
nop
nop
sub $20533, %rdx
mov $0x5152535455565758, %r8
movq %r8, (%rcx)
nop
nop
inc %rdx

// Store
lea addresses_WT+0xf20c, %rdx
nop
nop
inc %rsi
movb $0x51, (%rdx)
nop
nop
nop
nop
nop
inc %rbx

// Faulty Load
lea addresses_US+0x85a8, %rbx
nop
nop
nop
nop
nop
cmp $65121, %rsi
movups (%rbx), %xmm3
vpextrq $1, %xmm3, %r14
lea oracles, %rbx
and $0xff, %r14
shlq $12, %r14
mov (%rbx,%r14,1), %r14
pop %rsi
pop %rdx
pop %rcx
pop %rbx
pop %r8
pop %r14
pop %r11
ret

/*
<gen_faulty_load>
[REF]
{'OP': 'LOAD', 'src': {'type': 'addresses_US', 'size': 16, 'AVXalign': False, 'NT': False, 'congruent': 0, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_WT', 'size': 2, 'AVXalign': False, 'NT': False, 'congruent': 6, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_D', 'size': 4, 'AVXalign': False, 'NT': False, 'congruent': 9, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_WT', 'size': 8, 'AVXalign': False, 'NT': False, 'congruent': 0, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_WT', 'size': 1, 'AVXalign': False, 'NT': False, 'congruent': 0, 'same': False}}
[Faulty Load]
{'OP': 'LOAD', 'src': {'type': 'addresses_US', 'size': 16, 'AVXalign': False, 'NT': False, 'congruent': 0, 'same': True}}
<gen_prepare_buffer>
{'OP': 'REPM', 'src': {'type': 'addresses_D_ht', 'congruent': 11, 'same': False}, 'dst': {'type': 'addresses_UC_ht', 'congruent': 6, 'same': True}}
{'OP': 'STOR', 'dst': {'type': 'addresses_normal_ht', 'size': 2, 'AVXalign': False, 'NT': False, 'congruent': 4, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_WC_ht', 'congruent': 11, 'same': False}, 'dst': {'type': 'addresses_A_ht', 'congruent': 4, 'same': True}}
{'OP': 'REPM', 'src': {'type': 'addresses_A_ht', 'congruent': 2, 'same': False}, 'dst': {'type': 'addresses_A_ht', 'congruent': 6, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_D_ht', 'size': 4, 'AVXalign': False, 'NT': False, 'congruent': 5, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_normal_ht', 'congruent': 9, 'same': False}, 'dst': {'type': 'addresses_WC_ht', 'congruent': 2, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_WC_ht', 'congruent': 1, 'same': False}, 'dst': {'type': 'addresses_A_ht', 'congruent': 4, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_D_ht', 'size': 16, 'AVXalign': False, 'NT': True, 'congruent': 3, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_D_ht', 'size': 2, 'AVXalign': False, 'NT': False, 'congruent': 0, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_D_ht', 'size': 2, 'AVXalign': True, 'NT': False, 'congruent': 10, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_WT_ht', 'congruent': 11, 'same': False}, 'dst': {'type': 'addresses_WC_ht', 'congruent': 2, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_A_ht', 'congruent': 4, 'same': False}, 'dst': {'type': 'addresses_WC_ht', 'congruent': 6, 'same': False}}
{'00': 12}
00 00 00 00 00 00 00 00 00 00 00 00
*/
