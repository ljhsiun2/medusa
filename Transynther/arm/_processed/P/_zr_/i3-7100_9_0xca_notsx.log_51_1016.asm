.global s_prepare_buffers
s_prepare_buffers:
push %r11
push %r8
push %rax
push %rbp
push %rbx
push %rcx
push %rdi
push %rdx
push %rsi
lea addresses_UC_ht+0xbe7e, %rdi
nop
nop
nop
nop
nop
xor $57833, %rdx
movb (%rdi), %al
nop
nop
nop
nop
sub $56428, %rax
lea addresses_WC_ht+0x1cf84, %rbp
nop
nop
nop
nop
sub $24640, %r11
movl $0x61626364, (%rbp)
nop
sub $15713, %rdi
lea addresses_D_ht+0x102c4, %r11
nop
nop
nop
nop
add $16755, %r8
movb (%r11), %bl
nop
nop
nop
nop
xor $63546, %rbp
lea addresses_WT_ht+0x6d14, %rsi
lea addresses_D_ht+0x7fee, %rdi
xor $33729, %r8
mov $75, %rcx
rep movsl
sub %rdx, %rdx
lea addresses_normal_ht+0x14684, %rdx
nop
nop
dec %rcx
mov (%rdx), %rax
nop
nop
add %r8, %r8
lea addresses_D_ht+0x3e0a, %rbx
clflush (%rbx)
nop
nop
lfence
movb $0x61, (%rbx)
cmp %rcx, %rcx
pop %rsi
pop %rdx
pop %rdi
pop %rcx
pop %rbx
pop %rbp
pop %rax
pop %r8
pop %r11
ret

    .global s_faulty_load
s_faulty_load:
push %r13
push %r15
push %r8
push %r9
push %rcx
push %rdi
push %rdx
push %rsi

// REPMOV
lea addresses_D+0x3784, %rsi
lea addresses_normal+0x9a6c, %rdi
nop
inc %rdx
mov $92, %rcx
rep movsb
nop
nop
nop
xor $29353, %r13

// Load
lea addresses_PSE+0x1d433, %rdx
nop
nop
sub $64343, %rdi
movups (%rdx), %xmm2
vpextrq $0, %xmm2, %r13
nop
nop
add %rsi, %rsi

// Store
lea addresses_WC+0x15b28, %rdi
nop
nop
nop
nop
nop
xor $337, %rcx
movl $0x51525354, (%rdi)
nop
sub $18399, %rsi

// Store
lea addresses_A+0x6784, %rsi
cmp $19898, %r8
movw $0x5152, (%rsi)
nop
nop
nop
nop
nop
inc %r15

// REPMOV
lea addresses_A+0x4f6c, %rsi
lea addresses_PSE+0xbb4c, %rdi
nop
nop
nop
add %r8, %r8
mov $84, %rcx
rep movsq
nop
nop
nop
and $54972, %rcx

// Load
lea addresses_WT+0x1784, %rcx
nop
nop
nop
nop
add %rdi, %rdi
movb (%rcx), %dl
nop
nop
nop
nop
nop
and %r15, %r15

// Load
lea addresses_WT+0x184b5, %r13
clflush (%r13)
nop
nop
nop
nop
cmp %rsi, %rsi
mov (%r13), %di
dec %rsi

// Load
lea addresses_normal+0xb308, %r8
nop
nop
nop
sub %r13, %r13
vmovups (%r8), %ymm1
vextracti128 $0, %ymm1, %xmm1
vpextrq $1, %xmm1, %rdx
nop
nop
nop
xor %rdi, %rdi

// Store
lea addresses_PSE+0x3bbd, %r13
and %rcx, %rcx
mov $0x5152535455565758, %r8
movq %r8, %xmm1
movups %xmm1, (%r13)
nop
inc %r8

// REPMOV
lea addresses_WC+0x13884, %rsi
lea addresses_normal+0x11764, %rdi
nop
nop
cmp %r9, %r9
mov $63, %rcx
rep movsw
nop
cmp %r8, %r8

// Load
lea addresses_normal+0x9384, %r13
nop
nop
nop
cmp %rcx, %rcx
mov (%r13), %rdi
nop
and $31512, %rdi

// Faulty Load
mov $0xf84, %rcx
sub %r9, %r9
mov (%rcx), %r15d
lea oracles, %rdx
and $0xff, %r15
shlq $12, %r15
mov (%rdx,%r15,1), %r15
pop %rsi
pop %rdx
pop %rdi
pop %rcx
pop %r9
pop %r8
pop %r15
pop %r13
ret

/*
<gen_faulty_load>
[REF]
{'src': {'same': False, 'congruent': 0, 'NT': False, 'type': 'addresses_P', 'size': 1, 'AVXalign': False}, 'OP': 'LOAD'}
{'src': {'type': 'addresses_D', 'congruent': 7, 'same': False}, 'OP': 'REPM', 'dst': {'type': 'addresses_normal', 'congruent': 3, 'same': False}}
{'src': {'same': False, 'congruent': 0, 'NT': False, 'type': 'addresses_PSE', 'size': 16, 'AVXalign': False}, 'OP': 'LOAD'}
{'OP': 'STOR', 'dst': {'same': False, 'congruent': 0, 'NT': False, 'type': 'addresses_WC', 'size': 4, 'AVXalign': False}}
{'OP': 'STOR', 'dst': {'same': False, 'congruent': 11, 'NT': False, 'type': 'addresses_A', 'size': 2, 'AVXalign': False}}
{'src': {'type': 'addresses_A', 'congruent': 2, 'same': False}, 'OP': 'REPM', 'dst': {'type': 'addresses_PSE', 'congruent': 2, 'same': False}}
{'src': {'same': False, 'congruent': 10, 'NT': False, 'type': 'addresses_WT', 'size': 1, 'AVXalign': False}, 'OP': 'LOAD'}
{'src': {'same': False, 'congruent': 0, 'NT': False, 'type': 'addresses_WT', 'size': 2, 'AVXalign': False}, 'OP': 'LOAD'}
{'src': {'same': False, 'congruent': 2, 'NT': False, 'type': 'addresses_normal', 'size': 32, 'AVXalign': False}, 'OP': 'LOAD'}
{'OP': 'STOR', 'dst': {'same': False, 'congruent': 0, 'NT': False, 'type': 'addresses_PSE', 'size': 16, 'AVXalign': False}}
{'src': {'type': 'addresses_WC', 'congruent': 6, 'same': False}, 'OP': 'REPM', 'dst': {'type': 'addresses_normal', 'congruent': 5, 'same': False}}
{'src': {'same': False, 'congruent': 10, 'NT': False, 'type': 'addresses_normal', 'size': 8, 'AVXalign': False}, 'OP': 'LOAD'}
[Faulty Load]
{'src': {'same': True, 'congruent': 0, 'NT': False, 'type': 'addresses_P', 'size': 4, 'AVXalign': False}, 'OP': 'LOAD'}
<gen_prepare_buffer>
{'src': {'same': True, 'congruent': 1, 'NT': False, 'type': 'addresses_UC_ht', 'size': 1, 'AVXalign': False}, 'OP': 'LOAD'}
{'OP': 'STOR', 'dst': {'same': False, 'congruent': 11, 'NT': False, 'type': 'addresses_WC_ht', 'size': 4, 'AVXalign': False}}
{'src': {'same': False, 'congruent': 6, 'NT': False, 'type': 'addresses_D_ht', 'size': 1, 'AVXalign': False}, 'OP': 'LOAD'}
{'src': {'type': 'addresses_WT_ht', 'congruent': 2, 'same': True}, 'OP': 'REPM', 'dst': {'type': 'addresses_D_ht', 'congruent': 0, 'same': False}}
{'src': {'same': False, 'congruent': 5, 'NT': False, 'type': 'addresses_normal_ht', 'size': 8, 'AVXalign': False}, 'OP': 'LOAD'}
{'OP': 'STOR', 'dst': {'same': False, 'congruent': 1, 'NT': False, 'type': 'addresses_D_ht', 'size': 1, 'AVXalign': False}}
{'00': 51}
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
*/
