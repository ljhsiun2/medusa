.global s_prepare_buffers
s_prepare_buffers:
push %r11
push %r12
push %r13
push %r8
push %r9
push %rax
push %rcx
push %rdi
push %rsi
lea addresses_WC_ht+0x1d795, %rcx
nop
and $19760, %r11
mov (%rcx), %rax
nop
dec %r8
lea addresses_UC_ht+0x1ba95, %rax
nop
nop
nop
nop
nop
dec %r13
mov $0x6162636465666768, %r9
movq %r9, (%rax)
nop
nop
nop
and $29079, %r13
lea addresses_A_ht+0x1cb75, %r11
nop
nop
nop
nop
add %r12, %r12
mov (%r11), %eax
nop
nop
nop
sub %r12, %r12
lea addresses_A_ht+0x11b95, %rsi
lea addresses_D_ht+0x1e615, %rdi
nop
nop
nop
nop
nop
and %r13, %r13
mov $93, %rcx
rep movsq
nop
and $20159, %r11
lea addresses_A_ht+0x1baed, %r9
nop
nop
nop
xor %r8, %r8
mov (%r9), %r11
xor %r12, %r12
lea addresses_WC_ht+0xd84d, %r11
nop
nop
nop
nop
cmp $37578, %rax
mov (%r11), %r9w
xor %r12, %r12
lea addresses_UC_ht+0xad75, %r13
nop
nop
nop
add %r11, %r11
movb (%r13), %r8b
nop
nop
nop
nop
nop
sub $4197, %r12
lea addresses_A_ht+0xfc05, %rdi
dec %r12
mov $0x6162636465666768, %r11
movq %r11, (%rdi)
nop
nop
nop
sub %rax, %rax
lea addresses_WT_ht+0x4f15, %r9
clflush (%r9)
nop
nop
nop
add $5892, %rdi
movw $0x6162, (%r9)
nop
nop
nop
nop
dec %r13
lea addresses_D_ht+0x14b95, %rsi
lea addresses_UC_ht+0x2163, %rdi
sub %r13, %r13
mov $105, %rcx
rep movsw
nop
and %rax, %rax
lea addresses_normal_ht+0x8b05, %rsi
lea addresses_WC_ht+0x1ab59, %rdi
clflush (%rsi)
nop
cmp %r11, %r11
mov $48, %rcx
rep movsl
nop
nop
nop
nop
cmp %rsi, %rsi
lea addresses_A_ht+0x1401b, %r13
nop
nop
nop
nop
sub $3310, %rdi
mov $0x6162636465666768, %rcx
movq %rcx, (%r13)
nop
add %rsi, %rsi
lea addresses_A_ht+0xfc55, %rsi
lea addresses_WC_ht+0x1c75, %rdi
nop
nop
xor %r11, %r11
mov $127, %rcx
rep movsl
nop
nop
inc %r13
lea addresses_A_ht+0x179a5, %rax
nop
xor $64360, %r9
mov (%rax), %r13w
nop
nop
nop
add $25334, %rdi
lea addresses_normal_ht+0x9b95, %rax
clflush (%rax)
nop
nop
nop
inc %r8
vmovups (%rax), %ymm1
vextracti128 $1, %ymm1, %xmm1
vpextrq $1, %xmm1, %r13
nop
nop
nop
nop
add $35799, %r13
pop %rsi
pop %rdi
pop %rcx
pop %rax
pop %r9
pop %r8
pop %r13
pop %r12
pop %r11
ret

    .global s_faulty_load
s_faulty_load:
push %r10
push %r11
push %r14
push %r8
push %r9
push %rcx
push %rdx

// Store
lea addresses_RW+0x12b95, %rdx
dec %rcx
mov $0x5152535455565758, %r10
movq %r10, %xmm5
vmovups %ymm5, (%rdx)
nop
nop
nop
nop
nop
add $10858, %rcx

// Store
mov $0xaad, %rdx
nop
nop
nop
nop
nop
dec %r11
movb $0x51, (%rdx)
dec %r8

// Load
lea addresses_RW+0x123d5, %rdx
nop
nop
nop
nop
sub %r14, %r14
mov (%rdx), %r8d
nop
nop
nop
nop
sub %r10, %r10

// Store
lea addresses_WT+0xb015, %r9
nop
nop
nop
nop
nop
cmp $55994, %rdx
movb $0x51, (%r9)
nop
nop
nop
and $48475, %r10

// Load
mov $0xd95, %r10
nop
nop
nop
nop
nop
and %r8, %r8
movb (%r10), %cl
nop
nop
nop
nop
nop
xor $23959, %rdx

// Store
mov $0x7dd, %r11
nop
and %rcx, %rcx
mov $0x5152535455565758, %r8
movq %r8, (%r11)
nop
nop
nop
nop
and $2813, %r11

// Store
lea addresses_PSE+0x7195, %rdx
nop
nop
nop
nop
nop
sub %r10, %r10
movw $0x5152, (%rdx)
nop
sub $489, %rdx

// Store
mov $0x43ebb40000000895, %rdx
nop
nop
nop
nop
nop
and %r9, %r9
mov $0x5152535455565758, %r11
movq %r11, %xmm6
vmovups %ymm6, (%rdx)
nop
nop
nop
inc %rdx

// Faulty Load
lea addresses_RW+0x8395, %rdx
nop
dec %r14
mov (%rdx), %r11
lea oracles, %rdx
and $0xff, %r11
shlq $12, %r11
mov (%rdx,%r11,1), %r11
pop %rdx
pop %rcx
pop %r9
pop %r8
pop %r14
pop %r11
pop %r10
ret

/*
<gen_faulty_load>
[REF]
{'OP': 'LOAD', 'src': {'type': 'addresses_RW', 'size': 16, 'AVXalign': False, 'NT': False, 'congruent': 0, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_RW', 'size': 32, 'AVXalign': False, 'NT': False, 'congruent': 11, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_P', 'size': 1, 'AVXalign': False, 'NT': False, 'congruent': 3, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_RW', 'size': 4, 'AVXalign': False, 'NT': False, 'congruent': 5, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_WT', 'size': 1, 'AVXalign': True, 'NT': False, 'congruent': 6, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_P', 'size': 1, 'AVXalign': False, 'NT': False, 'congruent': 9, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_P', 'size': 8, 'AVXalign': False, 'NT': False, 'congruent': 1, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_PSE', 'size': 2, 'AVXalign': False, 'NT': True, 'congruent': 9, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_NC', 'size': 32, 'AVXalign': False, 'NT': False, 'congruent': 8, 'same': False}}
[Faulty Load]
{'OP': 'LOAD', 'src': {'type': 'addresses_RW', 'size': 8, 'AVXalign': False, 'NT': False, 'congruent': 0, 'same': True}}
<gen_prepare_buffer>
{'OP': 'LOAD', 'src': {'type': 'addresses_WC_ht', 'size': 8, 'AVXalign': False, 'NT': False, 'congruent': 8, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_UC_ht', 'size': 8, 'AVXalign': True, 'NT': False, 'congruent': 8, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_A_ht', 'size': 4, 'AVXalign': False, 'NT': False, 'congruent': 5, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_A_ht', 'congruent': 11, 'same': False}, 'dst': {'type': 'addresses_D_ht', 'congruent': 7, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_A_ht', 'size': 8, 'AVXalign': False, 'NT': False, 'congruent': 0, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_WC_ht', 'size': 2, 'AVXalign': False, 'NT': False, 'congruent': 2, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_UC_ht', 'size': 1, 'AVXalign': False, 'NT': False, 'congruent': 5, 'same': True}}
{'OP': 'STOR', 'dst': {'type': 'addresses_A_ht', 'size': 8, 'AVXalign': False, 'NT': False, 'congruent': 3, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_WT_ht', 'size': 2, 'AVXalign': False, 'NT': False, 'congruent': 7, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_D_ht', 'congruent': 8, 'same': False}, 'dst': {'type': 'addresses_UC_ht', 'congruent': 1, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_normal_ht', 'congruent': 4, 'same': False}, 'dst': {'type': 'addresses_WC_ht', 'congruent': 1, 'same': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_A_ht', 'size': 8, 'AVXalign': False, 'NT': False, 'congruent': 0, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_A_ht', 'congruent': 4, 'same': False}, 'dst': {'type': 'addresses_WC_ht', 'congruent': 0, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_A_ht', 'size': 2, 'AVXalign': False, 'NT': False, 'congruent': 4, 'same': False}}
{'OP': 'LOAD', 'src': {'type': 'addresses_normal_ht', 'size': 32, 'AVXalign': False, 'NT': False, 'congruent': 10, 'same': True}}
{'32': 440}
32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32 32
*/
