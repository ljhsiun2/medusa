.global s_prepare_buffers
s_prepare_buffers:
push %r12
push %r13
push %r14
push %r9
push %rcx
push %rdi
push %rsi
lea addresses_WC_ht+0x9462, %rsi
lea addresses_WC_ht+0x1659a, %rdi
clflush (%rdi)
nop
nop
and $47427, %r14
mov $55, %rcx
rep movsl
nop
nop
and $1837, %r13
lea addresses_normal_ht+0x1d366, %rsi
lea addresses_WC_ht+0x1559a, %rdi
nop
nop
sub $7931, %r14
mov $62, %rcx
rep movsw
nop
nop
nop
nop
sub %r13, %r13
lea addresses_WT_ht+0x209a, %r12
nop
dec %r9
movw $0x6162, (%r12)
nop
nop
nop
nop
nop
and %rdi, %rdi
lea addresses_WT_ht+0xab9a, %r13
nop
nop
nop
cmp $10236, %rdi
mov (%r13), %r14
nop
nop
cmp %rdi, %rdi
lea addresses_normal_ht+0x8ba, %r9
nop
nop
xor $24114, %r13
and $0xffffffffffffffc0, %r9
movntdqa (%r9), %xmm5
vpextrq $0, %xmm5, %rdi
nop
nop
nop
xor $35667, %r9
lea addresses_normal_ht+0x579a, %rdi
nop
nop
nop
nop
nop
and $37329, %r13
mov (%rdi), %esi
nop
add $62323, %rcx
lea addresses_normal_ht+0x1dd9a, %r13
nop
nop
nop
nop
xor $15116, %rdi
movl $0x61626364, (%r13)
nop
nop
nop
nop
sub %rcx, %rcx
lea addresses_WC_ht+0x1c272, %r13
clflush (%r13)
nop
nop
nop
nop
sub %r9, %r9
mov (%r13), %r14w
cmp %r9, %r9
lea addresses_WT_ht+0x99a, %rsi
lea addresses_normal_ht+0x19682, %rdi
nop
nop
nop
nop
cmp %r12, %r12
mov $101, %rcx
rep movsb
nop
and %r9, %r9
lea addresses_WT_ht+0xdd9a, %r13
clflush (%r13)
nop
nop
nop
cmp $24716, %r9
mov (%r13), %ecx
nop
nop
nop
xor $33408, %r12
lea addresses_normal_ht+0x11f93, %r13
nop
sub %r14, %r14
mov $0x6162636465666768, %rdi
movq %rdi, %xmm3
movups %xmm3, (%r13)
nop
sub %r9, %r9
lea addresses_WT_ht+0xa39a, %rsi
lea addresses_WT_ht+0x740a, %rdi
clflush (%rdi)
nop
and %r12, %r12
mov $125, %rcx
rep movsq
nop
nop
nop
nop
nop
cmp $27827, %r14
lea addresses_normal_ht+0x2a9a, %r12
nop
add %r14, %r14
mov (%r12), %ecx
nop
and %rdi, %rdi
pop %rsi
pop %rdi
pop %rcx
pop %r9
pop %r14
pop %r13
pop %r12
ret

    .global s_faulty_load
s_faulty_load:
push %r11
push %r13
push %r14
push %r15
push %r9
push %rbx
push %rsi

// Store
mov $0xe1a, %r9
nop
cmp $37374, %rbx
movw $0x5152, (%r9)
nop
nop
nop
nop
nop
cmp $54614, %r9

// Load
lea addresses_D+0x1679a, %r14
nop
nop
xor $41292, %r13
mov (%r14), %si
nop
nop
nop
nop
cmp $39024, %r11

// Store
lea addresses_UC+0x39a, %r13
nop
nop
nop
nop
add $27986, %r14
mov $0x5152535455565758, %r11
movq %r11, (%r13)
nop
inc %rsi

// Store
mov $0xb66, %rbx
clflush (%rbx)
nop
nop
add $28318, %r9
mov $0x5152535455565758, %r13
movq %r13, %xmm6
vmovups %ymm6, (%rbx)
nop
nop
add $38615, %rsi

// Faulty Load
lea addresses_WT+0x9d9a, %r14
nop
add %r13, %r13
movntdqa (%r14), %xmm6
vpextrq $1, %xmm6, %r11
lea oracles, %rbx
and $0xff, %r11
shlq $12, %r11
mov (%rbx,%r11,1), %r11
pop %rsi
pop %rbx
pop %r9
pop %r15
pop %r14
pop %r13
pop %r11
ret

/*
<gen_faulty_load>
[REF]
{'src': {'NT': False, 'same': False, 'congruent': 0, 'type': 'addresses_WT', 'AVXalign': False, 'size': 8}, 'OP': 'LOAD'}
{'OP': 'STOR', 'dst': {'NT': False, 'same': False, 'congruent': 6, 'type': 'addresses_P', 'AVXalign': False, 'size': 2}}
{'src': {'NT': False, 'same': False, 'congruent': 9, 'type': 'addresses_D', 'AVXalign': False, 'size': 2}, 'OP': 'LOAD'}
{'OP': 'STOR', 'dst': {'NT': False, 'same': False, 'congruent': 7, 'type': 'addresses_UC', 'AVXalign': False, 'size': 8}}
{'OP': 'STOR', 'dst': {'NT': False, 'same': False, 'congruent': 2, 'type': 'addresses_P', 'AVXalign': False, 'size': 32}}
[Faulty Load]
{'src': {'NT': True, 'same': True, 'congruent': 0, 'type': 'addresses_WT', 'AVXalign': False, 'size': 16}, 'OP': 'LOAD'}
<gen_prepare_buffer>
{'src': {'same': False, 'congruent': 2, 'type': 'addresses_WC_ht'}, 'OP': 'REPM', 'dst': {'same': False, 'congruent': 10, 'type': 'addresses_WC_ht'}}
{'src': {'same': False, 'congruent': 0, 'type': 'addresses_normal_ht'}, 'OP': 'REPM', 'dst': {'same': True, 'congruent': 11, 'type': 'addresses_WC_ht'}}
{'OP': 'STOR', 'dst': {'NT': False, 'same': False, 'congruent': 6, 'type': 'addresses_WT_ht', 'AVXalign': False, 'size': 2}}
{'src': {'NT': False, 'same': False, 'congruent': 8, 'type': 'addresses_WT_ht', 'AVXalign': False, 'size': 8}, 'OP': 'LOAD'}
{'src': {'NT': True, 'same': False, 'congruent': 5, 'type': 'addresses_normal_ht', 'AVXalign': False, 'size': 16}, 'OP': 'LOAD'}
{'src': {'NT': False, 'same': True, 'congruent': 4, 'type': 'addresses_normal_ht', 'AVXalign': False, 'size': 4}, 'OP': 'LOAD'}
{'OP': 'STOR', 'dst': {'NT': False, 'same': False, 'congruent': 10, 'type': 'addresses_normal_ht', 'AVXalign': False, 'size': 4}}
{'src': {'NT': False, 'same': False, 'congruent': 3, 'type': 'addresses_WC_ht', 'AVXalign': True, 'size': 2}, 'OP': 'LOAD'}
{'src': {'same': False, 'congruent': 10, 'type': 'addresses_WT_ht'}, 'OP': 'REPM', 'dst': {'same': False, 'congruent': 2, 'type': 'addresses_normal_ht'}}
{'src': {'NT': False, 'same': False, 'congruent': 11, 'type': 'addresses_WT_ht', 'AVXalign': False, 'size': 4}, 'OP': 'LOAD'}
{'OP': 'STOR', 'dst': {'NT': False, 'same': False, 'congruent': 0, 'type': 'addresses_normal_ht', 'AVXalign': False, 'size': 16}}
{'src': {'same': False, 'congruent': 8, 'type': 'addresses_WT_ht'}, 'OP': 'REPM', 'dst': {'same': False, 'congruent': 0, 'type': 'addresses_WT_ht'}}
{'src': {'NT': False, 'same': False, 'congruent': 8, 'type': 'addresses_normal_ht', 'AVXalign': False, 'size': 4}, 'OP': 'LOAD'}
{'44': 12498, '48': 4506, '49': 406, 'ff': 1, '00': 4412, 'e9': 4, '08': 2}
48 49 00 00 49 44 44 00 44 48 44 48 00 44 44 48 00 44 49 48 44 44 00 48 44 44 44 00 44 48 48 44 44 00 00 44 44 48 44 44 48 44 44 48 44 44 48 44 44 00 44 44 44 49 44 48 00 44 44 48 00 44 44 48 44 44 48 44 00 48 44 44 48 44 44 00 44 44 48 44 48 00 44 44 48 44 44 44 00 44 44 48 44 44 48 00 44 44 00 44 44 48 44 48 00 44 44 00 44 49 00 44 44 48 44 48 00 44 44 48 44 44 00 00 44 44 48 44 44 44 44 00 00 44 44 44 00 44 44 00 44 49 48 44 48 48 44 44 48 00 44 44 48 44 44 48 00 44 44 00 44 44 48 00 44 49 00 44 44 48 44 00 48 44 44 48 00 44 44 00 44 44 48 44 44 00 44 44 00 44 44 00 44 49 48 48 44 44 44 48 44 44 00 44 44 44 00 44 44 44 00 44 48 00 44 48 00 44 44 48 44 48 00 44 44 44 44 48 00 44 48 00 44 48 00 44 44 48 44 44 44 00 44 44 00 44 44 00 44 44 44 44 00 00 44 44 48 44 44 00 44 44 44 44 44 48 00 44 48 00 44 44 00 44 44 48 00 44 48 00 44 49 44 44 48 44 44 48 44 44 44 00 44 44 48 44 44 48 00 44 44 00 44 44 48 44 48 48 44 44 48 00 49 44 00 44 44 48 00 44 44 48 44 44 00 00 44 44 48 49 44 44 44 44 00 00 44 48 00 44 44 00 44 44 48 44 44 48 00 44 44 48 44 44 44 00 44 44 48 44 44 48 00 44 44 48 44 44 48 44 48 00 49 44 00 44 44 48 00 44 48 00 44 48 00 44 44 48 44 44 44 00 44 44 48 44 44 44 44 48 00 44 44 48 44 44 44 00 44 48 48 44 44 48 00 44 44 00 44 44 44 44 48 00 44 44 48 44 44 44 48 00 44 44 00 44 44 44 44 48 44 44 48 00 44 44 00 44 44 48 44 44 48 00 44 44 48 44 44 44 44 44 00 44 44 00 44 44 48 00 44 48 00 44 44 48 44 44 44 00 44 44 48 00 44 48 00 44 48 00 44 49 44 44 44 48 00 44 49 00 44 44 48 44 44 48 44 44 44 44 48 44 44 48 44 44 44 44 48 00 44 44 00 44 48 00 44 44 48 44 44 48 00 44 44 48 44 44 44 00 44 44 48 00 44 48 00 00 44 44 48 44 44 44 00 44 44 48 44 44 44 00 44 44 48 44 44 44 44 48 00 44 44 48 00 44 44 00 44 44 48 44 48 00 44 44 48 00 44 44 00 44 44 48 00 44 48 00 44 44 00 44 44 44 44 44 00 44 44 48 00 44 44 00 44 44 48 44 00 00 44 44 48 44 44 48 44 48 00 44 44 00 44 44 00 44 44 00 00 44 44 00 44 44 00 44 44 00 00 44 44 00 44 44 48 44 44 48 00 44 48 48 44 44 48 00 44 49 00 44 44 48 44 44 48 44 44 48 00 44 44 48 44 44 48 44 48 48 44 44 48 00 44 44 00 44 44 48 44 48 00 44 44 48 00 44 44 00 44 44 48 44 44 48 00 44 44 00 44 49 00 44 44 49 44 48 00 44 44 00 00 44 44 44 49 48 00 44 44 48 44 44 48 00 44 44 00 44 44 44 48 00 44 44 00 44 44 48 00 44 44 48 44 44 48 00 44 44 00 44 44 48 00 44 44 48 44 44 48 44 44 44 00 44 44 48 00 44 48 00 44 44 00 44 48 00 44 44 44 00 44 44 48 44 44 48 00 44 44 48 44 49 48 00 44 44 00 44 44 00 44 44 48 44 48 44 44 48 00 44 48 00 44 44 00 44 44 48 44 48 00 44 44 00 44 48 00 44 44 48 44 44 48 00 44 44 00 44 44 48 44 44 48 44 44 44 00 44 44 00 44 44 44 44 48 00 44 44 00 44 48 00 44 44 44 00 44 44 00 44 48 00 44 44 44 44 48 00 00 44 44 49 48 00 44 48 00 44 44 00 44 44 48 44 44 44 48 44 44 48 00 44 44 48 44 44 48 44 48 00 44 49 00 00 44 44 00 44 44 44 00 44 48 00 44 44 48 44 44 44 44 48 00 44 44 00 44 44 44 48 48 44 44 48 00 44 44 48 44 44 44 00 44 44 48 44 44 48 00 44 49 48 44 44 48 44 44 48 48 44 44 44 48 44 44 00 00 44 44 48
*/
