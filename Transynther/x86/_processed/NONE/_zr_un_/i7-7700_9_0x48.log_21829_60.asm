.global s_prepare_buffers
s_prepare_buffers:
push %r10
push %r11
push %r13
push %r8
push %rbx
push %rcx
push %rdi
lea addresses_normal_ht+0x73ea, %r10
clflush (%r10)
nop
nop
nop
nop
nop
sub $45643, %rcx
mov (%r10), %r13d
cmp %r10, %r10
lea addresses_UC_ht+0x15aaa, %r8
nop
nop
nop
and $28981, %rbx
movw $0x6162, (%r8)
nop
xor $57599, %r13
lea addresses_WC_ht+0xe4a, %rdi
nop
nop
add %r11, %r11
mov $0x6162636465666768, %rbx
movq %rbx, %xmm7
vmovups %ymm7, (%rdi)
xor %r8, %r8
pop %rdi
pop %rcx
pop %rbx
pop %r8
pop %r13
pop %r11
pop %r10
ret

    .global s_faulty_load
s_faulty_load:
push %r12
push %r13
push %r14
push %r15
push %rax
push %rbp
push %rdi

// Store
lea addresses_normal+0x1976a, %r12
add $21384, %r14
movb $0x51, (%r12)
nop
nop
nop
cmp $51511, %r14

// Faulty Load
lea addresses_UC+0x87ea, %rdi
nop
cmp %r15, %r15
vmovups (%rdi), %ymm2
vextracti128 $1, %ymm2, %xmm2
vpextrq $1, %xmm2, %r14
lea oracles, %r12
and $0xff, %r14
shlq $12, %r14
mov (%r12,%r14,1), %r14
pop %rdi
pop %rbp
pop %rax
pop %r15
pop %r14
pop %r13
pop %r12
ret

/*
<gen_faulty_load>
[REF]
{'OP': 'LOAD', 'src': {'type': 'addresses_UC', 'AVXalign': False, 'congruent': 0, 'size': 1, 'same': False, 'NT': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_normal', 'AVXalign': False, 'congruent': 7, 'size': 1, 'same': False, 'NT': False}}
[Faulty Load]
{'OP': 'LOAD', 'src': {'type': 'addresses_UC', 'AVXalign': False, 'congruent': 0, 'size': 32, 'same': True, 'NT': False}}
<gen_prepare_buffer>
{'OP': 'LOAD', 'src': {'type': 'addresses_normal_ht', 'AVXalign': False, 'congruent': 9, 'size': 4, 'same': False, 'NT': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_UC_ht', 'AVXalign': False, 'congruent': 5, 'size': 2, 'same': False, 'NT': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_WC_ht', 'AVXalign': False, 'congruent': 5, 'size': 32, 'same': True, 'NT': False}}
{'08': 3110, '00': 15732, '72': 2986, '04': 1}
04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 72 72 72 08 72 72 08 72 00 00 08 00 08 00 08 00 00 08 00 08 00 00 00 00 00 00 00 00 00 00 00 08 00 00 08 00 00 00 08 08 00 00 08 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 72 08 08 72 08 00 00 72 00 00 00 72 00 00 00 00 00 00 00 00 72 00 00 00 72 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 72 08 72 72 72 08 72 72 00 00 00 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 08 00 08 08 00 00 00 00 00 00 00 00 00 08 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 72 72 72 72 72 72 72 08 08 72 72 72 72 72 72 72 72 08 72 72 72 72 72 72 72 00 00 00 00 00 00 00 08 00 00 00 08 00 08 00 00 00 00 00 08 08 08 00 00 08 00 00 00 00 00 00 00 08 00 00 00 00 08 00 00 00 00 00 00 00 00 08 72 72 72 08 72 72 72 72 72 72 72 72 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 08 08 08 00 00 00 00 00 00 00 00 00 72 00 00 00 00 00 00 00 72 00 72 00 00 00 00 00 00 72 00 72 00 00 00 00 72 00 72 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 72 00 72 00 72 00 00 00 72 00 00 00 72 00 00 72 00 00 00 00 00 00 00 00 00 00 00 72 72 72 00 72 00 00 00 72 00 00 00 00 00 00 00 00 72 00 00 00 00 00 00 00 00 00 00 72 72 00 00 00 00 00 72 00 00 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 08 00 00 08 00 00 08 00 00 00 00 00 08 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 00 00 72 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 08 08 72 08 08 08 00 00 00 72 00 72 00 72 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 72 72 08 72 08 08 08 08 72 72 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 72 72 72 72 00 00 00 00 00 00 00 00 00 08 00 08 00 08 00 00 00 00 00 00 00 00 00 00 00 00 08 00 00 00 00 08 00 00 00 00 08 00 00 00 00 08 08 08 00 08 00 00 00 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 72 08 08 08 72 08 08 08 08 08 08 00 08 08 08 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 72 72 08 08 00 00 00 00 00 00 00 72 00 00 00 00 72 00 72 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
*/
