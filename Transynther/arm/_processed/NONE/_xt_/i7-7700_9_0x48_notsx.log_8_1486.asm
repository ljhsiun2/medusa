.global s_prepare_buffers
s_prepare_buffers:
push %r12
push %r13
push %rax
push %rbx
push %rcx
push %rdi
push %rsi
lea addresses_UC_ht+0x2709, %rsi
lea addresses_UC_ht+0x1b509, %rdi
clflush (%rsi)
nop
nop
nop
nop
nop
cmp $37381, %rbx
mov $21, %rcx
rep movsb
nop
nop
nop
nop
nop
and $34121, %r13
lea addresses_normal_ht+0x19c27, %r12
nop
nop
nop
nop
nop
cmp %rax, %rax
mov $0x6162636465666768, %r13
movq %r13, (%r12)
nop
nop
nop
dec %rsi
lea addresses_WT_ht+0x2f19, %rdi
clflush (%rdi)
nop
nop
nop
nop
nop
dec %r12
movb $0x61, (%rdi)
nop
nop
nop
nop
cmp %rax, %rax
lea addresses_WC_ht+0x14a09, %rdi
nop
nop
nop
sub %rax, %rax
mov $0x6162636465666768, %rsi
movq %rsi, %xmm7
movups %xmm7, (%rdi)
nop
nop
sub $57623, %rax
lea addresses_WC_ht+0x1f89, %rax
nop
nop
nop
nop
cmp %r13, %r13
movups (%rax), %xmm6
vpextrq $1, %xmm6, %rdi
nop
add %r13, %r13
pop %rsi
pop %rdi
pop %rcx
pop %rbx
pop %rax
pop %r13
pop %r12
ret

    .global s_faulty_load
s_faulty_load:
push %r10
push %r12
push %r13
push %r15
push %rax
push %rcx
push %rsi

// Store
mov $0x361d160000000d09, %rcx
nop
nop
nop
and %rax, %rax
mov $0x5152535455565758, %r15
movq %r15, %xmm3
vmovups %ymm3, (%rcx)

// Exception!!!
nop
nop
mov (0), %rax
nop
nop
nop
and $54321, %r13

// Store
lea addresses_WC+0x1b229, %rsi
nop
sub %r12, %r12
mov $0x5152535455565758, %r15
movq %r15, %xmm3
vmovups %ymm3, (%rsi)
nop
dec %r13

// Faulty Load
lea addresses_D+0x1a909, %r10
nop
nop
nop
nop
dec %rcx
movups (%r10), %xmm0
vpextrq $0, %xmm0, %rax
lea oracles, %rcx
and $0xff, %rax
shlq $12, %rax
mov (%rcx,%rax,1), %rax
pop %rsi
pop %rcx
pop %rax
pop %r15
pop %r13
pop %r12
pop %r10
ret

/*
<gen_faulty_load>
[REF]
{'OP': 'LOAD', 'src': {'same': False, 'NT': False, 'AVXalign': False, 'size': 1, 'type': 'addresses_D', 'congruent': 0}}
{'dst': {'same': False, 'NT': False, 'AVXalign': False, 'size': 32, 'type': 'addresses_NC', 'congruent': 10}, 'OP': 'STOR'}
{'dst': {'same': False, 'NT': False, 'AVXalign': False, 'size': 32, 'type': 'addresses_WC', 'congruent': 1}, 'OP': 'STOR'}
[Faulty Load]
{'OP': 'LOAD', 'src': {'same': True, 'NT': False, 'AVXalign': False, 'size': 16, 'type': 'addresses_D', 'congruent': 0}}
<gen_prepare_buffer>
{'dst': {'same': False, 'congruent': 9, 'type': 'addresses_UC_ht'}, 'OP': 'REPM', 'src': {'same': False, 'congruent': 9, 'type': 'addresses_UC_ht'}}
{'dst': {'same': False, 'NT': True, 'AVXalign': False, 'size': 8, 'type': 'addresses_normal_ht', 'congruent': 0}, 'OP': 'STOR'}
{'dst': {'same': False, 'NT': False, 'AVXalign': False, 'size': 1, 'type': 'addresses_WT_ht', 'congruent': 3}, 'OP': 'STOR'}
{'dst': {'same': False, 'NT': False, 'AVXalign': False, 'size': 16, 'type': 'addresses_WC_ht', 'congruent': 3}, 'OP': 'STOR'}
{'OP': 'LOAD', 'src': {'same': True, 'NT': False, 'AVXalign': False, 'size': 16, 'type': 'addresses_WC_ht', 'congruent': 7}}
{'36': 8}
36 36 36 36 36 36 36 36
*/
