.global s_prepare_buffers
s_prepare_buffers:
push %r10
push %r13
push %r9
push %rcx
push %rdi
push %rsi
lea addresses_UC_ht+0xb182, %rsi
lea addresses_UC_ht+0xe626, %rdi
nop
nop
nop
nop
inc %r13
mov $99, %rcx
rep movsb
nop
nop
dec %r10
lea addresses_A_ht+0x2ba6, %rsi
lea addresses_WT_ht+0x1d3a6, %rdi
clflush (%rsi)
clflush (%rdi)
nop
xor %r9, %r9
mov $18, %rcx
rep movsq
and $36758, %r9
pop %rsi
pop %rdi
pop %rcx
pop %r9
pop %r13
pop %r10
ret

    .global s_faulty_load
s_faulty_load:
push %r10
push %r8
push %rbx
push %rdx
push %rsi

// Faulty Load
lea addresses_A+0x3a6, %rsi
nop
add $25307, %rbx
vmovups (%rsi), %ymm7
vextracti128 $0, %ymm7, %xmm7
vpextrq $1, %xmm7, %rdx
lea oracles, %rsi
and $0xff, %rdx
shlq $12, %rdx
mov (%rsi,%rdx,1), %rdx
pop %rsi
pop %rdx
pop %rbx
pop %r8
pop %r10
ret

/*
<gen_faulty_load>
[REF]
{'OP': 'LOAD', 'src': {'type': 'addresses_A', 'size': 8, 'AVXalign': False, 'NT': False, 'congruent': 0, 'same': False}}
[Faulty Load]
{'OP': 'LOAD', 'src': {'type': 'addresses_A', 'size': 32, 'AVXalign': False, 'NT': False, 'congruent': 0, 'same': True}}
<gen_prepare_buffer>
{'OP': 'REPM', 'src': {'type': 'addresses_UC_ht', 'congruent': 2, 'same': True}, 'dst': {'type': 'addresses_UC_ht', 'congruent': 7, 'same': False}}
{'OP': 'REPM', 'src': {'type': 'addresses_A_ht', 'congruent': 10, 'same': False}, 'dst': {'type': 'addresses_WT_ht', 'congruent': 11, 'same': False}}
{'35': 21829}
35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35 35
*/
