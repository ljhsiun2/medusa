.global s_prepare_buffers
s_prepare_buffers:
push %r12
push %r8
push %r9
push %rsi
lea addresses_D_ht+0x11d12, %r12
nop
nop
nop
nop
nop
xor %r9, %r9
mov $0x6162636465666768, %r8
movq %r8, %xmm7
vmovups %ymm7, (%r12)
nop
nop
nop
add $7311, %rsi
pop %rsi
pop %r9
pop %r8
pop %r12
ret

    .global s_faulty_load
s_faulty_load:
push %r10
push %r13
push %r9
push %rax
push %rcx
push %rdi

// Store
lea addresses_D+0x4ed2, %r10
clflush (%r10)
xor %rdi, %rdi
mov $0x5152535455565758, %rax
movq %rax, %xmm3
movups %xmm3, (%r10)
nop
nop
nop
nop
nop
sub %rcx, %rcx

// Store
lea addresses_normal+0x6e52, %r13
dec %r10
mov $0x5152535455565758, %rcx
movq %rcx, (%r13)

// Exception!!!
nop
nop
nop
nop
nop
mov (0), %rax
nop
nop
sub $78, %r13

// Store
mov $0x7648eb0000000e52, %r10
nop
nop
nop
nop
nop
xor $55350, %r9
mov $0x5152535455565758, %r13
movq %r13, %xmm4
vmovaps %ymm4, (%r10)
nop
add $16797, %rax

// Faulty Load
mov $0x7648eb0000000e52, %r9
nop
sub $59859, %rax
mov (%r9), %cx
lea oracles, %r13
and $0xff, %rcx
shlq $12, %rcx
mov (%r13,%rcx,1), %rcx
pop %rdi
pop %rcx
pop %rax
pop %r9
pop %r13
pop %r10
ret

/*
<gen_faulty_load>
[REF]
{'OP': 'LOAD', 'src': {'type': 'addresses_NC', 'AVXalign': False, 'congruent': 0, 'size': 2, 'same': True, 'NT': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_D', 'AVXalign': False, 'congruent': 7, 'size': 16, 'same': False, 'NT': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_normal', 'AVXalign': False, 'congruent': 5, 'size': 8, 'same': False, 'NT': False}}
{'OP': 'STOR', 'dst': {'type': 'addresses_NC', 'AVXalign': True, 'congruent': 0, 'size': 32, 'same': True, 'NT': False}}
[Faulty Load]
{'OP': 'LOAD', 'src': {'type': 'addresses_NC', 'AVXalign': False, 'congruent': 0, 'size': 2, 'same': True, 'NT': False}}
<gen_prepare_buffer>
{'OP': 'STOR', 'dst': {'type': 'addresses_D_ht', 'AVXalign': False, 'congruent': 6, 'size': 32, 'same': True, 'NT': False}}
{'58': 2272, '00': 2971}
58 00 00 00 00 00 00 00 00 58 00 00 00 00 58 58 00 00 00 58 58 00 58 58 58 58 00 00 58 00 00 00 00 58 00 00 00 00 58 00 58 58 58 00 00 00 00 00 00 00 58 58 00 00 58 00 58 58 58 00 00 00 58 00 00 58 58 00 58 00 00 00 00 00 00 00 00 58 58 58 00 00 58 00 00 58 58 58 58 00 58 00 00 58 00 00 58 00 00 58 00 00 58 58 58 00 00 58 00 58 58 00 00 00 00 00 00 00 00 58 00 58 00 00 58 00 00 00 58 00 00 00 58 58 00 58 00 58 00 58 58 00 58 58 00 00 58 58 58 58 00 58 58 58 00 58 58 58 58 00 00 58 00 58 00 58 00 00 58 00 00 58 00 00 00 58 00 00 58 58 00 00 58 58 00 00 00 58 00 00 58 58 00 00 00 00 58 00 00 00 00 00 00 58 00 58 00 00 00 58 00 00 00 00 58 00 58 00 58 00 58 00 00 00 58 58 00 00 58 00 58 00 58 58 00 00 00 58 00 58 58 58 58 58 00 00 58 00 00 00 58 58 00 58 00 00 00 00 00 00 00 00 58 00 00 58 58 58 00 00 00 00 00 00 58 00 00 58 00 58 00 00 00 00 00 00 00 00 58 00 58 58 58 00 58 00 58 00 00 00 00 00 58 00 00 58 58 58 58 00 58 58 00 00 00 58 58 00 58 00 00 00 00 00 00 00 58 58 00 00 58 58 58 58 00 00 00 00 00 00 00 58 58 00 58 58 58 00 58 58 00 00 58 00 58 58 00 58 00 00 58 58 58 00 00 58 00 00 58 58 58 58 00 00 58 00 00 00 58 00 58 00 00 00 58 58 00 00 00 58 58 58 58 00 00 00 00 00 00 00 58 00 58 58 58 58 58 00 58 58 00 58 00 00 58 58 00 58 58 00 00 00 00 00 58 00 00 00 00 58 58 00 00 58 00 58 00 00 00 58 00 58 58 00 00 00 58 58 00 58 00 58 58 00 00 58 00 58 00 00 58 00 00 00 00 58 00 00 58 00 00 00 58 58 58 58 58 58 58 58 58 00 00 58 00 00 00 58 58 00 00 00 58 58 58 58 00 00 00 00 00 00 00 58 00 58 58 58 00 00 00 00 58 00 58 00 00 58 00 00 58 00 58 58 58 58 00 58 00 00 00 58 00 00 00 00 00 58 00 58 00 58 58 58 00 00 00 00 00 58 58 58 00 00 00 00 00 58 58 00 00 00 00 58 58 00 00 58 58 00 00 00 00 00 00 58 58 58 58 00 58 58 00 00 58 58 58 58 58 58 58 00 58 00 58 00 58 58 00 00 58 00 00 00 58 00 58 00 58 58 00 58 00 00 00 58 58 58 00 58 58 58 00 00 00 58 00 00 58 00 58 00 00 00 00 00 00 58 00 00 58 58 00 00 58 00 58 00 00 00 58 00 58 58 00 58 58 58 00 00 58 00 00 58 00 00 00 00 00 58 58 58 58 00 00 00 00 00 00 00 00 58 00 00 00 58 00 00 58 00 00 00 58 58 58 00 00 58 58 58 00 00 00 58 00 00 58 58 00 58 58 58 00 58 00 00 00 58 00 00 58 00 00 00 00 58 00 58 00 00 00 58 00 00 58 58 00 58 00 58 58 58 58 00 58 58 00 00 58 58 58 00 00 00 00 00 00 58 00 00 00 00 58 00 00 58 58 58 00 00 58 58 00 00 00 00 00 58 00 58 58 58 00 58 58 58 58 58 58 00 58 00 58 58 58 58 00 58 00 58 00 00 58 00 58 58 58 58 00 00 00 00 58 00 58 00 00 58 58 58 58 58 58 00 00 00 00 58 00 00 00 00 58 58 00 00 58 00 00 58 00 58 58 00 00 00 00 58 00 00 00 58 58 58 58 00 00 00 58 00 00 00 00 00 58 00 58 58 00 58 58 58 00 00 58 00 58 58 00 58 58 58 00 00 58 58 00 58 58 00 00 00 58 00 58 00 58 00 00 00 58 00 58 00 00 58 00 58 58 00 00 00 58 00 00 58 00 00 00 58 00 58 00 58 58 58 00 00 00 00 58 58 00 58 58 58 58 58 58 58 58 00 00 58 00 00 00 00 00 00 00 00 58 58 00 58 00 00 00 00 00 00 00 58 58 00 58 58 00 00 00 00 58 58 58 58 00 00 58 00 00 58 00 58 58 00 00 58 00 58 00 00 00 00 00 58 00 00 00 00
*/
