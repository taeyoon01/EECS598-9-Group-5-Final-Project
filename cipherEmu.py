import sys
import time
import angr
import random
from unicorn import *
from unicorn.x86_const import *
assert(len(sys.argv) > 1)
binaryName = sys.argv[1]

random.seed(0xF0F0F0F0)
class GetTime(angr.SimProcedure):
    def run(self):
        timestamp = round(time.time() * 1000)
        return timestamp

p = angr.Project(binaryName)
print('%08x' % p.entry)
print(p.loader.shared_objects)

p.hook_symbol('clock_gettime', GetTime())
@p.hook(0x004330dd, length=4)
def rdrand0(state):
    rNum = random.randrange(0, 2 ** 64)
    state.regs.rdi = rNum
    state.regs.rflags = 1
@p.hook(0x004337a0, length=4)
def rdrand1(state):
    rNum = random.randrange(0, 2 ** 64)
    state.regs.rdi = rNum
    state.regs.rflags = 1
@p.hook(0x004331f3, length=2)
def syscall0(state):
    print('syscall intercepted:', state.regs.rax)
    state.regs.rax = 0
@p.hook(0x0043377a, length=2)
def syscall1(state):
    print('syscall intercepted:', state.regs.rax)
    state.regs.rax = 0

entryState = p.factory.entry_state()
simgr = p.factory.simgr(entryState)
ctr = 0
while len(simgr.active):
    print(ctr)
    for s in simgr.active:
        print('%08x' % s.addr)
        bb = p.factory.block(s.addr)
        bb.pp()
    simgr.step()
    ctr += 1
print(simgr)
for s in simgr.deadended: print(s.posix.dumps(1))

uc = Uc(UC_ARCH_X86, UC_MODE_64)
# uc.mem_map()
# uc.mem_write()
