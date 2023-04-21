import re
import sys
diffName = sys.argv[1]
traceName = sys.argv[2]

weakOps = {}
pattern = r'^[a-z0-9]+$'
with open(diffName, 'r') as f:
    for line in f.readlines():
        if line.startswith('<'):
            terms = line.split()
            if len(terms) >= 4:
                offset = terms[1]
                offset.strip(':')
                if re.match(pattern, offset) != None:
                    offset = int(offset, 16)
                    weakOps[offset] = True

accessTable = {}
with open(traceName, 'r') as f:
    for line in f.readlines():
        terms = line.split()
        if len(terms) == 7:
            _, pc, _, mem, rwType, _, val = terms
            if rwType != 'W': continue
            pc, mem, val = int(pc, 16), int(mem, 16), int(val, 16)
            pc -= 0x7fa7915b5000 # automated this offset search!
            if pc < 0x33000: continue # automated this offset search!
            if pc > 0x36157: continue # automated this offset search!
            if mem not in accessTable: accessTable[mem] = {}
            if val not in accessTable[mem]: accessTable[mem][val] = []
            accessTable[mem][val].append(pc)

for m in accessTable:
    noCollisions = True
    if len(accessTable[m]) > 1:
        for v in accessTable[m]:
            if len(accessTable[m][v]) > 1:
                noCollisions = False
                break
    if not noCollisions:
        print('-' * 16)
        print('[Collisions] MEM %08x' % m)
        for v in accessTable[m]:
            print('VAL %08x' % v)
            hexPCs = [ '%08x' % pc for pc in accessTable[m][v] ]
            print('PC', hexPCs)
        print('-' * 16)
