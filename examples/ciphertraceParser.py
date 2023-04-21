import sys
filename = sys.argv[1]

accessTable = {}
with open(filename, 'r') as f:
    for line in f.readlines():
        terms = line.split()
        if len(terms) == 7:
            _, pc, _, mem, rwType, _, val = terms
            if rwType != 'W': continue
            pc = int(pc, 16)
            mem = int(mem, 16)
            val = int(val, 16)
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