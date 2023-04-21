import re
import sys
import subprocess
assert(len(sys.argv) > 2) # PIN-TOOL-generated_trace x1 instrumented_images xN
PIN_ROOT = '~/Desktop/cipherTee/pin-3.27-98718-gbeaa5d51e-gcc-linux'
hexReg = re.compile('^[a-fA-F0-9]+$')

maskPatterns = [('mov', '%r11,%r11'), ('mov', '%r13,%r13'), ('mov', '%r12,%r12'),
            ('mov', '%r13,%r13'), ('mov', '%r11,%r11'), ('mov', '%r13,%r13')]
maskState = 5
def identifyMasked(line):
    global maskState
    terms = line.split()
    action = ''
    if len(terms) < 4: maskState = 5
    else:
        ptn = (terms[-2], terms[-1])
        if (maskState == 1) and (ptn == maskPatterns[2]): action = 'on'
        elif (maskState == 2) and (ptn == maskPatterns[3]): action = 'off'
        if ptn == maskPatterns[(maskState + 1) % 6]: maskState = (maskState + 1) % 6
        else: maskState = (2 if maskState == 2 else 5)
    return action

def disasmImages(imageNames):
    disasms = {}
    for img in imageNames:
        imgDisasm = subprocess.run(['objdump', '-drwC', img], capture_output=True).stdout
        imgDisasm = imgDisasm.decode()
        disasms[img] = imgDisasm
        disasmFileName = '%s.objdump.disasm' % img.strip('./').replace('.', '-').replace('/', '-')
        with open(disasmFileName, 'w') as f: f.write(imgDisasm)
    return disasms

def registerRoutines(disasms):
    routines = {}
    idCounter = {}
    for imgPath in disasms:
        imgName = (imgPath.split('/'))[-1]
        disasmLines = disasms[imgPath].split('\n')
        protected = False
        for line in disasmLines:
            terms = line.split()

            if (len(terms) == 2) and (len(terms[0]) == 16) and (hexReg.match(terms[0]) != None):
                routineOffset, routineName = terms
                routineOffset = int(routineOffset, 16)
                routineName = routineName.strip('<>:')
                routineId = imgName + '/' + routineName

                if routineId not in idCounter: idCounter[routineId] = 0
                idCounter[routineId] += 1
                routineId += '/' + str(idCounter[routineId])
                routines[routineId] = { 'offset': routineOffset, '.inst': protected,
                                        'start': None, 'end': None, 'masked': [] }

            elif ('section' in line) and ('.instr.text' in line):
                protected = True

            else:
                action = identifyMasked(line)
                if action == 'on':
                    maskStart = int(terms[0].strip(':'), 16) # exclude
                elif action == 'off':
                    maskEnd = int(terms[0].strip(':'), 16) # exclude
                    routines[routineId]['masked'].append((maskStart, maskEnd))

    return routines

def matchDisasmTrace(traceName, routines):
    idCounter = {}    
    with open(traceName, 'r') as f:
        for line in f.readlines():
            terms = line.split()

            if line.startswith('RTN'):
                _, imageName, routineName, physicalAddress, routineSize = terms
                imageName = (imageName.split('/'))[-1]
                physicalAddress = int(physicalAddress, 16)
                routineSize = int(routineSize, 16)
                routineId = imageName + '/' + routineName

                if routineId not in idCounter: idCounter[routineId] = 0
                idCounter[routineId] += 1
                routineId += '/' + str(idCounter[routineId])
                if routineId in routines:
                    routines[routineId]['start'] = physicalAddress
                    routines[routineId]['end'] = physicalAddress + routineSize
                else:
                    # print('[WARNING] matchDisasmTrace: unexpected symbol %s' % routineId)
                    routines[routineId] = { 'offset': physicalAddress, '.inst': False,
                                            'start': physicalAddress,
                                            'end': physicalAddress + routineSize,
                                            'masked': [] }
    return routines

def recordMemoryAccess(traceName, routines):
    rtnNow, programStart, protected = '', 0, False
    memoryAccessTable = {}
    with open(traceName, 'r') as f:
        for line in f.readlines():
            terms = line.split()

            if (len(terms) == 9) and (terms[4] == 'W'):
                _, pc, _, mem, rwType, _, val, _, size = terms
                pc, mem, val, size = int(pc, 16), int(mem, 16), int(val, 16), int(size)
                pc -= programStart
                # SPECIFIC TO CIPHERH + CIPHERFIX: start
                if (not protected) or (size > 1): continue
                for maskStart, maskEnd in routines[rtnNow]['masked']:
                    if (pc > maskStart) and (pc < maskEnd): break
                else: continue
                # SPECIFIC TO CIPHERH + CIPHERFIX: end
                if mem not in memoryAccessTable: memoryAccessTable[mem] = {}
                if val not in memoryAccessTable[mem]: memoryAccessTable[mem][val] = []
                memoryAccessTable[mem][val].append((rtnNow, pc, size))

            elif line.startswith('['):
                pc = int(terms[0].strip('[]'), 16)
                if len(rtnNow):
                    if (pc >= routines[rtnNow]['start']) and (pc < routines[rtnNow]['end']): continue
                for routineId in routines:
                    rStart, rEnd = routines[routineId]['start'], routines[routineId]['end']
                    if rStart == None: continue
                    if (pc >= rStart) and (pc < rEnd):
                        rtnNow = routineId
                        programStart = rStart - routines[routineId]['offset']
                        protected = routines[routineId]['.inst']
                        break
                else:
                    # print('[WARNING] parseTrace: homeless instruction @ %08x' % pc)
                    rtnNow, programStart, protected = '', 0, False

    return memoryAccessTable

def parseTrace(traceName, routines):
    matchDisasmTrace(traceName, routines)
    memoryAccessTable = recordMemoryAccess(traceName, routines)
    return memoryAccessTable

def findCollisions(table):
    collisions = {}
    for m in table:
        collided = False
        if len(table[m]) < 2: continue
        for v in table[m]:
            if len(table[m][v]) > 1:
                collided = True
                if m not in collisions: collisions[m] = {}
                collisions[m][v] = table[m][v]

        if collided:
            print('-' * 16)
            print('[COLLISION] MEM %08x' % m)
            for v in table[m]:
                pcsInHex = [ ('%s/%08x/%d-byte' % (rtn, pc, size)) for rtn, pc, size in table[m][v] ]
                print('VAL %08x PC %s' % (v, ' '.join(pcsInHex)))
            print('-' * 16)
    return collisions


print('Disassemble main + shared objects ...')
disasmTexts = disasmImages(sys.argv[2 : ])
print('Register all routines found ...')
routineDB = registerRoutines(disasmTexts)
print('Parse the program execution trace ...')
memoryAccesses = parseTrace(sys.argv[1], routineDB)
print('Identify interesting collisions ...')
foundCollisions = findCollisions(memoryAccesses)

