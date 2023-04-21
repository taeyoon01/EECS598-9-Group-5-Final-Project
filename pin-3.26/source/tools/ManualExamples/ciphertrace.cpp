/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

/*
 *  This file contains an ISA-portable PIN tool for tracing memory accesses.
 */

#include <stdio.h>
#include <vector>
#include "pin.H"

FILE* trace;
bool prevIsWrite = false;
VOID* prevInst = 0;
VOID* prevMem = 0;
UINT32 prevSize = 0;

VOID printInst(UINT64 instAddr, std::string instDisasm) {
    if (prevIsWrite) {
        UINT64 value;
        PIN_SafeCopy(&value, reinterpret_cast<UINT64*>(prevMem), sizeof(UINT64));
        fprintf(trace, "PC %p MEM %p W VAL %lx SIZE %d\n", prevInst, prevMem, value, prevSize);
        prevIsWrite = false;
    }
    // fprintf(trace, "[%lx] %s\n", instAddr, instDisasm.c_str());
    fprintf(trace, "[%lx]\n", instAddr);
}

// Print a memory read record
VOID RecordMemRead(VOID* ip, VOID* addr, UINT32 size) {
    UINT64 value;
    PIN_SafeCopy(&value, reinterpret_cast<UINT64*>(addr), sizeof(UINT64));
    fprintf(trace, "PC %p MEM %p R VAL %lx SIZE %d\n", ip, addr, value, size);
}

// Print a memory write record
VOID RecordMemWrite(VOID* ip, VOID* addr, UINT32 size) {
    prevIsWrite = true;
    prevInst = ip;
    prevMem = addr;
    prevSize = size;
}

VOID PrintRoutineInfo(VOID* imgName, VOID* rtnName, ADDRINT addr, UINT64 size) {
    fprintf(trace, "RTN %s %s %lx %lx\n", (char*)imgName, (char*)rtnName, addr, size);
}

VOID Routine(RTN rtn, VOID* v) {
    ADDRINT rtnAddr = RTN_Address(rtn);
    IMG imgHome = IMG_FindByAddress(rtnAddr);
    const char* rtnName = RTN_Name(rtn).c_str();
    const char* imgName = IMG_Name(imgHome).c_str();
    PrintRoutineInfo((VOID*)imgName, (VOID*)rtnName, rtnAddr, RTN_Size(rtn));

    /* RTN_Open(rtn);
    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)PrintRoutineInfo,
		   IARG_PTR, (VOID*)imgName,
		   IARG_PTR, (VOID*)rtnName,
		   IARG_ADDRINT, rtnAddr,
		   IARG_UINT64, RTN_Size(rtn),
		   // IARG_UINT64, RTN_Range(rtn),
		   IARG_END);
    RTN_Close(rtn); */
}

// Is called for every instruction and instruments reads and writes
VOID Instruction(INS ins, VOID* v)
{
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printInst,
		   IARG_ADDRINT, INS_Address(ins),
		   IARG_PTR, new std::string(INS_Disassemble(ins)),
		   IARG_END);

    // Instruments memory accesses using a predicated call, i.e.
    // the instrumentation is called iff the instruction will actually be executed.
    //
    // On the IA-32 and Intel(R) 64 architectures conditional moves and REP
    // prefixed instructions appear as predicated instructions in Pin.
    UINT32 memOperands = INS_MemoryOperandCount(ins);

    // Iterate over each memory operand of the instruction.
    for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
        if (INS_MemoryOperandIsRead(ins, memOp)) {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
			             IARG_INST_PTR,
				     IARG_MEMORYOP_EA, memOp,
				     IARG_MEMORYREAD_SIZE,
                                     IARG_END);
        }
        // Note that in some architectures a single memory operand can be
        // both read and written (for instance incl (%eax) on IA-32)
        // In that case we instrument it once for read and once for write.
        if (INS_MemoryOperandIsWritten(ins, memOp)) {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
			             IARG_INST_PTR,
				     IARG_MEMORYOP_EA, memOp,
				     IARG_MEMORYWRITE_SIZE,
                                     IARG_END);
        }
    }
}

VOID Fini(INT32 code, VOID* v)
{
    fprintf(trace, "#eof\n");
    fclose(trace);
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    PIN_ERROR("This Pintool prints a trace of memory addresses\n" + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[])
{
    if (PIN_Init(argc, argv)) return Usage();

    trace = fopen("ciphertrace.out", "w");

    PIN_InitSymbols();
    RTN_AddInstrumentFunction(Routine, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();

    return 0;
}
