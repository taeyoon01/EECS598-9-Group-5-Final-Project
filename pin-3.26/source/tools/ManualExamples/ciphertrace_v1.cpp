/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

/*
 *  This file contains an ISA-portable PIN tool for tracing memory accesses.
 */

#include <stdio.h>
#include "pin.H"

FILE* trace;
bool prevIsWrite = false;
VOID* prevInst = 0;
VOID* prevMem = 0;

VOID printInst(UINT64 instAddr, std::string instDisasm) {
    if (prevIsWrite) {
        UINT64 value;
        PIN_SafeCopy(&value, reinterpret_cast<UINT64*>(prevMem), sizeof(UINT64));
        fprintf(trace, "PC %p MEM %p W VAL %lx\n", prevInst, prevMem, value);
        prevIsWrite = false;
    }
    fprintf(trace, "[%lx] %s\n", instAddr, instDisasm.c_str());
}

// Print a memory read record
VOID RecordMemRead(VOID* ip, VOID* addr) {
    UINT64 value;
    PIN_SafeCopy(&value, reinterpret_cast<UINT64*>(addr), sizeof(UINT64));
    fprintf(trace, "PC %p MEM %p R VAL %lx\n", ip, addr, value);
}

// Print a memory write record
VOID RecordMemWrite(VOID* ip, VOID* addr) {
    prevIsWrite = true;
    prevInst = ip;
    prevMem = addr;
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
    for (UINT32 memOp = 0; memOp < memOperands; memOp++)
    {
        if (INS_MemoryOperandIsRead(ins, memOp))
        {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead, IARG_INST_PTR, IARG_MEMORYOP_EA, memOp,
                                     IARG_END);
        }
        // Note that in some architectures a single memory operand can be
        // both read and written (for instance incl (%eax) on IA-32)
        // In that case we instrument it once for read and once for write.
        if (INS_MemoryOperandIsWritten(ins, memOp))
        {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite, IARG_INST_PTR, IARG_MEMORYOP_EA, memOp,
                                     IARG_END);
        }
    }
}

VOID LogAllMemAcc(VOID* ip, ADDRINT addr, UINT32 size, BOOL isWrite) {
    UINT64 value;
    PIN_SafeCopy(&value, reinterpret_cast<UINT64*>(addr), sizeof(UINT64));
    fprintf(trace, "%p %lx %lx\n", ip, addr, value);
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

    trace = fopen("ciphertrace_v1.out", "w");

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns
    PIN_StartProgram();

    return 0;
}
