#include "pin.H"
#include <iostream>
#include <ostream>
#include <fstream>

//ofstream OutFile;
//fstream OutFile;
FILE* OutFile;
using namespace std;

VOID RecordMemoryWriteSize(VOID* addr, UINT32 size)
{
    OutFile << "Write of size " << size << " at address " << addr << endl;
}

VOID Instruction(INS ins, VOID* v)
{
    if (INS_IsMemoryWrite(ins))
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordMemoryWriteSize,
            IARG_MEMORYWRITE_EA,
            IARG_MEMORYWRITE_SIZE,
            IARG_END);
    }
}

VOID Fini(INT32 code, VOID* v)
{
    OutFile->close();
}

int main(int argc, char* argv[])
{
    PIN_InitSymbols();
    if (PIN_Init(argc, argv))
    {
        return 1;
    }

    //ofstream OutFile;

    OutFile.open("memory_writes.txt");

    INS_AddInstrumentFunction(Instruction, 0);

    PIN_AddFiniFunction(Fini, 0);

    PIN_StartProgram();

    return 0;
}
