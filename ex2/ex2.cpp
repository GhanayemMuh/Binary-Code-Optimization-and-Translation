#include <iomanip>
#include <fstream>
#include <iostream>
#include "pin.H"
#include <string.h>
using namespace std;

typedef struct RoutineInfo {
    string name;
    ADDRINT address;
    UINT64 instructionCount;
    UINT64 executionCount;
} RoutineData;

typedef struct LoopInfo {
    ADDRINT loopAddress;
    ADDRINT targetLoopAddress;
    UINT64 lastIteration;
    UINT64 iterationCount;
    UINT64 loopInvocationCount;
    UINT64 loopSeenCount;
    UINT64 mean;
    UINT64 diffCount;
    string routineName;
    ADDRINT routineAddress;
    UINT64 routineInstructionCount;
    UINT64 routineExecutionCount;
} LoopData;

std::map<std::string, RoutineData*> routineList;
std::map<ADDRINT, LoopData*> loopList;

VOID IncreaseLoop(UINT64* iteration, UINT64* loopInvocationCount, BOOL toBranch, UINT64* lastIteration, UINT64* diffCount, UINT64* loopSeenCount, UINT64* mean);
VOID IncreaseRoutineExecutionCount(string routineName);
VOID CountInstructions(INS ins, VOID* v);
VOID RoutineInstrumentation(RTN routine, VOID* v);
VOID ProgramFini(INT32 code, VOID* v);

bool CompareLoops(const pair<ADDRINT, LoopData*>& firstLoop, const pair<ADDRINT, LoopData*>& secondLoop)
{
    return firstLoop.second->loopSeenCount > secondLoop.second->loopSeenCount;
}

int main(int argc, char* argv[])
{
    PIN_InitSymbols();
    PIN_Init(argc, argv);
    INS_AddInstrumentFunction(CountInstructions, 0);
    RTN_AddInstrumentFunction(RoutineInstrumentation, 0);
    PIN_AddFiniFunction(ProgramFini, 0);
    PIN_StartProgram();
    return 0;
}

VOID CountInstructions(INS ins, VOID* v)
{
    RoutineData* routineData = routineList[RTN_FindNameByAddress(INS_Address(ins))];
    if (routineData != nullptr) {
        routineData->instructionCount++;
    }
}

VOID RoutineInstrumentation(RTN routine, VOID* v)
{
    RoutineData* currentRoutine = new RoutineData;
    currentRoutine->name = RTN_Name(routine);
    currentRoutine->address = RTN_Address(routine);
    currentRoutine->instructionCount = 0;
    currentRoutine->executionCount = 0;
    routineList[currentRoutine->name] = currentRoutine;

    RTN_Open(routine);

    for (INS instruction = RTN_InsHead(routine); INS_Valid(instruction); instruction = INS_Next(instruction))
    {
        INS_InsertCall(instruction, IPOINT_BEFORE, (AFUNPTR)IncreaseRoutineExecutionCount,
            IARG_PTR, new string(currentRoutine->name),
            IARG_END);

        if ((INS_IsDirectBranch(instruction) && INS_HasFallThrough(instruction)) && (INS_DirectControlFlowTargetAddress(instruction) < INS_Address(instruction)))
        {
            std::map<ADDRINT, LoopData*>::iterator iterator;
            iterator = loopList.find(INS_Address(instruction));

            if (iterator == loopList.end())
            {
                LoopData* currentLoop = new LoopData;
                currentLoop->loopAddress = INS_Address(instruction);
                currentLoop->targetLoopAddress = INS_DirectControlFlowTargetAddress(instruction);
                currentLoop->lastIteration = 0;
                currentLoop->iterationCount = 0;
                currentLoop->loopInvocationCount = 0;
                currentLoop->loopSeenCount = 0;
                currentLoop->mean = 0;
                currentLoop->diffCount = 0;
                currentLoop->routineName = currentRoutine->name;
                currentLoop->routineAddress = currentRoutine->address;
                currentLoop->routineInstructionCount = currentRoutine->instructionCount;
                currentLoop->routineExecutionCount = currentRoutine->executionCount;
                loopList[INS_Address(instruction)] = currentLoop;
            }

            INS_InsertCall(instruction, IPOINT_BEFORE, (AFUNPTR)IncreaseLoop,
                IARG_PTR, &(loopList[INS_Address(instruction)]->iterationCount),
                IARG_PTR, &(loopList[INS_Address(instruction)]->loopInvocationCount),
                IARG_BRANCH_TAKEN,
                IARG_PTR, &(loopList[INS_Address(instruction)]->lastIteration),
                IARG_PTR, &(loopList[INS_Address(instruction)]->diffCount),
                IARG_PTR, &(loopList[INS_Address(instruction)]->loopSeenCount),
                IARG_PTR, &(loopList[INS_Address(instruction)]->mean),
                IARG_END);
        }
    }

    RTN_Close(routine);
}

VOID IncreaseLoop(UINT64* iteration, UINT64* loopInvocationCount, BOOL toBranch, UINT64* lastIteration, UINT64* diffCount, UINT64* loopSeenCount, UINT64* mean)
{
    (*loopSeenCount)++;
    (*iteration)++;

    if (!toBranch)
    {
        if (*lastIteration != *iteration)
        {
            if (*lastIteration != 0)
            {
                (*diffCount)++;
            }
        }

        (*loopInvocationCount)++;
        (*lastIteration) = (*iteration);
        (*iteration) = 0;
        (*mean) = ((*mean) * ((*loopInvocationCount) - 1) + (*lastIteration)) / (*loopInvocationCount);
    }
}

VOID IncreaseRoutineExecutionCount(string routineName)
{
    RoutineData* routineData = routineList[routineName];
    if (routineData != nullptr) {
        routineData->executionCount++;
    }
}

VOID ProgramFini(INT32 code, VOID* v)
{
    ofstream output;
    output.open("loop-count.csv");

    std::map<ADDRINT, LoopData*>::iterator loopIterator;

    for (loopIterator = loopList.begin(); loopIterator != loopList.end(); loopIterator++)
    {
        std::map<string, RoutineData*>::iterator routineIterator = routineList.find(loopIterator->second->routineName);
        loopIterator->second->routineInstructionCount = routineIterator->second->instructionCount;
        loopIterator->second->routineExecutionCount = routineIterator->second->executionCount;
    }

    std::vector<std::pair<ADDRINT, LoopData*>> sortedLoops(loopList.begin(), loopList.end());
    std::sort(sortedLoops.begin(), sortedLoops.end(), CompareLoops);

    for (const auto& loop : sortedLoops)
    {
        output << "0x" << hex << loop.second->targetLoopAddress << ", ";
        output << dec << loop.second->loopSeenCount << ", ";
        output << loop.second->loopInvocationCount << ", ";
        output << loop.second->mean << ", ";
        output << loop.second->diffCount << ", ";
        output << loop.second->routineName << ", ";
        output << "0x" << hex << loop.second->routineAddress << ", ";
        output << loop.second->routineInstructionCount << ", ";
        output << loop.second->routineExecutionCount << endl;
    }

    output.close();
}
