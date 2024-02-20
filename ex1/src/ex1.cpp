#include <fstream>
#include <iomanip>
#include <iostream>
#include <string.h>
#include <iterator>
#include <utility>
#include "pin.H"
#include <map>
#include <vector>

using namespace std;
// class to represent a Routine.
class RTNCTR{
    public:
        RTN rtn;
		
		ADDRINT RTN_ADR;
        
		ADDRINT IMG_ADR;
        
		string RTN_NAME;
        
		string IMG_NAME;
                
		UINT64 INSTR_COUNTER;
		
		UINT64 TIMES_CALLED;

		RTNCTR() {} ;
        ~RTNCTR() = default;
};
// map to hold all routines and their info.
map <ADDRINT,RTNCTR*> rtnMap;

// Func declerations.
VOID Routine(RTN rotine , VOID *v);
VOID Fini(INT32 code, VOID *v);
const char * FixPath(const char * string);
VOID docount(UINT64 * counter);
bool SortDescending (const pair<ADDRINT, RTNCTR*> A ,const pair<ADDRINT, RTNCTR*> B);
vector<pair<ADDRINT,RTNCTR*>>* sort(map <ADDRINT,RTNCTR*>* rtnMap);

int main(int argc , char* argv[]) {
    PIN_InitSymbols();
    PIN_Init(argc , argv);
    RTN_AddInstrumentFunction(Routine, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
	return 0;
}
// main Func for each routine that is called.
VOID Routine(RTN rtn , VOID *v){
    auto * Current = new RTNCTR;
	Current->RTN_ADR = RTN_Address(rtn);
    Current->IMG_ADR = IMG_LowAddress(SEC_Img(RTN_Sec(rtn)));
	Current->RTN_NAME = RTN_Name(rtn);
    Current->IMG_NAME = FixPath(IMG_Name(SEC_Img(RTN_Sec(rtn))).c_str());
    Current->INSTR_COUNTER = 0;
    Current->TIMES_CALLED = 0;
	pair<ADDRINT,RTNCTR*> tmp(Current->RTN_ADR ,Current ) ;
    rtnMap.insert(tmp);
    RTN_Open(rtn);
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(Current->TIMES_CALLED), IARG_END);
    for (INS inst = RTN_InsHead(rtn); INS_Valid(inst); inst = INS_Next(inst)) {
        INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)docount, IARG_PTR, &(Current->INSTR_COUNTER), IARG_END);
    }
    RTN_Close(rtn);
}
// printing info to the "rtn-output.czv" file.
VOID Fini(INT32 code, VOID *v){
	// sort vector of routines in Descending order of the num of instructions of each routine.
    vector<pair<ADDRINT,RTNCTR*>>* Vec = sort(&rtnMap);
	ofstream Output;
    Output.open("rtn-output.csv");

    for (auto it = Vec->begin()  ;  it != Vec->end();  ++it ){
        if(it->second->INSTR_COUNTER >0)
            Output << setw(23) << it->second->IMG_NAME << ","
                << setw(18)  << hex <<"0x"<< it->second->IMG_ADR << dec <<","
                << setw(23) << it->second->RTN_NAME << ","
                << setw(18) << hex <<"0x"<< it->second->RTN_ADR << dec <<","
                << setw(12) << it->second->INSTR_COUNTER << ","
                << setw(18) << it->second->TIMES_CALLED << endl;
	}

    Output.close();
}


VOID docount(UINT64 * counter){
    (*counter)++;
}
// returns remaining string of "string" after last occurance of character '/' in it.
const char * FixPath(const char * string){
    const char * tmp = strrchr(string,'/');
    if (tmp != nullptr)
        return tmp+1;
    return string;
}

// used to sort Routines in descending order of their # of instructions.
bool SortDescending (const pair<ADDRINT, RTNCTR*> rA ,const pair<ADDRINT, RTNCTR*> rB){
	int Count1 =  rA.second->INSTR_COUNTER;
	int Count2 = rB.second->INSTR_COUNTER;
    return Count1 > Count2;
}
// sorts using the SortDescending func above.
vector<pair<ADDRINT,RTNCTR*>>* sort(map <ADDRINT,RTNCTR*>* rtnMap){
    vector<pair<ADDRINT,RTNCTR*>>* Vec = new vector<pair<ADDRINT,RTNCTR*>> ;
    for (map<ADDRINT,RTNCTR*>::iterator it= rtnMap->begin();it != rtnMap->end() ;it++) {
        Vec->push_back(*it);
    }
    sort(Vec->begin(), Vec->end(), SortDescending);
	return Vec;

}
