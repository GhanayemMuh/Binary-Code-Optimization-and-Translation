#include "pin.H"
#include <iostream>
#include <map>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
extern "C" {
#include "xed-interface.h"
}
#include <iomanip>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <values.h>
using namespace std;
using std::cerr;
using std::endl;
using std::find;

// For XED:
#if defined(TARGET_IA32E)
    xed_state_t dstate = {XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b};
#else
    xed_state_t dstate = { XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b};
#endif

ADDRINT lowest_sec_addr = 0;
ADDRINT highest_sec_addr = 0;

#define MAX_PROBE_JUMP_INSTR_BYTES  14



const unsigned int max_inst_len = XED_MAX_INSTRUCTION_BYTES;
const ADDRINT NO_DOMINATE_CALL = (ADDRINT)0, NO_DIRECT_CONTROL_FLOW = (ADDRINT)0;
/*======================================================================*/
/* commandline switches                                                 */
/*======================================================================*/
KNOB<BOOL>   KnobVerbose(KNOB_MODE_WRITEONCE, "pintool",
    "verbose", "0", "Verbose run");

KNOB<BOOL>   KnobDumpTranslatedCode(KNOB_MODE_WRITEONCE, "pintool",
    "dump_tc", "0", "Dump Translated Code");

KNOB<BOOL>   KnobDoNotCommitTranslatedCode(KNOB_MODE_WRITEONCE, "pintool",
    "no_tc_commit", "0", "Do not commit translated code");

KNOB<BOOL>   KnobOpt(KNOB_MODE_WRITEONCE, "pintool",
	"opt", "0", "Probe mode");
KNOB<BOOL>   KnobProf(KNOB_MODE_WRITEONCE, "pintool",
	"prof", "0", "JIT mode");
	
	
	
	
// instruction map with an entry for each new instruction:
typedef struct { 
	ADDRINT orig_ins_addr;
	ADDRINT new_ins_addr;
	ADDRINT orig_targ_addr;
	bool hasNewTargAddr;
	char encoded_ins[XED_MAX_INSTRUCTION_BYTES];
	xed_category_enum_t category_enum;
	unsigned int size;
	int targ_map_entry;
} instr_map_t;
	
	
	

class RoutineProfile {
public:
    std::string name;
    ADDRINT address;    
    UINT64 instruction_count = 0;
    UINT64 call_count = 0;
    bool is_recursive = false;
    std::map<ADDRINT, UINT64> caller_map; // Maps call instruction addresses to counts.

    ADDRINT dominate_call() const {
        const ADDRINT NO_DOMINATE_CALL = (ADDRINT)0;
        
        if (this->caller_map.empty()) {
            return NO_DOMINATE_CALL;
        }
        
        std::vector<std::pair<ADDRINT, UINT64>> vec(caller_map.begin(), caller_map.end());
        std::sort(vec.begin(), vec.end(), 
                  [](const std::pair<ADDRINT, UINT64>& a, const std::pair<ADDRINT, UINT64>& b) {
                      return a.second > b.second;
                  });
        
        for (size_t i = 1; i < vec.size(); i++) {
            if (vec[i].second == vec[0].second) {
                return NO_DOMINATE_CALL;
            }
        }
        
        return vec[0].first;
    }
    
	bool is_candidate() const {
		if (caller_map.empty()) {
			return false;
		}

		ADDRINT dominantCaller = dominate_call();
		if (dominantCaller == NO_DOMINATE_CALL) {
			return false;
		}

		double dominantCallerCount = caller_map.at(dominantCaller);
		double totalCalls = call_count;

		return (dominantCallerCount / totalCalls) >= 0.75;
	}

};




struct LoopProfile {
    RoutineProfile* routine;          // Pointer to the RoutineProfile which this loop is part of.
    ADDRINT start_address;            // Starting address of the loop.
    ADDRINT end_address;              // Ending address of the loop.
    UINT64 invocation_count = 0;      // Number of times the loop has been invoked.
    UINT64 total_iterations = 0;      // Total iterations the loop has run.
	std::vector<UINT64> countSeen;    
    bool is_valid = true;             // Flag to check if the loop is valid or not.
};


typedef struct BranchProfile {
    ADDRINT source_address;      // The address of the branch instruction itself
    ADDRINT target_address;      // The address the branch jumps to if taken
    ADDRINT fall_through_end;    // The address at the end of the fall-through sequence
    UINT64 run_count = 0;        // Number of times the branch was encountered
    UINT64 jump_count = 0;       // Number of times the branch was taken
    UINT64 hot_count = 0;        // Number of times the branch was considered "hot"
    bool is_taken_hot = false;   // Flag indicating if the branch is frequently taken
} BranchProfile;



struct BasicBlockProfile {
    ADDRINT head_address;            // Starting address of the basic block.
    ADDRINT tail_address;            // Ending address of the basic block.
    ADDRINT jump_address = 0;        // Address where the block jumps to (if it has a jump).
    ADDRINT fall_address = 0;        // Address where the block falls through to (if applicable).
    RoutineProfile* routine = nullptr; // Pointer to the RoutineProfile which this block is part of.
    UINT64 count_taken = 0;          // Count of times the block's tail instruction jumped.
    UINT64 count_total = 0;          // Total execution count of the block's tail instruction.
};

struct ConditionalBranchProfile {
    ADDRINT branch_address;       // Address of the branch instruction.
    ADDRINT end_fallthrough_address; // Address of the end of the fall-through sequence.
};

// Tables of all candidate routines to be translated:
typedef struct { 
	ADDRINT rtn_addr; 
	USIZE rtn_size;
	int instr_map_entry;   // negative instr_map_entry means routine does not have a translation.
	bool isSafeForReplacedProbe;	
} translated_rtn_t;

translated_rtn_t *translated_rtn;
instr_map_t *instr_map = NULL;
int translated_rtn_num = 0;
int num_of_instr_map_entries = 0;
int max_ins_count = 0;
int max_rtn_count = 0;
std::ofstream* out = 0;
// tc containing the new code:
char *tc;	
int tc_cursor = 0;
std::map<ADDRINT, RoutineProfile> rtn_map; // Map to store profiles for each routine based on its starting address.
std::map<ADDRINT, LoopProfile> loop_map; // Map to store loop profiles based on the loop's starting address.
std::map<ADDRINT, BranchProfile> branch_profiles; // Map to store branch profiles based on the branch instruction's address.
std::map<ADDRINT, BasicBlockProfile> bbl_map; // Map to store basic block profiles based on the block's starting address.
std::map<ADDRINT, ConditionalBranchProfile> cond_br_profiles; // Map to store conditional branch profiles based on the branch instruction's address.
std::vector<ADDRINT> top_ten_rtn; // Vector to store the top 10 routines to be inlined and reordered in OPT stage.
std::vector<std::pair<ADDRINT, ADDRINT>> inlineFunctionCandidates; // vector to store the functions to be inlined.
std::map<ADDRINT, std::vector<std::pair<ADDRINT, ADDRINT>>> reorderedRoutineMap;
std::map<ADDRINT, ADDRINT> condBrAddressToEndOfFallthrough;

// similar to the python "split" method for strings.
std::vector<std::string> split(const std::string &s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
}



bool isElementExistInMap(ADDRINT address, auto map) {
	return (!(map.find(address) == map.end()));
}



class xed_ins_to_translate {
public:
	ADDRINT addr;
	USIZE size;
	ADDRINT target_addr;
	xed_decoded_inst_t data;
	xed_category_enum_t category_enum;
	xed_ins_to_translate() : addr((ADDRINT)0), size(0), target_addr((ADDRINT)0) {
		xed_decoded_inst_zero_set_mode(&(data), &dstate);
	}
	xed_ins_to_translate(ADDRINT new_addr, USIZE new_size, xed_error_enum_t& xed_code) : addr(new_addr), size(new_size) {
		target_addr = (ADDRINT)0;
		xed_decoded_inst_zero_set_mode(&data, &dstate);
		xed_code = xed_decode(&data, reinterpret_cast<UINT8*>(addr), max_inst_len);
		if (xed_code == XED_ERROR_NONE) {
			category_enum = xed_decoded_inst_get_category(&data);
			if (xed_decoded_inst_get_branch_displacement_width(&data) > 0) { // there is a branch offset.
				target_addr = new_addr + xed_decoded_inst_get_length(&data) + xed_decoded_inst_get_branch_displacement(&data);
			}
		}
	}
	/* unconditonal jump decoded constructor: 
		The user must check output parameters and category_enum, before usage.
	*/
	xed_ins_to_translate(ADDRINT new_orig_addr, ADDRINT new_orig_target, xed_bool_t& convert_ok,
		xed_error_enum_t& xed_code) {
		xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
		xed_int32_t disp = (xed_int32_t)(new_orig_target - new_orig_addr);
		xed_encoder_instruction_t  enc_instr;

		xed_inst1(&enc_instr, dstate,
			XED_ICLASS_JMP, 64,
			xed_relbr(disp, 32));

		xed_encoder_request_t enc_req;

		xed_encoder_request_zero_set_mode(&enc_req, &dstate);
		convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
		if (convert_ok) {
			unsigned int new_size = 0;
			xed_code = xed_encode(&enc_req, enc_buf, max_inst_len, &new_size);
			if (xed_code == XED_ERROR_NONE) {
				xed_ins_to_translate* result = new xed_ins_to_translate();
				xed_code = xed_decode(&(result->data), enc_buf, max_inst_len);
				if (xed_code == XED_ERROR_NONE) {
					data = result->data;
					addr = new_orig_addr;
					size = xed_decoded_inst_get_length(&data);
					target_addr = new_orig_target;
					xed_category_enum_t test_category = xed_decoded_inst_get_category(&data);
					category_enum = (test_category == XED_CATEGORY_UNCOND_BR) ? test_category : XED_CATEGORY_INVALID;
				}
				else {
					cerr << "JUMP: Failed to decode." << endl;
				}
				delete result;
			}
			else {
				cerr << "JUMP: Failed to encode." << endl;
			}
		}
	}
	xed_ins_to_translate(const xed_ins_to_translate& obj) : addr(obj.addr), size(obj.size), target_addr(obj.target_addr),
		data(obj.data), category_enum(obj.category_enum) {}
	xed_ins_to_translate& operator= (const xed_ins_to_translate& obj) {
		if (this == &obj) {
			return *this;
		}
		addr = obj.addr;
		size = obj.size;
		target_addr = obj.target_addr;
		data = obj.data;
		category_enum = obj.category_enum;
		return *this;
	}
	bool revert_cond_jump(xed_error_enum_t& xed_code) {
		if (this->category_enum != XED_CATEGORY_COND_BR) {
			xed_code = XED_ERROR_NONE;
			return false;
		}

		xed_decoded_inst_t xed_to_revert = this->data;
		xed_iclass_enum_t iclass_enum = xed_decoded_inst_get_iclass(&xed_to_revert);
		if (iclass_enum == XED_ICLASS_JRCXZ) {
			xed_code = XED_ERROR_NONE;
			return false;    // do not revert JRCXZ
		}
		xed_iclass_enum_t 	retverted_iclass;
		switch (iclass_enum) {

		case XED_ICLASS_JB:
			retverted_iclass = XED_ICLASS_JNB;
			break;

		case XED_ICLASS_JBE:
			retverted_iclass = XED_ICLASS_JNBE;
			break;

		case XED_ICLASS_JL:
			retverted_iclass = XED_ICLASS_JNL;
			break;

		case XED_ICLASS_JLE:
			retverted_iclass = XED_ICLASS_JNLE;
			break;

		case XED_ICLASS_JNB:
			retverted_iclass = XED_ICLASS_JB;
			break;

		case XED_ICLASS_JNBE:
			retverted_iclass = XED_ICLASS_JBE;
			break;

		case XED_ICLASS_JNL:
			retverted_iclass = XED_ICLASS_JL;
			break;

		case XED_ICLASS_JNLE:
			retverted_iclass = XED_ICLASS_JLE;
			break;

		case XED_ICLASS_JNO:
			retverted_iclass = XED_ICLASS_JO;
			break;

		case XED_ICLASS_JNP:
			retverted_iclass = XED_ICLASS_JP;
			break;

		case XED_ICLASS_JNS:
			retverted_iclass = XED_ICLASS_JS;
			break;

		case XED_ICLASS_JNZ:
			retverted_iclass = XED_ICLASS_JZ;
			break;

		case XED_ICLASS_JO:
			retverted_iclass = XED_ICLASS_JNO;
			break;

		case XED_ICLASS_JP:
			retverted_iclass = XED_ICLASS_JNP;
			break;

		case XED_ICLASS_JS:
			retverted_iclass = XED_ICLASS_JNS;
			break;

		case XED_ICLASS_JZ:
			retverted_iclass = XED_ICLASS_JNZ;
			break;

		default:
			xed_code = XED_ERROR_NONE;
			return false;
		}

		// Converts the decoder request to a valid encoder request:
		xed_encoder_request_init_from_decode(&xed_to_revert);

		// set the reverted opcode;
		xed_encoder_request_set_iclass(&xed_to_revert, retverted_iclass);

		xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
		unsigned int new_size = 0;

		xed_error_enum_t xed_error = xed_encode(&xed_to_revert, enc_buf, max_inst_len, &new_size);
		if (xed_error != XED_ERROR_NONE) {
			xed_code = xed_error;
			return false;
		}
		xed_decoded_inst_t new_xedd;
		xed_decoded_inst_zero_set_mode(&new_xedd, &dstate);

		xed_error = xed_decode(&new_xedd, enc_buf, max_inst_len);
		if (xed_error != XED_ERROR_NONE) {
			xed_code = xed_error;
			return false;
		}
		xed_decoded_inst_zero_set_mode(&this->data, &dstate);
		this->data = new_xedd;
		this->size = xed_decoded_inst_get_length(&new_xedd);
		return true;
	}
	~xed_ins_to_translate() {}
};

std::map<ADDRINT, std::vector<xed_ins_to_translate>> functionXeddsMap;

std::vector<xed_ins_to_translate> reorder(std::vector<xed_ins_to_translate> translated_routine, std::vector<std::pair<ADDRINT, ADDRINT>> new_order)  {
	std::vector<xed_ins_to_translate> result;
	std::map<ADDRINT, size_t> back_edges;
	///*
	//	The function using the map of bbls, and order, should create a new vector.
	//	Where as each command is in the right place. Using translated_routine[i]. etc..
	//*/
	/*while working:
	if ins is in place : add to result
	else :
		swap until in place*/
	/*bool swappped = false;
	while */

	for (size_t i = 0; i < new_order.size(); i++) {
		for (auto itr = translated_routine.begin(); itr != translated_routine.end(); ++itr) {
			if (itr->addr >= new_order[i].first && itr->addr <= new_order[i].second) {
				if (itr->addr != new_order[i].second) {
					result.push_back(*itr);
				}
				else {
					if (itr->category_enum == XED_CATEGORY_COND_BR && (i < new_order.size() - 1 && itr != translated_routine.end() - 1)
						&& itr->target_addr == new_order[i + 1].first) {
						/* Fix cond jump. Cause the new order brings target to be FT.*/
						xed_ins_to_translate new_tail(*itr);
						xed_error_enum_t xed_error;
						if (new_tail.revert_cond_jump(xed_error)) {
							new_tail.target_addr = std::next(itr)->addr;
							result.push_back(new_tail);
							/* Searching for the end of the fall through.
								Need to figure a away for it not to be in the -opt run.
								Or a much more efficient way in Complexity.
							*/
							/*auto end_of_fallthrough = std::next(itr);
							for (; std::next(end_of_fallthrough) != translated_routine.end()
								&& std::next(end_of_fallthrough)->addr != itr->target_addr; ++end_of_fallthrough) {
							}*/
							//if (end_of_fallthrough != translated_routine.end()) {
							if(isElementExistInMap(itr->addr, condBrAddressToEndOfFallthrough)){
								back_edges[condBrAddressToEndOfFallthrough[itr->addr]] = i + 1;
							}
						}
						else if (xed_error != XED_ERROR_NONE) {
							/* Error handling in case of encoder/decoder failur. */
							cerr << "ENCODE ERROR at new_tail (Reorder): " << xed_error_enum_t2str(xed_error) << endl;
							result.clear();
							return result;
						}

					}
					else {
						result.push_back(*itr);
					}
				}
				if (isElementExistInMap(itr->addr, back_edges)) {
					xed_bool_t convert_ok;
					xed_error_enum_t xed_code;
					xed_ins_to_translate new_back_jump(itr->addr, new_order[back_edges[itr->addr]].first, convert_ok, xed_code);
					if (!convert_ok) {
						cerr << "conversion to encode request failed at new_jump. (Reorder)" << endl;
						result.clear();
						return result;
					}
					else if (xed_code != XED_ERROR_NONE) {
						cerr << "ENCODE ERROR at new_jump (Reorder): " << xed_error_enum_t2str(xed_code) << endl;
						result.clear();
						return result;
					}
					else if (new_back_jump.category_enum == XED_CATEGORY_INVALID) {
						cerr << "new_back_jump construction failed. (Reorder)" << endl;
						result.clear();
						return result;
					}
					else {
						result.push_back(new_back_jump);
						//std::cout << "New back jump, actual target: 0x" << std::hex << new_back_jump.target_addr << endl;
					}
				}
			}
		}
	}
	return result;
}


bool isInlineCandidateExist(ADDRINT candidate_rtn_address) {
    for (const auto& pair : inlineFunctionCandidates) {
        if (pair.second == candidate_rtn_address) {
            return true;
        }
    }
    return false;
}



// Increments the instruction count for a routine
VOID increment_instruction_count(UINT64* instruction_count) {
    (*instruction_count)++;
}

// Increments the call count for a routine or call site
VOID increment_call_count(UINT64* call_count) {
    (*call_count)++;
}

// Increments the iteration count for a loop
VOID increment_loop_iteration(LoopProfile* loop) {
    if (loop->countSeen.size() > loop->invocation_count) {
        loop->countSeen[loop->invocation_count]++;
        loop->total_iterations++;
    }
}

// Increments the invocation count of the loop
VOID increment_loop_invocation(LoopProfile* loop) {
    loop->invocation_count++;
    loop->countSeen.push_back(0); // Initialize the count for this new invocation
}



VOID profile_loops_and_instructions(INS ins, VOID* v) {
    RTN rtn_arg = INS_Rtn(ins);
    if (RTN_Valid(rtn_arg)) {
        ADDRINT rtn_address = RTN_Address(rtn_arg);
        IMG img = IMG_FindByAddress(rtn_address);
        if (!IMG_Valid(img) || !IMG_IsMainExecutable(img)) {
            return;
        }

        // Check if the routine exists in our map. If not, create a new RoutineProfile for it.
        if (rtn_map.find(rtn_address) == rtn_map.end()) {
            rtn_map[rtn_address] = { RTN_Name(rtn_arg), rtn_address };
        }

        RoutineProfile& current_routine = rtn_map[rtn_address];

        // Increment instruction count for the routine
        increment_instruction_count(&current_routine.instruction_count);

        // If the instruction is the start of the routine, increment the call count
        if (rtn_address == INS_Address(ins)) {
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)increment_call_count, IARG_PTR, &(current_routine.call_count), IARG_END);

        }
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)increment_instruction_count, IARG_PTR, &(rtn_map[rtn_address].instruction_count), IARG_END);

        // Handle loops
        if (INS_IsDirectControlFlow(ins) && !INS_IsCall(ins) && !INS_IsSyscall(ins)) {
            ADDRINT myself = INS_Address(ins);
            ADDRINT target = INS_DirectControlFlowTargetAddress(ins);

            if (target < myself) {
                if (loop_map.find(myself) == loop_map.end()) {
                    loop_map[myself] = { &current_routine, myself, target };
                    loop_map[myself].countSeen.push_back(0);
                }

                LoopProfile& current_loop = loop_map[myself];

                if (INS_Category(ins) == XED_CATEGORY_COND_BR) {
                    if (INS_IsValidForIpointTakenBranch(ins)) {
                        INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)increment_loop_iteration, IARG_PTR, &current_loop, IARG_END);
                    }

                    if (INS_IsValidForIpointAfter(ins)) {
                        INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)increment_loop_invocation, IARG_PTR, &current_loop, IARG_END);
                    }
                }
                else if (INS_Category(ins) == XED_CATEGORY_UNCOND_BR) {
                    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)increment_loop_iteration, IARG_PTR, &current_loop, IARG_END);

                    RTN_Open(rtn_arg);
                    INS start = RTN_InsHead(rtn_arg);
                    for (; INS_Valid(start) && INS_Address(start) < target; start = INS_Next(start)) {
                        ; // Iterate through instructions to find the conditional jump
                    }

                    for (INS cond_jump = start; INS_Valid(cond_jump); cond_jump = INS_Next(cond_jump)) {
                        if (INS_IsDirectControlFlow(cond_jump) && !INS_IsCall(cond_jump) && INS_Category(cond_jump) == XED_CATEGORY_COND_BR
                            && INS_DirectControlFlowTargetAddress(cond_jump) > myself) {
                            if (INS_IsValidForIpointTakenBranch(cond_jump)) {
                                INS_InsertCall(cond_jump, IPOINT_TAKEN_BRANCH, (AFUNPTR)increment_loop_invocation, IARG_PTR, &current_loop, IARG_END);
                            }
                            break;
                        }
                    }
                    RTN_Close(rtn_arg);
                }
            }
        }
    }
}


VOID profile_basic_blocks(TRACE trace, VOID* v) {
    RTN rtn_arg = TRACE_Rtn(trace);
    if (RTN_Valid(rtn_arg)) {
        ADDRINT rtn_address = RTN_Address(rtn_arg);
        IMG img = IMG_FindByAddress(rtn_address);
        if (!IMG_Valid(img) || !IMG_IsMainExecutable(img)) {
            return;
        }

        // Iterate through each basic block within the trace
        for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
            INS ins_head = BBL_InsHead(bbl);
            ADDRINT head_address = INS_Address(ins_head);
            INS ins_tail = BBL_InsTail(bbl);
            ADDRINT tail_address = INS_Address(ins_tail);

            // Check if the basic block exists in our map. If not, create a new BasicBlockProfile for it.
            if (bbl_map.find(head_address) == bbl_map.end()) {
                bbl_map[head_address] = { head_address, tail_address, 0, 0, &rtn_map[rtn_address] };
            }

            BasicBlockProfile& current_bbl = bbl_map[head_address];

            if (INS_IsDirectControlFlow(ins_tail)) {
                ADDRINT target = INS_DirectControlFlowTargetAddress(ins_tail);
                if (target > tail_address) {
                    bbl_map[head_address].jump_address = target;

                    if (INS_HasFallThrough(ins_tail)) {
                        if (INS_IsValidForIpointTakenBranch(ins_tail)) {
                            INS_InsertCall(ins_tail, IPOINT_TAKEN_BRANCH, (AFUNPTR)increment_instruction_count, IARG_PTR, &current_bbl.count_taken, IARG_END);
                        }
                        INS_InsertCall(ins_tail, IPOINT_BEFORE, (AFUNPTR)increment_instruction_count, IARG_PTR, &current_bbl.count_total, IARG_END);
                        
                        INS fall = INS_Next(ins_tail);
                        if (INS_Valid(fall)) {
                            current_bbl.fall_address = INS_Address(fall);
                        }
                    }
                }
            }
        }
    }
}


VOID profile_conditional_branches(RTN rtn_arg, VOID* v) {
    if (RTN_Valid(rtn_arg)) {
        ADDRINT rtn_address = RTN_Address(rtn_arg);
        IMG img = IMG_FindByAddress(rtn_address);
        if (!IMG_Valid(img) || !IMG_IsMainExecutable(img)) {
            return;
        }

        RTN_Open(rtn_arg);
        for (INS ins = RTN_InsHead(rtn_arg); INS_Valid(ins); ins = INS_Next(ins)) {
            if (INS_IsDirectControlFlow(ins)) {
                ADDRINT branch_address = INS_Address(ins);
                ADDRINT target = INS_DirectControlFlowTargetAddress(ins);

                if (target > branch_address && INS_HasFallThrough(ins)) {
                    INS end_fall = INS_Next(ins);
                    while (INS_Valid(end_fall) && INS_Valid(INS_Next(end_fall)) && (INS_Address(INS_Next(end_fall)) < target)) {
                        end_fall = INS_Next(end_fall);
                    }

                    if (INS_Valid(end_fall)) {
                        ConditionalBranchProfile cond_branch_profile = {
                            branch_address,
                            INS_Address(end_fall)
                        };

                        // Insert or update the conditional branch profile in our map
                        cond_br_profiles[branch_address] = cond_branch_profile;
                    } else {
                        std::cout << "Invalid end of fall-through for branch at address: " << std::hex << branch_address << std::endl;
                    }
                }
            }
        }
        RTN_Close(rtn_arg);
    }
}


VOID profile_routine_calls(INS ins, VOID* v) {
    ADDRINT ins_address = INS_Address(ins);
    RTN rtn_arg = INS_Rtn(ins);
    if (RTN_Valid(rtn_arg)) {
        ADDRINT rtn_address = RTN_Address(rtn_arg);
        IMG img = IMG_FindByAddress(rtn_address);
        if (!IMG_Valid(img) || !IMG_IsMainExecutable(img)) {
            return;
        }

        if (rtn_map.find(rtn_address) == rtn_map.end()) {
            RoutineProfile routine_profile = {
                RTN_Name(rtn_arg),
                rtn_address
            };
            rtn_map[rtn_address] = routine_profile;
        }

        increment_instruction_count(&(rtn_map[rtn_address].instruction_count));

        if (INS_IsDirectControlFlow(ins) && INS_IsCall(ins)) {
            ADDRINT target_address = INS_DirectControlFlowTargetAddress(ins);

            if (target_address == rtn_address) {
                rtn_map[rtn_address].is_recursive = true;
            } else {
                RTN target_rtn_pin = RTN_FindByAddress(target_address);
                if (RTN_Valid(target_rtn_pin)) {
                    IMG img_target = IMG_FindByAddress(target_address);
                    if (IMG_Valid(img_target) && IMG_IsMainExecutable(img_target)) {
                        if (rtn_map.find(target_address) == rtn_map.end()) {
                            RoutineProfile target_routine = {
                                RTN_Name(target_rtn_pin),
                                target_address
                            };
                            rtn_map[target_address] = target_routine;
                        }

                        if (rtn_map[target_address].caller_map.find(ins_address) == rtn_map[target_address].caller_map.end()) {
                            rtn_map[target_address].caller_map[ins_address] = 0;
                        }

                        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)increment_call_count, 
                            IARG_PTR, &(rtn_map[target_address].caller_map[ins_address]), IARG_END);
                    }
                }
            }
        }
    }
}


bool GetTopTenRtns() {
    std::ifstream input_file("count.csv");
    if (!input_file.is_open()) {
        return false;
    }

    std::string line;
    std::getline(input_file, line);

    while (std::getline(input_file, line) && top_ten_rtn.size() < 10) {
        std::vector<std::string> fields = split(line, ',');

        // Extract the needed fields.
        bool is_recursive = (fields[4] == "yes") ? true : false;
        bool is_candidate = (fields[6] == "yes") ? true : false;
        ADDRINT addr;
        std::istringstream addr_in_hex(fields[1]);
        addr_in_hex >> std::hex >> addr;

        if (!is_recursive && is_candidate) {
            top_ten_rtn.push_back(addr); //populate top 10 rtn vec
        }
    }

    input_file.close();
    
    return true;
}

bool GetInlineFunctionCandidates() {
    std::ifstream input_file("count.csv");
    if (!input_file.is_open()) {
        /* Failed to open. */
        return false;
    }

    std::string line;
    // Skip the header line
    std::getline(input_file, line);    
    while (std::getline(input_file, line)) {
        std::vector<std::string> temp_line = split(line, ',');
        UINT64 ins_count = std::stoll(temp_line[2]);
        UINT64 call_count = std::stoi(temp_line[3]);
        bool is_recursive = (bool)std::stoi(temp_line[4]);

        if (is_recursive || !ins_count || !call_count) {
            continue;
        }

        ADDRINT candidateAddr, dominantCallAddr;
        std::istringstream candidateAddressStr(temp_line[1]);
        candidateAddressStr >> std::hex >> candidateAddr;

        std::istringstream dominantCallAddressStr(temp_line[5]);
        dominantCallAddressStr >> std::hex >> dominantCallAddr;

        if (dominantCallAddr == NO_DOMINATE_CALL) {
            continue;
        }

        // Check for specific functions "fallbackSort" and "fallbackQSort3"
        RTN dominantRtn = RTN_FindByAddress(dominantCallAddr);
        ADDRINT dominantRtnAddr = RTN_Address(dominantRtn);
        IMG candidateImg = IMG_FindByAddress(candidateAddr);
        IMG dominantRtnImg = IMG_FindByAddress(dominantRtnAddr);

        if (IMG_Valid(candidateImg) && IMG_IsMainExecutable(candidateImg)
            && IMG_Valid(dominantRtnImg) && IMG_IsMainExecutable(dominantRtnImg)) {

            if (RTN_Name(dominantRtn) != "fallbackQSort3" &&
                (RTN_Name(dominantRtn) != "fallbackSort" || RTN_FindNameByAddress(candidateAddr) != "fallbackQSort3")) {
                continue;
            }

            if (std::find(top_ten_rtn.begin(), top_ten_rtn.end(), dominantRtnAddr) != top_ten_rtn.end()) {
                inlineFunctionCandidates.push_back({dominantCallAddr, candidateAddr});
            }
        }
    }

    input_file.close();
    return true;
}


bool GetReorderedRoutineMap() {
    std::ifstream input_file("bbl-count.csv");
    if (!input_file.is_open()) {
        return false;
    }
    std::string line;
    while (std::getline(input_file, line)) {
        std::vector<std::string> temp_line = split(line, ',');
        
        ADDRINT rtn_address;
        std::istringstream rtnAddressStr(temp_line[1]);
        rtnAddressStr >> std::hex >> rtn_address;

        if (reorderedRoutineMap.find(rtn_address) == reorderedRoutineMap.end()) {
            reorderedRoutineMap[rtn_address].clear();
        }

        size_t start_bbl_list = std::distance(temp_line.begin(), std::find(temp_line.begin(), temp_line.end(), "start_bbl_list"));
        size_t end_bbl_list = std::distance(temp_line.begin(), std::find(temp_line.begin(), temp_line.end(), "end_bbl_list"));
        size_t start_cond_end_list = std::distance(temp_line.begin(), std::find(temp_line.begin(), temp_line.end(), "start_cond_end_list"));
        size_t end_cond_end_list = std::distance(temp_line.begin(), std::find(temp_line.begin(), temp_line.end(), "end_cond_end_list"));

        for (size_t i = start_bbl_list + 1; i < end_bbl_list; i+= 2) {
            ADDRINT start_bbl_address, end_bbl_address;
            std::istringstream startBblAddressStr(temp_line[i]);
            std::istringstream endBblAddressStr(temp_line[i + 1]);
            startBblAddressStr >> std::hex >> start_bbl_address;
            endBblAddressStr >> std::hex >> end_bbl_address;
            reorderedRoutineMap[rtn_address].push_back({start_bbl_address, end_bbl_address});
        }

        for (size_t i = start_cond_end_list + 1; i < end_cond_end_list; i += 2) {
            ADDRINT cond_br_address, end_fall_address;
            std::istringstream condBrAddressStr(temp_line[i]);
            std::istringstream endFallAddressStr(temp_line[i + 1]);
            condBrAddressStr >> std::hex >> cond_br_address;
            endFallAddressStr >> std::hex >> end_fall_address;
            condBrAddressToEndOfFallthrough[cond_br_address] = end_fall_address;
        }
    }
    input_file.close();
    return true;
}

/*#####################
 * ####################
 * ####################\
 *#####################
 * ####################
 * */
 

 
/* ============================================================= */
/* Service dump routines                                         */
/* ============================================================= */

/*************************/
/* dump_all_image_instrs */
/*************************/
void dump_all_image_instrs(IMG img)
{
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {   
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {		

			// Open the RTN.
            RTN_Open( rtn );

			cerr << RTN_Name(rtn) << ":" << endl;

			for( INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins) )
            {				
	              cerr << "0x" << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << endl;
			}

			// Close the RTN.
            RTN_Close( rtn );
		}
	}
}


/*************************/
/* dump_instr_from_xedd */
/*************************/
void dump_instr_from_xedd (xed_decoded_inst_t* xedd, ADDRINT address)
{
	// debug print decoded instr:
	char disasm_buf[2048];

    xed_uint64_t runtime_address = static_cast<UINT64>(address);  // set the runtime adddress for disassembly 	

    xed_format_context(XED_SYNTAX_INTEL, xedd, disasm_buf, sizeof(disasm_buf), static_cast<UINT64>(runtime_address), 0, 0);	

    cerr << hex << address << ": " << disasm_buf <<  endl;
}


/************************/
/* dump_instr_from_mem */
/************************/
void dump_instr_from_mem (ADDRINT *address, ADDRINT new_addr)
{
  char disasm_buf[2048];
  xed_decoded_inst_t new_xedd;

  xed_decoded_inst_zero_set_mode(&new_xedd,&dstate); 
   
  xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8*>(address), max_inst_len);				   

  BOOL xed_ok = (xed_code == XED_ERROR_NONE);
  if (!xed_ok){
	  cerr << "invalid opcode" << endl;
	  return;
  }
 
  xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, 2048, static_cast<UINT64>(new_addr), 0, 0);

  cerr << "0x" << hex << new_addr << ": " << disasm_buf <<  endl;  
 
}


/****************************/
/*  dump_entire_instr_map() */
/****************************/
void dump_entire_instr_map()
{	
	for (int i=0; i < num_of_instr_map_entries; i++) {
		for (int j=0; j < translated_rtn_num; j++) {
			if (translated_rtn[j].instr_map_entry == i) {

				RTN rtn = RTN_FindByAddress(translated_rtn[j].rtn_addr);

				if (rtn == RTN_Invalid()) {
					cerr << "Unknwon"  << ":" << endl;
				} else {
				  cerr << RTN_Name(rtn) << ":" << endl;
				}
			}
		}
		dump_instr_from_mem ((ADDRINT *)instr_map[i].new_ins_addr, instr_map[i].new_ins_addr);		
	}
}


/*************************************/
/* void commit_translated_routines() */
/*************************************/
inline void commit_translated_routines() 
{
    // Commit the translated functions: 
    // Go over the candidate functions and replace the original ones by their new successfully translated ones:

    for (int i=0; i < translated_rtn_num; i++) {

        //replace function by new function in tc
    
        if (translated_rtn[i].instr_map_entry >= 0) {
                    
            if (translated_rtn[i].rtn_size > MAX_PROBE_JUMP_INSTR_BYTES && translated_rtn[i].isSafeForReplacedProbe) {                        

                RTN rtn = RTN_FindByAddress(translated_rtn[i].rtn_addr);

                //debug print:                
                if (rtn == RTN_Invalid()) {
                    cerr << "committing rtN: Unknown";
                } else {
                    cerr << "committing rtN: " << RTN_Name(rtn);
                }
                cerr << " from: 0x" << hex << RTN_Address(rtn) << " to: 0x" << hex << instr_map[translated_rtn[i].instr_map_entry].new_ins_addr << endl;

                        
                if (RTN_IsSafeForProbedReplacement(rtn)) {

                    AFUNPTR origFptr = RTN_ReplaceProbed(rtn,  (AFUNPTR)instr_map[translated_rtn[i].instr_map_entry].new_ins_addr);                            

                    if (origFptr == NULL) {
                        cerr << "RTN_ReplaceProbed failed.";
                    } else {
                        cerr << "RTN_ReplaceProbed succeeded. ";
                    }
                    cerr << " orig routine addr: 0x" << hex << translated_rtn[i].rtn_addr
                            << " replacement routine addr: 0x" << hex << instr_map[translated_rtn[i].instr_map_entry].new_ins_addr << endl;    

                    dump_instr_from_mem ((ADDRINT *)translated_rtn[i].rtn_addr, translated_rtn[i].rtn_addr);                                                
                }                                                
            }
        }
    }
}


/**************************/
/* dump_instr_map_entry */
/**************************/
void dump_instr_map_entry(int instr_map_entry)
{
	cerr << dec << instr_map_entry << ": ";
	cerr << " orig_ins_addr: " << hex << instr_map[instr_map_entry].orig_ins_addr;
	cerr << " new_ins_addr: " << hex << instr_map[instr_map_entry].new_ins_addr;
	cerr << " orig_targ_addr: " << hex << instr_map[instr_map_entry].orig_targ_addr;

	ADDRINT new_targ_addr;
	if (instr_map[instr_map_entry].targ_map_entry >= 0)
		new_targ_addr = instr_map[instr_map[instr_map_entry].targ_map_entry].new_ins_addr;
	else
		new_targ_addr = instr_map[instr_map_entry].orig_targ_addr;

	cerr << " new_targ_addr: " << hex << new_targ_addr;
	cerr << "    new instr:";
	dump_instr_from_mem((ADDRINT *)instr_map[instr_map_entry].encoded_ins, instr_map[instr_map_entry].new_ins_addr);
}


/*************/
/* dump_tc() */
/*************/
void dump_tc()
{
  char disasm_buf[2048];
  xed_decoded_inst_t new_xedd;
  ADDRINT address = (ADDRINT)&tc[0];
  unsigned int size = 0;

  while (address < (ADDRINT)&tc[tc_cursor]) {

      address += size;

	  xed_decoded_inst_zero_set_mode(&new_xedd,&dstate); 
   
	  xed_error_enum_t xed_code = xed_decode(&new_xedd, reinterpret_cast<UINT8*>(address), max_inst_len);				   

	  BOOL xed_ok = (xed_code == XED_ERROR_NONE);
	  if (!xed_ok){
		  cerr << "invalid opcode" << endl;
		  return;
	  }
 
	  xed_format_context(XED_SYNTAX_INTEL, &new_xedd, disasm_buf, 2048, static_cast<UINT64>(address), 0, 0);

	  cerr << "0x" << hex << address << ": " << disasm_buf <<  endl;

	  size = xed_decoded_inst_get_length (&new_xedd);	
  }
}
 
 /****************************/
/* allocate_and_init_memory */
/****************************/ 
int allocate_and_init_memory(IMG img) 
{
	// Calculate size of executable sections and allocate required memory:
	//
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
    {   
		if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
			continue;


		if (!lowest_sec_addr || lowest_sec_addr > SEC_Address(sec))
			lowest_sec_addr = SEC_Address(sec);

		if (highest_sec_addr < SEC_Address(sec) + SEC_Size(sec))
			highest_sec_addr = SEC_Address(sec) + SEC_Size(sec);

		// need to avouid using RTN_Open as it is expensive...
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
        {		

			if (rtn == RTN_Invalid())
				continue;

			max_ins_count += RTN_NumIns  (rtn);
			max_rtn_count++;
		}
	}

	max_ins_count *= 4; // estimating that the num of instrs of the inlined functions will not exceed the total nunmber of the entire code.
	
	// Allocate memory for the instr map needed to fix all branch targets in translated routines:
	instr_map = (instr_map_t *)calloc(max_ins_count, sizeof(instr_map_t));
	if (instr_map == NULL) {
		perror("calloc");
		return -1;
	}


	// Allocate memory for the array of candidate routines containing inlineable function calls:
	// Need to estimate size of inlined routines.. ???
	translated_rtn = (translated_rtn_t *)calloc(max_rtn_count, sizeof(translated_rtn_t));
	if (translated_rtn == NULL) {
		perror("calloc");
		return -1;
	}


	// get a page size in the system:
	int pagesize = sysconf(_SC_PAGE_SIZE);
    if (pagesize == -1) {
      perror("sysconf");
	  return -1;
	}

	ADDRINT text_size = (highest_sec_addr - lowest_sec_addr) * 2 + pagesize * 4;

    int tclen = 2 * text_size + pagesize * 4;   // need a better estimate???

	// Allocate the needed tc with RW+EXEC permissions and is not located in an address that is more than 32bits afar:		
	char * addr = (char *) mmap(NULL, tclen, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if ((ADDRINT) addr == 0xffffffffffffffff) {
		cerr << "failed to allocate tc" << endl;
        return -1;
	}
	
	tc = (char *)addr;
	return 0;
}


int add_new_instr_entry(xed_decoded_inst_t *xedd, ADDRINT pc, unsigned int size, ADDRINT orig_targ_addr = (ADDRINT)0)
{

	// copy orig instr to instr map:
	if (xed_decoded_inst_get_length (xedd) != size) {
		cerr << "Invalid instruction decoding" << endl;
		return -1;
	}

    xed_uint_t disp_byts = xed_decoded_inst_get_branch_displacement_width(xedd);
	
	xed_int32_t disp;

    if (disp_byts > 0) { // there is a branch offset.
      disp = xed_decoded_inst_get_branch_displacement(xedd);
	  orig_targ_addr = (orig_targ_addr != (ADDRINT)0) ? orig_targ_addr : (pc + xed_decoded_inst_get_length (xedd) + disp);
	}
	// Converts the decoder request to a valid encoder request:
	xed_encoder_request_init_from_decode (xedd);

    unsigned int new_size = 0;
	
	xed_error_enum_t xed_error = xed_encode (xedd, reinterpret_cast<UINT8*>(instr_map[num_of_instr_map_entries].encoded_ins), max_inst_len , &new_size);
	if (xed_error != XED_ERROR_NONE) {
		cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;		
		return -1;
	}	
	
	// add a new entry in the instr_map:
	
	instr_map[num_of_instr_map_entries].orig_ins_addr = pc;
	instr_map[num_of_instr_map_entries].new_ins_addr = (ADDRINT)&tc[tc_cursor];  // set an initial estimated addr in tc
	instr_map[num_of_instr_map_entries].orig_targ_addr = orig_targ_addr; 
    instr_map[num_of_instr_map_entries].hasNewTargAddr = false;
	instr_map[num_of_instr_map_entries].targ_map_entry = -1;
	instr_map[num_of_instr_map_entries].size = new_size;	
    instr_map[num_of_instr_map_entries].category_enum = xed_decoded_inst_get_category(xedd);

	num_of_instr_map_entries++;

	// update expected size of tc:
	tc_cursor += new_size;    	     

	if (num_of_instr_map_entries >= max_ins_count) {
		cerr << "out of memory for map_instr" << endl;
		return -1;
	}
	

    // debug print new encoded instr:
	if (KnobVerbose) {
		cerr << "    new instr:";
		dump_instr_from_mem((ADDRINT *)instr_map[num_of_instr_map_entries-1].encoded_ins, instr_map[num_of_instr_map_entries-1].new_ins_addr);
	}

	return new_size;
}




int findCandidateRoutinesForTranslation(IMG img) 
{
    int rc;
    functionXeddsMap.clear();
    std::map<ADDRINT, USIZE> routineAddressToSize;
    bool errorInitDecode = false, enableInline = true;

    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) 
    {
        if (!SEC_IsExecutable(sec) || SEC_IsWriteable(sec) || !SEC_Address(sec))
            continue;

        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) 
        {
            if (rtn == RTN_Invalid()) 
            {
                std::cerr << "Warning: invalid routine " << RTN_Name(rtn) << std::endl;
                continue;
            }
            ADDRINT rtnAddr = RTN_Address(rtn);
            if (functionXeddsMap.find(rtnAddr) != functionXeddsMap.end()) 
            {
                continue;
            }
            std::cout << "Translating RTN: " << RTN_Name(rtn) << std::endl;
            functionXeddsMap[rtnAddr].clear();
            routineAddressToSize[rtnAddr] = RTN_Size(rtn);
            RTN_Open(rtn);

            for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) 
            {
                ADDRINT insAddr = INS_Address(ins);
                USIZE insSize = INS_Size(ins);
                xed_error_enum_t xedErrorCode;
                xed_ins_to_translate newXed(insAddr, insSize, xedErrorCode);
                if (INS_IsDirectControlFlow(ins)) 
                {
                    newXed.target_addr = INS_DirectControlFlowTargetAddress(ins);
                }
                if (xedErrorCode != XED_ERROR_NONE) 
                {
                    std::cerr << "ERROR: xed decode failed for instr at: " << "0x" << std::hex << newXed.addr << std::endl;
                    errorInitDecode = true;
                    break;
                }
                functionXeddsMap[rtnAddr].push_back(newXed);
            }

            RTN_Close(rtn);
            if (errorInitDecode) 
            {
                return -1;
            }
            std::cout << "Decoding RTN: " << RTN_Name(rtn) << " was successful." << std::endl;
        }
    }

    for (auto itr = functionXeddsMap.begin(); enableInline && itr != functionXeddsMap.end(); ++itr) 
    {
        std::vector<ADDRINT> functionsToClear;
        std::vector<xed_ins_to_translate> newFunction;
		auto found = std::find_if(inlineFunctionCandidates.begin(), inlineFunctionCandidates.end(),
			[itr](const std::pair<ADDRINT, ADDRINT>& p) {
				return p.first == itr->first; 
			});

		if (found == inlineFunctionCandidates.end()) {
			continue;
		}

        for (auto it = itr->second.begin(); it != itr->second.end(); ++it) 
        {
            if (it->category_enum == XED_CATEGORY_CALL && it->target_addr != NO_DIRECT_CONTROL_FLOW) 
            {
                ADDRINT callAddress = it->addr;
                ADDRINT targetAddress = it->target_addr;
                ADDRINT rtnAddr = itr->first;
                std::pair<ADDRINT, ADDRINT> inlineCandidate(callAddress, targetAddress);
                if (isInlineCandidateExist(rtnAddr)) 
                {
					std::cout << "In " << RTN_FindNameByAddress(rtnAddr) << " found call to : " << RTN_FindNameByAddress(targetAddress) << endl;
					auto inline_it = functionXeddsMap[targetAddress].begin();
					bool error_inline = false;
					for (;inline_it != functionXeddsMap[targetAddress].end()-1; inline_it++) {
						if (inline_it->category_enum == XED_CATEGORY_RET) {
							xed_bool_t convert_ok;
							xed_error_enum_t xed_code;
							xed_ins_to_translate new_jump(inline_it->addr, (it + 1)->addr, convert_ok, xed_code);
							if (!convert_ok) {
								cerr << "conversion to encode request failed at new_jump." << endl;
								error_inline = true;
								break;
							}
							else if (xed_code != XED_ERROR_NONE) {
								cerr << "ENCODE ERROR at new_jump: " << xed_error_enum_t2str(xed_code) << endl;
								error_inline = true;
								break;
							}
							else if (new_jump.category_enum == XED_CATEGORY_INVALID) {
								cerr << "new_jump construction failed." << endl;
								error_inline = true;
								break;
							}
							else {
								newFunction.push_back(new_jump);
							}
						}
						else {
							newFunction.push_back(*inline_it);
						}
					}
					if (error_inline) {
						enableInline = false;
						functionsToClear.clear();
						newFunction.clear();
						break;
					}
					if (inline_it == functionXeddsMap[targetAddress].end() - 1) {
						if (inline_it->category_enum != XED_CATEGORY_RET) {
							newFunction.push_back(*inline_it);
						}
					}
					functionsToClear.push_back(targetAddress);
					std::cout << "Done inserting xedds vector of " << RTN_FindNameByAddress(targetAddress) <<
						" into " << RTN_FindNameByAddress(rtnAddr) << endl;                }
            }
            else 
            {
                newFunction.push_back(*it);
            }
        }

        if (!functionsToClear.empty()) 
        {
            itr->second.clear();
            itr->second = newFunction;
            for (size_t i = 0; i < functionsToClear.size(); i++) 
            {
                functionXeddsMap[functionsToClear[i]].clear();
            }
        }
    }

    for (auto itr = functionXeddsMap.begin(); itr != functionXeddsMap.end(); itr++) 
    {
        if (!itr->second.empty()) 
        {
            std::string rtnName = RTN_FindNameByAddress(itr->first);
            std::vector<xed_ins_to_translate> reordered;
            if(rtnName != "BZ2_hbMakeCodeLengths") 
            {
                continue;
            }

            if (isElementExistInMap(itr->first, reorderedRoutineMap) && !reorderedRoutineMap[itr->first].empty()) 
            {
				std::cout << "Reorder " << rtnName << ":" << endl;
				reordered = reorder(itr->second,reorderedRoutineMap[itr->first]);
				if (reordered.empty()) {
					std::cout << "Reorder is empty." << endl;
					continue;
				}
				char disasm_buf[2048];
				std::cout << "Original translated:" << endl;
				for (auto itt = itr->second.begin(); itt != itr->second.end(); itt++) {
					xed_format_context(XED_SYNTAX_INTEL, &(itt->data), disasm_buf, 2048, static_cast<UINT64>(itt->addr), 0, 0);
					std::cout << "0x" << hex << itt->addr << ": " << disasm_buf;
					if (itt->target_addr != 0) {
						std::cout << "     orig_targ: 0x" << hex << itt->target_addr << endl;
					}
					else {
						std::cout << endl;
					}
				}
				std::cout << "Reorderd translated:" << endl;
				for (auto itt = reordered.begin(); itt != reordered.end(); itt++) {
					xed_format_context(XED_SYNTAX_INTEL, &(itt->data), disasm_buf, 2048, static_cast<UINT64>(itt->addr), 0, 0);
					std::cout << "0x" << hex << itt->addr << ": " << disasm_buf;
					if (itt->target_addr != 0) {
						std::cout << "     new orig_targ: 0x" << hex << itt->target_addr << endl;
					}
					else {
						std::cout << endl;
					}
				}
				itr->second.clear();
				itr->second = reordered;
			}

			std::cout << "Inserting " << rtnName << " into instr_map and translated_rtn." << endl;
			translated_rtn[translated_rtn_num].rtn_addr = itr->first;
			translated_rtn[translated_rtn_num].rtn_size = routineAddressToSize[itr->first];
			translated_rtn[translated_rtn_num].instr_map_entry = num_of_instr_map_entries;
			translated_rtn[translated_rtn_num].isSafeForReplacedProbe = true;
			for (auto it = itr->second.begin(); it != itr->second.end(); it++) {
				if (it->target_addr != (ADDRINT)0) {
					/* Forced new orig_targ_addr */
					rc = add_new_instr_entry(&(it->data), it->addr, it->size, it->target_addr);
				}
				else {
					rc = add_new_instr_entry(&(it->data), it->addr, it->size);
				}
				if (rc < 0) {
					cerr << "ERROR: failed during instructon translation." << endl;
					translated_rtn[translated_rtn_num].instr_map_entry = -1;
					return rc;
				}
			}
			translated_rtn_num++;
			std::cout << "Done inserting." << endl;
		}
    }

    return 0;
}

/************************************/
/* fix_direct_br_call_to_orig_addr */
/************************************/
int fix_direct_br_call_to_orig_addr(int instr_map_entry)
{

    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd,&dstate); 
                   
    xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
        return -1;
    }
    
    xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);
    
    if (category_enum != XED_CATEGORY_CALL && category_enum != XED_CATEGORY_UNCOND_BR) {

        cerr << "ERROR: Invalid direct jump from translated code to original code in rotuine: " 
              << RTN_Name(RTN_FindByAddress(instr_map[instr_map_entry].orig_ins_addr)) << endl;
        dump_instr_map_entry(instr_map_entry);
        return -1;
    }

    // check for cases of direct jumps/calls back to the orginal target address:
    if (instr_map[instr_map_entry].targ_map_entry >= 0) {
        cerr << "ERROR: Invalid jump or call instruction" << endl;
        return -1;
    }

    unsigned int ilen = XED_MAX_INSTRUCTION_BYTES;
    unsigned int olen = 0;
                

    xed_encoder_instruction_t  enc_instr;

    ADDRINT new_disp = (ADDRINT)&instr_map[instr_map_entry].orig_targ_addr - 
                       instr_map[instr_map_entry].new_ins_addr - 
                       xed_decoded_inst_get_length (&xedd);

    if (category_enum == XED_CATEGORY_CALL)
            xed_inst1(&enc_instr, dstate, 
            XED_ICLASS_CALL_NEAR, 64,
            xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));

    if (category_enum == XED_CATEGORY_UNCOND_BR)
            xed_inst1(&enc_instr, dstate, 
            XED_ICLASS_JMP, 64,
            xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));


    xed_encoder_request_t enc_req;

    xed_encoder_request_zero_set_mode(&enc_req, &dstate);
    xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
    if (!convert_ok) {
        cerr << "conversion to encode request failed" << endl;
        return -1;
    }
   

    xed_error_enum_t xed_error = xed_encode(&enc_req, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), ilen, &olen);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        dump_instr_map_entry(instr_map_entry); 
        return -1;
    }

    // handle the case where the original instr size is different from new encoded instr:
    if (olen != xed_decoded_inst_get_length (&xedd)) {
        
        new_disp = (ADDRINT)&instr_map[instr_map_entry].orig_targ_addr - 
                   instr_map[instr_map_entry].new_ins_addr - olen;

        if (category_enum == XED_CATEGORY_CALL)
            xed_inst1(&enc_instr, dstate, 
            XED_ICLASS_CALL_NEAR, 64,
            xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));

        if (category_enum == XED_CATEGORY_UNCOND_BR)
            xed_inst1(&enc_instr, dstate, 
            XED_ICLASS_JMP, 64,
            xed_mem_bd (XED_REG_RIP, xed_disp(new_disp, 32), 64));


        xed_encoder_request_zero_set_mode(&enc_req, &dstate);
        xed_bool_t convert_ok = xed_convert_to_encoder_request(&enc_req, &enc_instr);
        if (!convert_ok) {
            cerr << "conversion to encode request failed" << endl;
            return -1;
        }

        xed_error = xed_encode (&enc_req, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), ilen , &olen);
        if (xed_error != XED_ERROR_NONE) {
            cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
            dump_instr_map_entry(instr_map_entry);
            return -1;
        }        
    }

    
    // debug prints:
    if (KnobVerbose) {
        dump_instr_map_entry(instr_map_entry); 
    }
        
    instr_map[instr_map_entry].hasNewTargAddr = true;
    return olen;    
}


/***********************************/
/* fix_direct_br_call_displacement */
/***********************************/
int fix_direct_br_call_displacement(int instr_map_entry) 
{                    

    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd,&dstate); 
                   
    xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
        return -1;
    }

    xed_int32_t  new_disp = 0;    
    unsigned int size = XED_MAX_INSTRUCTION_BYTES;
    unsigned int new_size = 0;


    xed_category_enum_t category_enum = xed_decoded_inst_get_category(&xedd);
    
    if (category_enum != XED_CATEGORY_CALL && category_enum != XED_CATEGORY_COND_BR && category_enum != XED_CATEGORY_UNCOND_BR) {
        cerr << "ERROR: unrecognized branch displacement" << endl;
        return -1;
    }

    // fix branches/calls to original targ addresses:
    if (instr_map[instr_map_entry].targ_map_entry < 0) {
       int rc = fix_direct_br_call_to_orig_addr(instr_map_entry);
       return rc;
    }

    ADDRINT new_targ_addr;        
    new_targ_addr = instr_map[instr_map[instr_map_entry].targ_map_entry].new_ins_addr;
        
    new_disp = (new_targ_addr - instr_map[instr_map_entry].new_ins_addr) - instr_map[instr_map_entry].size; // orig_size;

    xed_uint_t   new_disp_byts = 4; // num_of_bytes(new_disp);  ???

    // the max displacement size of loop instructions is 1 byte:
    xed_iclass_enum_t iclass_enum = xed_decoded_inst_get_iclass(&xedd);
    if (iclass_enum == XED_ICLASS_LOOP ||  iclass_enum == XED_ICLASS_LOOPE || iclass_enum == XED_ICLASS_LOOPNE) {
      new_disp_byts = 1;
    }

    // the max displacement size of jecxz instructions is ???:
    xed_iform_enum_t iform_enum = xed_decoded_inst_get_iform_enum (&xedd);
    if (iform_enum == XED_IFORM_JRCXZ_RELBRb){
      new_disp_byts = 1;
    }

    // Converts the decoder request to a valid encoder request:
    xed_encoder_request_init_from_decode (&xedd);

    //Set the branch displacement:
    xed_encoder_request_set_branch_displacement (&xedd, new_disp, new_disp_byts);

    xed_uint8_t enc_buf[XED_MAX_INSTRUCTION_BYTES];
    unsigned int max_size = XED_MAX_INSTRUCTION_BYTES;
    
    xed_error_enum_t xed_error = xed_encode (&xedd, enc_buf, max_size , &new_size);
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) <<  endl;
        char buf[2048];        
        xed_format_context(XED_SYNTAX_INTEL, &xedd, buf, 2048, static_cast<UINT64>(instr_map[instr_map_entry].orig_ins_addr), 0, 0);
        cerr << " instr: " << "0x" << hex << instr_map[instr_map_entry].orig_ins_addr << " : " << buf <<  endl;
          return -1;
    }        

    new_targ_addr = instr_map[instr_map[instr_map_entry].targ_map_entry].new_ins_addr;

    new_disp = new_targ_addr - (instr_map[instr_map_entry].new_ins_addr + new_size);  // this is the correct displacemnet.

    //Set the branch displacement:
    xed_encoder_request_set_branch_displacement (&xedd, new_disp, new_disp_byts);
    
    xed_error = xed_encode (&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), size , &new_size); // &instr_map[i].size
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        dump_instr_map_entry(instr_map_entry);
        return -1;
    }                

    //debug print of new instruction in tc:
    if (KnobVerbose) {
        dump_instr_map_entry(instr_map_entry);
    }

    return new_size;
}   



int chain_all_direct_br_and_call_target_entries()
{
	for (int i=0; i < num_of_instr_map_entries; i++) {			    

		if (instr_map[i].orig_targ_addr == 0)
			continue;

		if (instr_map[i].hasNewTargAddr)
			continue;

        for (int j = 0; j < num_of_instr_map_entries; j++) {

            if (j == i)
			   continue;
	
            if (instr_map[j].orig_ins_addr == instr_map[i].orig_targ_addr) {
                instr_map[i].hasNewTargAddr = true; 
	            instr_map[i].targ_map_entry = j;
                break;
			}
		}
	}
   
	return 0;
}

/**************************/
/* fix_rip_displacement() */
/**************************/
int fix_rip_displacement(int instr_map_entry) 
{
    //debug print:
    //dump_instr_map_entry(instr_map_entry);

    xed_decoded_inst_t xedd;
    xed_decoded_inst_zero_set_mode(&xedd,&dstate); 
                   
    xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), max_inst_len);
    if (xed_code != XED_ERROR_NONE) {
        cerr << "ERROR: xed decode failed for instr at: " << "0x" << hex << instr_map[instr_map_entry].new_ins_addr << endl;
        return -1;
    }

    unsigned int memops = xed_decoded_inst_number_of_memory_operands(&xedd);

    if (instr_map[instr_map_entry].orig_targ_addr != 0)  // a direct jmp or call instruction.
        return 0;

    //cerr << "Memory Operands" << endl;
    bool isRipBase = false;
    xed_reg_enum_t base_reg = XED_REG_INVALID;
    xed_int64_t disp = 0;
    for(unsigned int i=0; i < memops ; i++)   {

        base_reg = xed_decoded_inst_get_base_reg(&xedd,i);
        disp = xed_decoded_inst_get_memory_displacement(&xedd,i);

        if (base_reg == XED_REG_RIP) {
            isRipBase = true;
            break;
        }
        
    }

    if (!isRipBase)
        return 0;

            
    //xed_uint_t disp_byts = xed_decoded_inst_get_memory_displacement_width(xedd,i); // how many byts in disp ( disp length in byts - for example FFFFFFFF = 4
    xed_int64_t new_disp = 0;
    xed_uint_t new_disp_byts = 4;   // set maximal num of byts for now.

    unsigned int orig_size = xed_decoded_inst_get_length (&xedd);

    // modify rip displacement. use direct addressing mode:    
    new_disp = instr_map[instr_map_entry].orig_ins_addr + disp + orig_size; // xed_decoded_inst_get_length (&xedd_orig);
    xed_encoder_request_set_base0 (&xedd, XED_REG_INVALID);

    //Set the memory displacement using a bit length 
    xed_encoder_request_set_memory_displacement (&xedd, new_disp, new_disp_byts);

    unsigned int size = XED_MAX_INSTRUCTION_BYTES;
    unsigned int new_size = 0;
            
    // Converts the decoder request to a valid encoder request:
    xed_encoder_request_init_from_decode (&xedd);
    
    xed_error_enum_t xed_error = xed_encode (&xedd, reinterpret_cast<UINT8*>(instr_map[instr_map_entry].encoded_ins), size , &new_size); // &instr_map[i].size
    if (xed_error != XED_ERROR_NONE) {
        cerr << "ENCODE ERROR: " << xed_error_enum_t2str(xed_error) << endl;
        dump_instr_map_entry(instr_map_entry); 
        return -1;
    }                

    if (KnobVerbose) {
        dump_instr_map_entry(instr_map_entry);
    }

    return new_size;
}



/************************************/
/* fix_instructions_displacements() */
/************************************/
int fix_instructions_displacements()
{
   // fix displacemnets of direct branch or call instructions:

    int size_diff = 0;    

    do {
        
        size_diff = 0;

        if (KnobVerbose) {
            cerr << "starting a pass of fixing instructions displacements: " << endl;
        }

        for (int i=0; i < num_of_instr_map_entries; i++) {

            instr_map[i].new_ins_addr += size_diff;
                   
            int new_size = 0;

            // fix rip displacement:            
            new_size = fix_rip_displacement(i);
            if (new_size < 0)
                return -1;

            if (new_size > 0) { // this was a rip-based instruction which was fixed.

                if (instr_map[i].size != (unsigned int)new_size) {
                   size_diff += (new_size - instr_map[i].size);                     
                   instr_map[i].size = (unsigned int)new_size;                                
                }

                continue;   
            }

            // check if it is a direct branch or a direct call instr:
            if (instr_map[i].orig_targ_addr == 0) {
                continue;  // not a direct branch or a direct call instr.
            }


            // fix instr displacement:            
            new_size = fix_direct_br_call_displacement(i);
            if (new_size < 0)
                return -1;

            if (instr_map[i].size != (unsigned int)new_size) {
               size_diff += (new_size - instr_map[i].size);
               instr_map[i].size = (unsigned int)new_size;
            }

        }  // end int i=0; i ..

    } while (size_diff != 0);

   return 0;
 }
 
 
 /***************************/
/* int copy_instrs_to_tc() */
/***************************/
int copy_instrs_to_tc()
{
    int cursor = 0;

    for (int i=0; i < num_of_instr_map_entries; i++) {

      if ((ADDRINT)&tc[cursor] != instr_map[i].new_ins_addr) {
          cerr << "ERROR: Non-matching instruction addresses: " << hex << (ADDRINT)&tc[cursor] << " vs. " << instr_map[i].new_ins_addr << endl;
          return -1;
      }      

      memcpy(&tc[cursor], &instr_map[i].encoded_ins, instr_map[i].size);

      cursor += instr_map[i].size;
    }

    return 0;
}


VOID ImageLoad(IMG img, VOID* v)
{

    // Step 0: Check the image and the CPU:
    if (!IMG_IsMainExecutable(img))
        return;
    // Step 1: Fetch top ten routines. On failer exit ImageLoad.
    if (!GetTopTenRtns()) {
        return;
    }
    if (!GetInlineFunctionCandidates()) {
        return;
    }
    if (!GetReorderedRoutineMap()) {
        return;
    }

    int rc = 0;

    // step 2: Check size of executable sections and allocate required memory:	
    rc = allocate_and_init_memory(img);
    if (rc < 0)
        return;

    cout << "after memory allocation" << endl;


    // Step 3: go over all routines and identify candidate routines and copy their code into the instr map IR:
    rc = findCandidateRoutinesForTranslation(img);
    if (rc < 0)
        return;

    cout << "after identifying candidate routines" << endl;

    // Step 4: Chaining - calculate direct branch and call instructions to point to corresponding target instr entries:
    rc = chain_all_direct_br_and_call_target_entries();
    if (rc < 0)
        return;

    cout << "after calculate direct br targets" << endl;

    // Step 5: fix rip-based, direct branch and direct call displacements:
    rc = fix_instructions_displacements();
    if (rc < 0)
        return;

    cout << "after fix instructions displacements" << endl;


    // Step 6: write translated routines to new tc:
    rc = copy_instrs_to_tc();
    if (rc < 0)
        return;
	
    cout << "after write all new instructions to memory tc" << endl;
	
    if (KnobDumpTranslatedCode) {
        cerr << "Translation Cache dump:" << endl;
        dump_tc();  // dump the entire tc

        cerr << endl << "instructions map dump:" << endl;
        dump_entire_instr_map();     // dump all translated instructions in map_instr
    }


    // Step 7: Commit the translated routines:
    //Go over the candidate functions and replace the original ones by their new successfully translated ones:
    if (!KnobDoNotCommitTranslatedCode) {
        commit_translated_routines();
        cout << "after commit translated routines" << endl;
    }
    
}



VOID Fini(INT32 code, VOID* v) {
    std::ofstream output_file("count.csv", std::ofstream::out);

    // Write the headers to the CSV file
    output_file << "Routine Name,Address,Instruction Count,Call Count,Is Recursive,Dominate Call,Is Candidate?\n";

    // Convert map to vector for sorting
    std::vector<std::pair<ADDRINT, RoutineProfile>> routines(rtn_map.begin(), rtn_map.end());

    // Sort routines by instruction_count (this can be adjusted based on your criteria)
    std::sort(routines.begin(), routines.end(), 
              [](const std::pair<ADDRINT, RoutineProfile>& a, const std::pair<ADDRINT, RoutineProfile>& b) {
                  return a.second.instruction_count > b.second.instruction_count;
              });

    // Write the sorted routines to the CSV file
    for (const auto& entry : routines) {
		ADDRINT address = entry.first;
		const RoutineProfile& routine = entry.second;
		if (routine.name.empty()){
			continue;
		}
        output_file << routine.name << ","
                    << "0x" << std::hex << address << ","
                    << std::dec << routine.instruction_count << ","
                    << routine.call_count << ","
                    << routine.is_recursive << ","
                    << "0x" << std::hex << routine.dominate_call() << ","
                    << (routine.is_candidate() ? "Yes" : "No") << "\n";
    }

    output_file.close();
}

INT32 Usage()
{
    cerr << "This tool prints out the number of dynamic instructions executed to stderr.\n"
        "\n";

    cerr << KNOB_BASE::StringKnobSummary();

    cerr << endl;

    return -1;
}



int main(int argc, char* argv[])
{

    PIN_InitSymbols();
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }
    if (KnobProf) {
        INS_AddInstrumentFunction(profile_loops_and_instructions, 0);
        TRACE_AddInstrumentFunction(profile_basic_blocks, 0);
        RTN_AddInstrumentFunction(profile_conditional_branches, 0);
        INS_AddInstrumentFunction(profile_routine_calls, 0);
        PIN_AddFiniFunction(Fini, 0);
        PIN_StartProgram();
    }
    else if (KnobOpt) {
        IMG_AddInstrumentFunction(ImageLoad, 0);
        PIN_StartProgramProbed();
    }
    else {
        PIN_StartProgram();
    }
    return 0;
}

