/*
 * Copyright 2002-2020 Intel Corporation.
 * 
 * This software is provided to you as Sample Source Code as defined in the accompanying
 * End User License Agreement for the Intel(R) Software Development Products ("Agreement")
 * section 1.L.
 * 
 * This software and the related documents are provided as is, with no express or implied
 * warranties, other than those that are expressly stated in the License.
 */

/*
 *  This test checks bogus symbol size
 */

#include <iostream>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <unordered_set>
#include <map>
#include <unistd.h>
#include <set>

using namespace std;


#include "pin.H"
using std::cerr;
using std::ofstream;
using std::hex;
using std::string;
using std::endl;
using std::cout;
using std::pair;
using std::map;


KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,         "pintool",
                            "o", "elf_symsize.out", "specify output file name");
KNOB<INT32>  KnobFilterByHighNibble(KNOB_MODE_WRITEONCE, "pintool",
    "f", "-1",         "only instrument instructions with a code address matching the filter");
KNOB<BOOL>   KnobPid(KNOB_MODE_WRITEONCE,                "pintool",
                     "i", "0", "append pid to output");

//ofstream outfile;

set <long unsigned int> addrSet;
long unsigned int main_addr = 0x0;


/* ===================================================================== */



VOID ImageLoad(IMG img, void *v)
{
    if (!IMG_IsMainExecutable(img))
    {
        //out << "Ignoring image: " << IMG_Name(img) << endl;
        return;
    }

    //out << "Parsing image: " << IMG_Name(img) << endl;
    for( SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym) )
    {
        //cout << "Symbol " << SYM_Name(sym) << " address 0x" << hex << SYM_Address(sym) << endl;

        // record address of main func
        string cmp = SYM_Name(sym);
        if(cmp.compare("main") == 0){
                main_addr = SYM_Address(sym);
                //cout << "main address ....." << SYM_Address(sym) << endl;

        }

        addrSet.insert(SYM_Address(sym));

        RTN rtn = RTN_FindByName(img, SYM_Name(sym).c_str());
        if (!RTN_Valid(rtn))
        {
            //out << "Routine not found, continue..." << endl;
            continue;
        }

        cout << "Routine " << RTN_Name(rtn) << " address 0x"
                << hex << RTN_Address(rtn) << " size 0x"
                << hex << RTN_Size(rtn) << endl;


        addrSet.insert(RTN_Address(rtn));
    }

}




/* get indirect calls*/

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

class COUNTER
{
  public:
    UINT64 _count;       // number of times the edge was traversed

    COUNTER() : _count(0)   {}
};

typedef enum
{
    ETYPE_INVALID,
    ETYPE_CALL,
    ETYPE_ICALL,
    ETYPE_BRANCH,
    ETYPE_IBRANCH,
    ETYPE_RETURN,
    ETYPE_SYSCALL,
    ETYPE_LAST
}ETYPE;

class EDGE
{
  public:
    ADDRINT _src;
    ADDRINT _dst;
    ADDRINT _next_ins;
    ETYPE   _type; // must be integer to make stl happy

    EDGE(ADDRINT s, ADDRINT d, ADDRINT n, ETYPE t) :
        _src(s),_dst(d), _next_ins(n),_type(t)  {}

    bool operator <(const EDGE& edge) const
    {
        return _src < edge._src || (_src == edge._src && _dst < edge._dst);
    }

};


string StringFromEtype( ETYPE etype)
{
    switch(etype)
    {
      case ETYPE_CALL:
        return "C";
      case ETYPE_ICALL:
        return "c";
      case ETYPE_BRANCH:
        return "B";
      case ETYPE_IBRANCH:
        return "b";
      case ETYPE_RETURN:
        return "r";
      case ETYPE_SYSCALL:
        return "s";
      default:
        ASSERTX(0);
        return "INVALID";
    }
}

typedef map< EDGE, COUNTER*> EDG_HASH_SET;

static EDG_HASH_SET EdgeSet;



/* ===================================================================== */

/*!
  An Edge might have been previously instrumented, If so reuse the previous entry
  otherwise create a new one.
 */

static COUNTER * Lookup( EDGE edge)
{
    COUNTER *& ref =   EdgeSet[ edge ];

    if( ref == 0 )
    {
        ref = new COUNTER();
    }

    return ref;
}

/* ===================================================================== */


VOID docount( COUNTER *pedg )
{
    pedg->_count++;
}

/* ===================================================================== */
// for indirect control flow we do not know the edge in advance and
// therefore must look it up

VOID docount2( ADDRINT src, ADDRINT dst, ADDRINT n, ETYPE type, INT32 taken )
{
    if(!taken) return;
    COUNTER *pedg = Lookup( EDGE(src,dst,n,type) );
    pedg->_count++;
}

/* ===================================================================== */




/* ===================================================================== */

VOID Instruction(INS ins, void *v)
{

   if (INS_MemoryBaseReg(ins) != REG_RIP){

        if (INS_IsDirectControlFlow(ins))
    {
        ETYPE type = INS_IsCall(ins) ? ETYPE_CALL : ETYPE_BRANCH;

        // static targets can map here once
        COUNTER *pedg = Lookup( EDGE(INS_Address(ins),  INS_DirectControlFlowTargetAddress(ins),
                                     INS_NextAddress(ins), type) );
        INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR) docount, IARG_ADDRINT, pedg, IARG_END);
    }
    else if( INS_IsIndirectControlFlow(ins) )
    {
        ETYPE type = ETYPE_IBRANCH;

        if( INS_IsRet(ins) )
        {
            type = ETYPE_RETURN;
        }
        else if (INS_IsCall(ins) )
        {
            type = ETYPE_ICALL;
        }

        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) docount2,
                       IARG_INST_PTR,
                       IARG_BRANCH_TARGET_ADDR,
                       IARG_ADDRINT, INS_NextAddress(ins),
                       IARG_UINT32, type,
                       IARG_BRANCH_TAKEN,
                       IARG_END);
    }
    else if( INS_IsSyscall(ins) )
    {
        COUNTER *pedg = Lookup( EDGE(INS_Address(ins),  ADDRINT(~0),INS_NextAddress(ins) ,ETYPE_SYSCALL) );
        INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR) docount, IARG_ADDRINT, pedg, IARG_END);
    }
   }
}


/* ===================================================================== */

inline INT32 AddressHighNibble(ADDRINT addr)
{
        return addr;
    //return  0xf & (addr >> (sizeof(ADDRINT)* 8 - 4));
}

/* ===================================================================== */



/* ===================================================================== */
static std::ofstream* out = 0;

VOID Fini(int n, void *v)
{
    SetAddress0x(1);

    const INT32 nibble = KnobFilterByHighNibble.Value();

    *out << "EDGCOUNT        4.0         0\n";  // profile header, no md5sum
    *out << "very_big\n";  // profile header, no md5sum
    UINT32 count = 0;

    for( EDG_HASH_SET::const_iterator it = EdgeSet.begin(); it !=  EdgeSet.end(); it++ )
    {
        const pair<EDGE, COUNTER*> tuple = *it;
        // skip inter shared lib edges

        if( nibble >= 0  && nibble != AddressHighNibble(tuple.first._dst)  &&
            nibble != AddressHighNibble(tuple.first._src) )
        {
            continue;
        }

        if( tuple.second->_count == 0 ) continue;

        count++;
    }

    for( EDG_HASH_SET::const_iterator it = EdgeSet.begin(); it !=  EdgeSet.end(); it++ )
    {
        const pair<EDGE, COUNTER*> tuple = *it;

        // skip inter shared lib edges

        if( nibble >= 0  && nibble != AddressHighNibble(tuple.first._dst)  &&
            nibble != AddressHighNibble(tuple.first._src) )
        {
            continue;
        }

        if( tuple.second->_count == 0 ) continue;

        if(StringFromEtype(tuple.first._type) == "c"){
		if(tuple.first._dst <= main_addr){
			if(addrSet.find(tuple.first._dst) == addrSet.end()){
				cout << "CFI voilated" << endl;
			}
	}	
        //*out <<StringFromEtype(tuple.first._type) << " " << hex << tuple.first._dst << " " << endl;
        }
    }

    out->close();
}

/*
VOID Fini2(INT32 code, VOID *v)
{
    outfile << "Symbol test passed successfully" << endl;
    outfile.close();
}

*/

/* ===================================================================== */
/* Print Help Message.                                                   */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This is the invocation pintool" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}


/* ===================================================================== */
/* Main.                                                                 */
/* ===================================================================== */

int main(int argc, char * argv[])
{
    PIN_InitSymbols();

    if (PIN_Init(argc, argv)) return Usage();


    string filename =  KnobOutputFile.Value();
    if (KnobPid)
    {
        filename += "." + decstr(getpid());
    }
    out = new std::ofstream(filename.c_str());


    IMG_AddInstrumentFunction(ImageLoad, 0);
    INS_AddInstrumentFunction(Instruction, 0);

    PIN_AddFiniFunction(Fini, 0);
    //PIN_AddFiniFunction(Fini2, 0);

    PIN_StartProgram();

    return 0;
}



/* ================================================================== */
