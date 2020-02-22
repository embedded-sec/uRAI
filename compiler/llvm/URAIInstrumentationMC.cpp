//===- URAIAnalysis.cpp -------------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// Performs analysis to obtain call graph and write it to JSON file
//
//===----------------------------------------------------------------------===//


//===-----------------------------Includes--------------------------------===//


#include "ARM.h"
#include "MCTargetDesc/ARMAddressingModes.h"
#include "ARMMachineFunctionInfo.h"
#include "Thumb2InstrInfo.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/MachineInstrBundle.h"
#include "ARMBaseInstrInfo.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "json/json.h"
#include <fstream>
#include <iostream>
#include <algorithm>
using namespace llvm;


//===-----------------------------Defines--------------------------------===//

#define DEBUG_EXMP_STR              "func"
#define DEBUG_TYPE                  "urai-mc"

/// file name for debugging file during development
#define URAI_MC_DEBUG_FILE_NAME     "urai-mc-debug.txt"
#define URAI_MC_ANALYSIS_FILE_NAME  "urai-mc-analysis.txt"
#define MCINSTR_VECTOR_SIZE         32
#define EXT_LIB_FILE_NAME           "STD_LIB.json"
#define EXT_LIB_OPT_LIST_FILE_NAME  "EXT_LIB_OPT_LIST.json"
#define MAX_APPEND_FLT_SIZE         1
#define USED_LABELS_FILE            "USED_LABELS.json"
#define MEM_OVERHEAD_STATS          "mem-overhead-stats.json"
#define BIN_FLT_EFF                 "bin-flt-eff.json"
#define SVC_EHSFI_STATS             "svc-ehsfi-calls-stats.json"
#define MPU_RNR                     0xE000ED98

// These are the feilds of the input JSON file
#define JSON_KEY                    "KEY"
#define JSON_SHIFT                  "SHIFT"
#define JSON_XOR_INST               "XOR_INST_KEY"
#define JSON_ADD_REC_INST           "ADD_REC_INST_KEY"
#define JSON_SUB_REC_INST           "SUB_REC_INST_KEY"
#define JSON_KEYS_DICT              "KEYS_DICT"
#define JSON_INFLAGS                "INFLAGS"
#define JSON_RET_INSTS              "RET_INSTS"
#define JSON_MAX_INFLAG             "MAX_INFLAG_KEY"
#define JSON_LABEL                  "LABEL"
#define JSON_B_INST                 "B_INST_KEY"
#define JSON_LDR_INST               "LDR_INST_KEY"
#define JSON_MOV1_INST              "MOV1_INST_KEY"
#define JSON_MOV2_INST              "MOV2_INST_KEY"
#define JSON_UNSPRTD_LIB            "IS_UNSUPPORTED_LIB"
#define JSON_OPMTIMIZABLE_EXTLIB    "OPTIMIZABLE_FUNC"
#define JSON_IS_SHIFTED             "IS_SHIFTED"
#define JSON_ISREC                  "IS_RECURSIVE"
#define JSON_ISPATHREC              "IS_PATH_RECURSIVE"
#define JSON_IS_MULTI_RECURSIVE     "IS_MULTI_RECURSIVE"
#define JSON_IS_ENTRY               "IS_ENTRY"
#define JSON_IS_SINGULAR            "IS_SINGULAR"
#define INDIR_SUFFIX                "Indir"
#define JSON_TCFI_SET               "TCFI_SET"
#define JSON_TCFI_INSTRMNT          "TCFI_INSTRMNT"
#define JSON_TCFI_LBL               "TCFI_LBL"
#define JSON_TCFI_EXIT              "TCFI_EXIT"
#define JSON_RECURSION_SIZE_KEY     "RECURSION_SIZE_KEY"
#define JSON_EXIT_LBL               "EXIT_LBL_KEY"
#define JSON_EXIY_SYM               "EXIT_SYM_KEY"
#define JSON_EXIT_B_INST            "EXIT_BRANCH"
#define JSON_START_LBL              "START_LBL_KEY"
#define JSON_TRAMPOLINE_INST        "TRAMPOLINE_INST_KEY"
#define JSON_SR_RESET               "REQ_SR_RESET_KEY"
#define JSON_RECURSION_CNTR_SHIFT   "RECURSION_CNTR_SHIFT_KEY"
#define JSON_RECURSION_TLR_LBL      "RECURSION_TLR_LBL_KEY"
#define JSON_MOV_REC_TLR_INST_KEY   "MOV_REC_TLR_INST_KEY"
#define JSON_IS_EH_CONTEXT          "IS_EH_CONTEXT"

// These are field names for mem-overhead-stats file
#define JSON_TCFI_OH                "tcfi-overhead-bytes"
#define JSON_FLT_OH                 "flt-overhead-bytes"
#define JSON_EHSFI_OH               "ehsfi-overhead-bytes"
#define JSON_EHSFI_INSTRS           "ehsfi-instrs"
#define JSON_SVC_INSTRS             "svc-instrs"
#define JSON_NUM_DIR_CALLS          "dir-calls"
#define JSON_NUM_URAI_CALLS         "urai-calls"
#define JSON_NUM_INDIR_CALLS        "indir-calls"
#define JSON_NUM_EXTLIB_CALLS       "extlib-calls"
#define JSON_NUM_TOT_CALLS          "total-calls"


const uint32_t SvcInitMain = 101;
const uint32_t SvcExitMain = 102;
const uint32_t SvcLibSave = 103;
const uint32_t SvcLibRestore = 104;
const uint32_t SvcAppSave = 105;
const uint32_t SvcAppRestore = 106;
const uint32_t SvcEhSFICntr = 109;
const uint32_t SvcRecSave = 110;
const uint32_t SvcRecRestore = 111;

// used for EHSFI
std::string cmp_inst[4] = {
  "cmp r0, #8\n",
  "cmp r0, #3472\n",
  "cmp r1, #8\n",
  "cmp r1, #3472\n"
};

std::string ehsfi_mov_inst[4] = {
  "movw r0,#60824\n",
  "movt r0,#57344\n",
  "movw r1,#60824\n",
  "movt r1,#57344\n"
};

std::string spec_msr_inst[4] = {
  "mrs r0,apsr\n",
  "msr apsr,r0\n",
  "mrs r1,apsr\n",
  "msr apsr,r1\n"
};

std::string opt_extlib_lbl_str = "OPTIMIZED_EXTLIB_LBL_";
uint32_t opt_extlib_cntr = 0;
std::vector<std::string> extlbls_vctr;
std::vector<std::string> extlbls_branch_vctr;
std::set<std::string> ptrList;


static cl::opt<std::string> URAIInstrumentation("urai-instrumentation",
                                  cl::desc("Input JSON file the urai backend "
                                           "uses for the keys and flag IDs."),
                                  cl::init("-"),cl::value_desc("filename"));

static cl::opt<std::string> URAIAppMain("urai-main-init",
                                  cl::desc("The main function of the application "
                                           "that uRAI should use for its initialization."),
                                  cl::init("-"),cl::value_desc("Application main function"));


static cl::opt<std::string> URAIBuildDir("urai-build-dir",
                                  cl::desc("The path to the build directory."),
                                  cl::init("-"),cl::value_desc("build dir"));


static cl::opt<std::string> URAIEhSFIMeasurement("urai-ehsfi-measurement",
                                  cl::desc("Flag for instrumenting the"
                                           " measurement of EHSFI protected"
                                           " store instructions."),
                                  cl::init("-"),cl::value_desc("filename"));

//===-----------------------------MainCode-------------------------------===//


namespace {
  class URAIInstrumentationMCPass : public MachineFunctionPass {
  public:
    static char ID;
    URAIInstrumentationMCPass() : MachineFunctionPass(ID) {}

    std::ifstream InputFd;    // Key-flag-ids input file
    std::ifstream LblsFd;     // used labels input file
    std::ofstream AnalysisFd; // Analysis file
    std::ofstream DbgFd;      // File used for debugging only
    std::ifstream ExtLibFd;
    std::ifstream ExtLibOptFd;
    Json::Value FlagIdRoot;   // The root of the key-flag-ids input file
    Json::Value ExtLibJsonRoot;
    Json::Value ExtLibOptListJsonRoot;
    Json::Value LabelsRoot;   // Root of used labels in the application

    /// This is the first relative jump in RAI's return sequence. It should
    /// point to the correct direct jump in the lookup table. If there is NO
    /// segmentation then we can use lr directly. If there is then we need
    /// to use use r12 for the current segment as lr holds multiple segments.
    std::string FuncRet = "add pc,pc,lr\n";
    std::string FuncRetWithSeg = "add pc,pc,r12\n";
    // this is used for functions/apps with multi or cyclic recursion
    std::string MovLRToR12WithLSL1 = "mov r12, lr, lsl #1\n";
    // this instruction counts the leading zeros in lr, and stores the result
    // in r12. This allows using the leading bit to check if there is
    // multi/cyclic recursion if r12 > 0.
    std::string ClzLRintoR12 = "clz r12, lr\n";
    std::string SVCNERecRestore = "svcne "+ std::to_string(SvcRecRestore) + "\n";
    /// This jump is used for empty indicies in the lookup table since no SR
    /// value matches the given index.
    std::string LTError = "bkpt\n";
    bool InstrumentedInit = false;

    /// variable used to calculate the overhead of FLTs
    uint64_t FLTOverhead = 0;
    uint64_t TCFIOverhead = 0;       // counter of tcfi instrumentation overhead
    uint64_t EHSFIMemOverhead = 0;

    uint64_t EHSFIStrInstrsCntr = 0; // counter for EHSFI instrumented STRs
    uint64_t SVCResetCntr = 0;
    uint64_t DirCallsCntr = 0, IndirCallsCntr = 0, ExtLibCallsCntr = 0,
      TotCallsCntr = 0;              // counters for # of calls

    Json::Value BinFltEff;


    std::map<std::string, unsigned> IndirCallRegMap;

    // A special case is the tcfi-handler, we add all of its instructions once
    // and return. It does not go through the same process as other functions.

    bool runOnMachineFunction(MachineFunction &MF) override{
      bool returnVal = false;
      bool InstrumentedEntry = false; // used to instrument entry to root funcs

      if ( URAIInstrumentation.compare("-") == 0 ){
          return false;
      }

      DbgFd << "Before Check\n";
      // check if we should instrument the function, if not just return false
      if (!MF.getFunction().hasFnAttribute("URAICall")){

        if (MF.getName().compare("__tcfi_handler") != 0){
          outs() << "no-urai: " << MF.getName() << "\n";
          return false;
        }
        outs() << "tcfi: " << MF.getName() << "\n";
      }


      DbgFd << "After check\n";

      // str objs used to write instructions to debgging files
      std::string str;
      raw_string_ostream rso(str);
      // log results to analysis file
      std::string MFName = MF.getName().str();
      std::string line = "Func: " + MFName + " has URAICall attr\n";
      AnalysisFd << line;

      // a map between callees and the call number in the current function.
      // This is used to get the correct label, xor instruction, and key.
      std::map<std::string, uint8_t> CalleeCntrMap;
      // Initialize the machine instruction builder
      MachineInstrBuilder MIB;
      // get the target instruction info
      const ARMBaseInstrInfo &TII =
          *static_cast<const ARMBaseInstrInfo *>(MF.getSubtarget().getInstrInfo());
      MachineBasicBlock *MBBptr;
      MachineInstr *MIptr;

      DbgFd << "********************************************************\n";
      DbgFd << "Function: " << MFName << "\n";

      // A special case is the tcfi-handler, we add all of its instructions once
      // and return. It does not go through the same process as other functions.
      if(MFName.compare("__tcfi_handler") == 0){
        addTCFIHandler(MF, MIB, TII, MFName);
        return true;
      }


      // check if this is a singular function, if this is the case no need
      // to instrument it
      if (FlagIdRoot[MFName][JSON_IS_SINGULAR].asBool() &&
          (
            (MFName.compare("SysTick_Handler") == 0) ||
            (MFName.compare("_sbrk") == 0) // [rei-debug]: fix this with json for syscalls!!
           )){
        return true;
      }

      //------------------------------------------------------------------------
      // Function Entry. We have 3 cases
      // (1) Root User Entry:
      //        These are root functions. We need and initial SVC to
      //        save LR, and then set it to 0 as we will treat LR as
      //        the state register. At the end of the function we need
      //        to restore the saved LR, and return normally.
      // (2) Exception Entry:
      //        These are similar to (1), we need here however to store LR
      //        and PC sepratley and remove them from the stack at entry.
      //        At exit, we write the values again to the stack, and the
      //        HW will handle exiting. This must be done since HW sets
      //        and uses a specific stack frame layout at exception entry
      //        and exit.
      // (3) Normal function:
      //        These are any non-root functions. We do not need to do anything
      //        at the entry of these functions.

      // [rai-debug]: TODO: add entry instrumentation here.

      // loop through every basic block in function
      for (MachineBasicBlock &MBB: MF){

        // create a vector of instructions to be deleted (these are replaced by
        // our instrumented instructions)
        SmallVector<MachineInstr *, MCINSTR_VECTOR_SIZE> DelInstVect;

        for(MachineInstr &MI: MBB){

          auto DbgLoc = MI.getDebugLoc();
          auto Iprev = std::prev(MI.getIterator());
          auto Inext = std::next(MI.getIterator());
          auto I = std::next(MI.getIterator());
          bool isUnrecordedExtLib = false;
          // this var is used to avoid duplicate instrumentation of branch to
          // the TLR. For tail extlib calls we instrument the branch right away
          // and avoid doing this later in the code (i.e., as a normal return)
          bool isExtLibCall = false;

          //--------------------------------------------------------------------
          // [rai-debug]: logging cbz/cbnz instructions and replacing them
          // with CMP and BEQ combination to fix the error of breaking the
          // CBZ/CBNZ optimization limit.
          if (MI.getOpcode() == ARM::tCBZ || MI.getOpcode() == ARM::tCBNZ){
            rso.str().clear();
            rso << "=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*\n" ;
            rso << "A CB instruction: \n";
            rso << MI;
            if (MI.getOpcode() == ARM::tCBZ){
              MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::tCMPi8))
                  .addReg(MI.getOperand(0).getReg())
                  .addImm(0)
                  .add(predOps(ARMCC::AL))
                  .setMIFlag(MachineInstr::RAIInstr);
              MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::t2Bcc))
                  .addMBB(MI.getOperand(1).getMBB())
                  .addImm(ARMCC::EQ)
                  .addReg(ARM::CPSR)
                  .setMIFlag(MachineInstr::RAIInstr);
            }
            // its a CBNZ instruction
            else{
              MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::tCMPi8))
                  .addReg(MI.getOperand(0).getReg())
                  .addImm(0)
                  .add(predOps(ARMCC::AL))
                  .setMIFlag(MachineInstr::RAIInstr);
              MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::t2Bcc))
                  .addMBB(MI.getOperand(1).getMBB())
                  .addImm(ARMCC::NE)
                  .addReg(ARM::CPSR)
                  .setMIFlag(MachineInstr::RAIInstr);
            }

            // add the instruction to deleted vector
            DelInstVect.push_back(&MI);
            rso << "=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*\n" ;
            DbgFd << rso.str();
          }


          //--------------------------------------------------------------------
          // EHSFI: Applying EHSFI is done in 2 parts:
          //        (1) Mask Store instructions.
          //        (2) Verify SP: Store instructions with SP as base register
          //            do not require SFI since we mask MSR/MOV/LDR with SP as
          //            as the destination.

          // Mask store instructions to apply SFI to EH context
          if (FlagIdRoot[MFName][JSON_IS_EH_CONTEXT].asBool() &&
              isSTRInstr(MI.getOpcode()) &&
              !MI.getFlag(MachineInstr::RAIInstr) &&
              (MFName.compare("SysTick_Handler") != 0) &&
              (MFName.compare("HAL_GetTick") != 0)){ // systick/getTick do not require EHSFI
            rso.str().clear();
            rso << "=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*=*\n" ;
            rso << MFName << "\n";
            rso << "A STRInstr instruction: \n";
            rso << MI;
            rso << "\n";

            for (MachineOperand Op: MI.operands()){
              rso << "[OP]: " << Op <<"\n";
            }
            rso <<"------------------------\n";

            instrumentRAIEhSfi(MBB, MIB, MI, Inext, TII);


            // delete the old str instruction
            DelInstVect.push_back(&MI);

            DbgFd << rso.str();
            rso.str().clear();

          }

          // Verify SP value if SP is the destination
          if(changeSP(MI.getOpcode()) && MI.getOperand(0).isReg() &&
             MI.getOperand(0).getReg() == ARM::SP){

            // add bic to mask store
            BuildMI(MBB, Inext, DbgLoc, TII.get(ARM::t2BICri),
                    MI.getOperand(1).getReg())
                .addReg(MI.getOperand(1).getReg())
                .addImm(0xD0000000) // for our board stack starts at 0x20000000
                .add(predOps(ARMCC::AL))
                .add(condCodeOp())
                .setMIFlag(MachineInstr::RAIInstr);

            // re-add the instruction, we do this to make sure the instructions are
            // inlined correctly. (i.e., BIC then a store instruction)
            MIB = BuildMI(MBB, Inext, DbgLoc, TII.get(MI.getOpcode()));
            for(MachineOperand OP: MI.operands()){
              // add the operands of the original instruction to the ext lib
              MIB.add(OP);
            }
            // add RAIInstr flag to avoid duplicate instrumentation
            MIB.setMIFlag(MachineInstr::RAIInstr);

            // update the EHSFI counter
            EHSFIStrInstrsCntr++;

            // update the EHSFI mem overhead
            EHSFIMemOverhead += 4; // 4 bytes from BIC

            // delete the old str instruction
            DelInstVect.push_back(&MI);

            // log instruction accessing SP
            rso << "*[SP]*\n" ;
            rso << MFName << "\n";
            rso << "SP instruction: \n";
            rso << MI;
            rso << "\n";

            for (MachineOperand Op: MI.operands()){
              rso << "[OP]: " << Op <<"\n";
            }
            rso <<"------------------------\n";
            DbgFd << rso.str();
            rso.str().clear();

          }

          // End of EHSFI
          //--------------------------------------------------------------------
          // end of [rai-debug]

          // First step is to add uRAI's initialization. First check if the
          // function is the one specified for initialization, and that we have
          // not add the initialzation sequence before.
          if (MFName.compare(URAIAppMain) == 0 && !InstrumentedInit){

            // A direct call to __urai_init
            MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
                .add(MachineOperand::CreateES("b __urai_init\n")).addImm(1)
                .setMIFlag(MachineInstr::RAIInstr);
            // This label is used by the initialization function as its
            // return target
            MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
                .add(MachineOperand::CreateES("RAI_INIT:\n")).addImm(1)
                .setMIFlag(MachineInstr::RAIInstr);


            // set instrumentInit to true
            InstrumentedInit = true;
          }

          // for other root functions (i.e., exception handlers) we need to
          // instrument it with saving LR and setting SR to its initial value
          if (FlagIdRoot[MFName][JSON_IS_ENTRY].asBool() &&
              MFName.compare(URAIAppMain) != 0 && !InstrumentedEntry){

            instrumentISREntry(MBB, MIB, MI, I, TII);
            // set to true to avoid re-instrumenting again
            InstrumentedEntry = true;
          }


          //--------------------------------------------------------------------
          // (1) handle call instructions <B/BL/BLX>
          //--------------------------------------------------------------------
          // check if it is a call and exclude SVCs from instrumentation, or
          // instructions we instrumented before
          // (e.g., an ext lib already instrumented)
          if(MI.isCall() && MI.getOpcode() != ARM::tSVC &&
             !MI.getFlag(MachineInstr::RAIInstr)){
            // Calls have 4 cases:
            // (1) Supported & direct:
            //        These are supported by RAI. The steps are:
            //        [1] Add an instruction to xor LR with the key before the call
            //        [2] Replace BL with B
            //        [3] Add return label after the call
            //        [4] Add xor with the same key to restore LR
            // (2) Supported & indirect:
            //        These are supported by RAI & typed-CFI:
            //        [1] Add TSTEQ block for target set. Each target has its
            //            own xor key? (probably one!)
            //        [2] Replace BLX with BX.
            //        [3] Add return label
            //        [4] add xor with the same key to resotre LR
            // (3) Supported & recursive:
            //        [1] Add an addition instructio to recursion counter
            //        [2] Replace BL/BLX with B/BX
            //        [3] Add label after call
            //        [4] Add subtract after label to restore LR
            // (3) Unsupported Libs:
            //        These are any pre-compiled libraries that
            //        are not supported by RAI. In order to maintain correct
            //        functionality, we wrap the call with 2 SVCs. One is to
            //        save SR. Then the call executes normally. Afterwards, we
            //        have an SVC to restore the saved value of SR.
            // debug
            rso.str().clear();
            rso << "[+] call instr: " ;
            rso << MI;
            DbgFd << rso.str();

            // update total calls counter
            TotCallsCntr++;

            // (1) if this is a direct call
            if (!isIndirectCall(MI.getOpcode())){
              // update direct calls counter
              DirCallsCntr++;

              // First, we need to get the callee name
              uint32_t CalleeOpIdx = getCalleeOpIdx(MI, true);
              std::string LBL = getURAILabel(MFName, MI.getOperand(CalleeOpIdx),
                                             &CalleeCntrMap, true);


              outs() << "LBL direct[" << MFName << "]: " << LBL << "\n";

              std::string CalleeName = getCalleeName(MI.getOperand(CalleeOpIdx));

              // The analysis pass seems to miss some of newlib funcs, so this
              // is an additional check
              if(FlagIdRoot[CalleeName].get(JSON_UNSPRTD_LIB,"") == ""){
                outs() << "[-] Could not find <" << CalleeName << "> in JSON!\n";
                if(ExtLibJsonRoot.get(CalleeName,"") != ""){
                  isUnrecordedExtLib = true;
                  FlagIdRoot[CalleeName][JSON_UNSPRTD_LIB] = true;
                  outs() << "[!] Unrecorded external lib function!  -> " <<
                            CalleeName << ", LBL: " << LBL << "\n";
                }

              }


              //----------------------------------------------------------------
              // (1.1) extrernal lib direct call
              // check if the callee from code supported by RAI or an
              // external code
              if(FlagIdRoot[CalleeName][JSON_UNSPRTD_LIB].asBool() ||
                 isUnrecordedExtLib){

                // update extlib counter
                ExtLibCallsCntr++;

                // set the ext lib flag
                isExtLibCall = true;
                rso.str().clear();
                rso << "Unsupported Lib call:\n";

                rso << "ExtLib call: " << MFName <<"[" << CalleeName <<"]\n";


                if (!isBLCall(MI.getOpcode())){
                  //MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::tBL));
                  rso << "[eit lib instr]: " << MI << "\n";
                  for(MachineOperand OP: MI.operands()){
                    rso << "[ext_lib] tBL[OP]: " << OP << "\n";
                    // add operand
                    //MIB.add(OP);
                  }
                  //MIB.add(condCodeOp()).setMIFlag(MachineInstr::RAIInstr);
                }
                DbgFd << rso.str();

                // check if handling the external call can be handled in
                // a more efficient method.
                bool is_opt_extlib  = isOptmizableExtlib(CalleeName);

                // instrument the call
                instrumentRAIUnsuprtdLib(MBB, MIB, MI, Iprev, Inext, TII,
                                         is_opt_extlib);
                // add the original ext lib call instruction to deleted vector
                // since we already replaced it in instrumentRAIUnsuprtdLib
                // This is done to make sure the ext lib call is inlined with
                // the corresponding SVCs for correct functionality
                DelInstVect.push_back(&MI);
              }

              //----------------------------------------------------------------
              // (1.2) recursive call
              // is the call a recursive call
              else if(FlagIdRoot[MFName][JSON_KEYS_DICT][LBL][JSON_ISREC].asBool()){
                errs() << "In RECURSIVE: LBL= " << LBL << "\n";
                // add the instruction to deleted vector
                DelInstVect.push_back(&MI);

                // instrument normal call
                instrumentRAIRecursiveCall(MBB, MIB, MI,I, Iprev, Inext, TII,
                                        MFName, LBL );
              }


              //----------------------------------------------------------------
              // (1.3) direct call
              // otherwise, it is a normal call without special cases
              else{

                // add the instruction to deleted vector
                DelInstVect.push_back(&MI);

                // instrument normal call
                instrumentRAIDirectCall(MBB, MIB, MI,I, Iprev, Inext, TII,
                                        MFName, LBL );

              }

            }

            // if it is an indirect call
            else{

              // update indir calls counter
              IndirCallsCntr++;

              rso.str().clear();
              // First, we need to get the indirect label
              uint32_t CalleeOpIdx = getCalleeOpIdx(MI, false);
              std::string LBL = getURAILabel(MFName, MI.getOperand(CalleeOpIdx),
                                             &CalleeCntrMap, false);
              outs() << "LBL INdirect[" << MFName << "]: " << LBL << "\n";

              // add the instruction to deleted vector
              DelInstVect.push_back(&MI);
              addTCFICheck(MBB, MIB, MI, I, Iprev, Inext,  TII, MFName, LBL);

            }

          }

          //--------------------------------------------------------------------
          // (2) handle inline assembluy
          //--------------------------------------------------------------------

          // [urai-debug]
          if (MI.isInlineAsm()){
            rso.str().clear();
            rso << "[+] Inline ASM instr: ";
            rso << MI;
            if (MI.getFlag(MachineInstr::RAIInstr)){
              rso << "HAS RAIInstr flag!!\n";
            }
            rso << "=============================\n";
            rso << "INLINE operands for : " << MI << "\n";
            uint i = 0;
            for(MachineOperand OP: MI.operands()){
              rso <<  "[" << i << "] ";
              rso << OP << "\n";
            }
            rso << "==------ End of operands ------==\n";
            DbgFd << rso.str();
            rso.str().clear();
            DbgFd << rso.str();
          }


          //------------------------------------------------------------------
          // (3) handle push/ldmia instructions using LR <push {r...., lr..}
          //------------------------------------------------------------------
          // will need to tag to changed PUSH to avoid an infinite loop. Using
          // a custmoized PUSH in *.td file is an option but will probably
          // confuse LLVM, so metadata or a tag seem a better choice.
          // maybe just check if LR is in the push is enough though
          if (MI.getOpcode() == ARM::tPUSH || MI.getOpcode() == ARM::t2LDMIA
              || MI.getOpcode() == ARM::t2LDMIA_UPD){

            auto Opcode = MI.getOpcode();
            if (isRegInOperands(MI, ARM::LR)){

              // add the instruction to deleted vector
              DelInstVect.push_back(&MI);

              // create new instruction
              MIB = BuildMI(MBB, I, DbgLoc,TII.get(Opcode));

              // The new instruction should be the same except that we remove
              // the uses of LR
              for(MachineOperand OP: MI.operands()){
                if(OP.isReg()){
                  // if LR is within the regs, skip it
                  if (OP.getReg() == ARM::LR){
                    continue;
                  }
                }
                // add operand if it is not LR
                MIB.add(OP);
              }

              auto ModMI = MIB.getInstr();
              rso << "{PUSH/LDMIA} before: " << MI;
              rso << "{PUSH/LDMIA} AFTER_MOD: " << *ModMI << "\n";
              DbgFd << rso.str();
              returnVal = true;
            }

          }

          //------------------------------------------------------------------
          // (4) handle return instructions <B/BX/pop>
          //------------------------------------------------------------------
          // We usually add a branch to the TLR instead of a return. One special
          // case is if we have a tail call to an extlib. In this case, we need
          // to branch to the TLR after the corresponding svc. We need to make
          // sure that the return is not a tail extlib return (either the old or
          // the added tail call for instrumenting with SVCs. The other case
          // we need to instrument is the svc after the tail extlib.
          if(
             ( MI.isReturn() &&
               !MI.getFlag(MachineInstr::RAIExtLibCall) &&
               !isExtLibCall)
             || MI.getFlag(MachineInstr::RAIExtLibRet)){

            // variable to hold conditional of current instruction
            unsigned PredReg = 0;
            ARMCC::CondCodes MICC = getInstrPredicate(MI,PredReg);//MI.getOperand(0);//getInstrPredicate(MI,0);

            // [urai-debug]
            rso << "[+] return instr: ";
            rso << MI;
            DbgFd << rso.str();

            switch(MI.getOpcode()){
            //------------------------------------------------------------------
            // (4.1) handle pop_ret <pop {r..., pc}>
            //------------------------------------------------------------------
            case ARM::tPOP_RET:{

              // add the instruction to delete vector
              DelInstVect.push_back(&MI);

              // Remove pc from pop instruction
              rso << "$$$$$$$$$$$$$$$$ BEFORE_MBB $$$$$$$$$$$$$$$$$$$\n";
              rso << MBB;
              rso << "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n";
              MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::tPOP));
              for(MachineOperand OP: MI.operands()){
                rso << "tPOP[OP]: " << OP << "\n";
                if(OP.isReg()){
                  if (OP.getReg() == ARM::PC){
                    continue;
                  }
                }
                // add operand if it is not PC
                MIB.add(OP);
              }

              rso << "$$$$$$$$$$$$$$$$ AFTER_MBB $$$$$$$$$$$$$$$$$$$\n";
              rso << MBB;
              rso << "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n";
              auto ModMI = MIB.getInstr();
              rso << "{POP_RET} before: " << MI;
              rso << "{POP_RET} AFTER_MOD: " << *ModMI << "\n";
              DbgFd << rso.str();
              returnVal = true;

              break;
            }
            //------------------------------------------------------------------
            // (4.2) handle bx_ret
            //------------------------------------------------------------------
            case ARM::tBX_RET:{
              // add the instruction to delete vector
              DelInstVect.push_back(&MI);
              // for BX_RET, we do not replace any instruction, so nothing to do
              returnVal = true;
              break;

            }
            default:
              rso << "NON POP_RET \n";
              rso << "[???] ";
              rso << MI << "\n";
              DbgFd << rso.str();
            }

            // branch to exit label
            //MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
            //    .add(MachineOperand::CreateES(
            //           FlagIdRoot[MFName][JSON_EXIT_B_INST].asCString()))
            //    .addImm(1)
            //   .setMIFlag(MachineInstr::RAIInstr);

            if (MICC == ARMCC::AL){
              MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::tB))
                  .addExternalSymbol(FlagIdRoot[MFName][JSON_EXIY_SYM].asCString())
                  .add(predOps(MICC))
                  .setMIFlag(MachineInstr::RAIInstr);
            }

            else{
              MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::tBcc))
                  .addExternalSymbol(FlagIdRoot[MFName][JSON_EXIY_SYM].asCString())
                  .add(predOps(MICC))
                  .setMIFlag(MachineInstr::RAIInstr);
            }



            rso << *MIB;
            rso << "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\n";
            DbgFd << rso.str();
          }

          // update pointers to MBB and MI
          MBBptr = &MBB;
          MIptr = &MI;

          // clear rso for next instruction
          rso.str().clear();
        }

        // remove the delete vector instructions
        for (auto DI: DelInstVect){
          rso.str().clear();
          rso << "[DELETE_MI]: ";
          rso << *DI;
          rso << "\n";
          MBB.remove_instr(DI);
          DbgFd << rso.str();

        }

      }

      //------------------------------------------------------------------
      // Add RAI's return sequence
      //------------------------------------------------------------------
      rso.str().clear();


      // get debug location and iterator
      auto DbgLoc = MIptr->getDebugLoc();
      auto Iprev = std::prev(MIptr->getIterator());
      auto Inext = std::next(MIptr->getIterator());
      auto I = std::next(MIptr->getIterator());


      //**********************************
      // if it is an ISR or main
      //**********************************
      if (FlagIdRoot[MFName][JSON_IS_ENTRY].asBool()){
        // if it is main
        if(MFName.compare(URAIAppMain) == 0){
          // add the function exit label
          MIB = BuildMI(*MBBptr, I, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES(
                     FlagIdRoot[MFName][JSON_EXIT_LBL].asCString()))
              .addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);
          // just a branch to exit function
          MIB = BuildMI(*MBBptr, I, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES("b __urai_exit_main\n"))
              .addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);

          //[urai-debug]
          MIB = BuildMI(*MBBptr, I, DbgLoc,TII.get(ARM::tB))
              .addExternalSymbol("__urai_debug")
              .add(predOps(ARMCC::AL))
              .setMIFlag(MachineInstr::RAIInstr);

        }
        // if it is an ISR
        else{
          // add the function exit label
          MIB = BuildMI(*MBBptr, I, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES(
                     FlagIdRoot[MFName][JSON_EXIT_LBL].asCString()))
              .addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);
          instrumentISRExit(*MBBptr, MIB, *MIptr, I, TII);

        }
      }

      //**********************************
      // other functions
      //**********************************
      else{
        addFuncTLR(*MBBptr,MIB, *MIptr, I, Iprev,Inext,TII, MF, MFName);
      }

      DbgFd << "********************************************************\n";

      // [urai-debug]: should change the below to true
      return returnVal;
    }

    /// Returns true if LR is an operand of the instruction.
    bool isRegInOperands(MachineInstr &MI, unsigned Reg){
      for(MachineOperand OP: MI.operands()){
        if(OP.isReg()){
          // if Reg is within the operands, return true
          if (OP.getReg() == Reg){
            return true;
          }
        }
      }
      // Reg was not found, return false
      return false;
    }

    bool isIndirectCall(int Opcode){
      if (Opcode == ARM::tBX_CALL || Opcode == ARM::tBLXr ||
          Opcode == ARM::tBLXi || Opcode == ARM::tBLXNSr ||
          Opcode == ARM::tTAILJMPr){
        return true;
      }

      return false;
    }

    bool changeSP(int Opcode){
      if (Opcode == ARM::t2MSRbanked ||
          Opcode == ARM::MSR ||
          Opcode == ARM::t2MOVr ||
          Opcode == ARM::t2LDRConstPool ||
          Opcode == ARM::t2LDRpcrel ||
          Opcode == ARM::LDRConstPool ||
          Opcode == ARM::tLDRpci_pic ||
          Opcode == ARM::tLDRpci ||
          Opcode == ARM::t2LDRpci_pic ||
          Opcode == ARM::t2LDRpci ||
          Opcode == ARM::t2LDRs
          ){
        return true;
      }

      return false;
    }

    bool isSTRInstr(unsigned Opcode){
      if (Opcode == ARM::tSTMIA_UPD || Opcode == ARM::tSTRBi ||
          Opcode == ARM::tSTRBr || Opcode == ARM::tSTRHi ||
          Opcode == ARM::tSTRHr || Opcode == ARM::tSTRi ||
          Opcode == ARM::tSTRr || Opcode == ARM::tSTRspi ||
          Opcode == ARM::t2STMDB || Opcode == ARM::t2STMDB_UPD ||
          Opcode == ARM::t2STMIA || Opcode == ARM::t2STMIA_UPD ||
          Opcode == ARM::t2STRBi8 || Opcode == ARM::t2STRBi12 ||
          Opcode == ARM::t2STRBs || Opcode == ARM::t2STRBs ||
          Opcode == ARM::t2STRBT || Opcode == ARM::t2STRB_POST ||
          Opcode == ARM::t2STRB_PRE || Opcode == ARM::t2STRB_preidx ||
          Opcode == ARM::t2STRDi8 || Opcode == ARM::t2STRD_POST ||
          Opcode == ARM::t2STRD_PRE || Opcode == ARM::t2STREX ||
          Opcode == ARM::t2STREXB || Opcode == ARM::t2STREXD ||
          Opcode == ARM::t2STREXH || Opcode == ARM::t2STRHi8 ||
          Opcode == ARM::t2STRHi12 || Opcode == ARM::t2STRHs ||
          Opcode == ARM::t2STRHT || Opcode == ARM::t2STRH_POST ||
          Opcode == ARM::t2STRH_PRE || Opcode == ARM::t2STRH_preidx ||
          Opcode == ARM::t2STRi8 || Opcode == ARM::t2STRi12 ||
          Opcode == ARM::t2STRs || Opcode == ARM::t2STRT ||
          Opcode == ARM::t2STR_POST || Opcode == ARM::t2STR_PRE ||
          Opcode == ARM::t2STR_preidx
          ){

        return true;
      }

      return false;
    }


    bool isBLCall(int Opcode){
      if (Opcode == ARM::tBL){
        return true;
      }

      return false;
    }

    uint32_t getCalleeOpIdx(MachineInstr &MI, bool isDirectCall){
      std::string str;
      raw_string_ostream rso(str);
      uint32_t idx = 0, callee_idx = 0;

      //outs() <<  "checking func: " << MI.getParent()->getParent()->getName() << "\n";
      //outs() << "MI: " << MI << "\n";

      //------------------------------------------------------------------------
      // if it is a direct call instruction
      if(isDirectCall){
        for (MachineOperand OP: MI.operands()){
          rso.str().clear();
          //outs() << "\t OP[" << idx << "]: " << OP << ", type: " <<
                    //std::to_string(OP.getType()) <<"\n";
          DbgFd << rso.str();
          if (OP.getType() == MachineOperand::MachineOperandType::MO_GlobalAddress){
            callee_idx = idx;
            //outs() << "\t callee idx = " << callee_idx << "\n";
            return callee_idx;
          }
          idx++;
        }
        // default to 2 if none is found
        callee_idx = 2;
        //outs() << "\t Did not find callee idx, defaulting to = " << callee_idx << "?\n";
      }

      //------------------------------------------------------------------------
      // if it is an indirect call
      else{
        // if indirect tail call
        if(MI.getOpcode() == ARM::tTAILJMPr){
          idx = 0;
          //outs() << "MI: " << MI << "\n";
          //outs() << "[+] Indirect TAIL CALL!\n";
          for (MachineOperand OP: MI.operands()){
            rso.str().clear();
            //outs() << "\t OP[" << idx << "]: " << OP << ", type: " <<
            //          std::to_string(OP.getType()) <<"\n";
            DbgFd << rso.str();
            if (OP.getType() == MachineOperand::MachineOperandType::MO_GlobalAddress){
              callee_idx = idx;
              //outs() << "\t callee idx = " << callee_idx << "\n";
            }
            // check if operand is a register
            if (OP.getType() == MachineOperand::MachineOperandType::MO_Register){
              //outs() << "^^ A Reg operand!\n";
            }
            idx++;
          }
          callee_idx = 0;
          //outs() << "[+] Indirect tail call: callee register @idx 0\n";
        }
        // otherwise, register used for indirect calls is ar idx 2
        else{
          callee_idx = 2;
          //outs() << "[+] Indirect call: callee register @idx 2\n";
        }
      }
      return callee_idx;
    }


    void addFuncTLR(MachineBasicBlock & MBBEnd,
                MachineInstrBuilder & MIB,
                MachineInstr &MIEnd,
                MachineBasicBlock::iterator I,
                MachineBasicBlock::iterator Iprev,
                MachineBasicBlock::iterator Inext,
                const ARMBaseInstrInfo &TII,
                MachineFunction &MF,
                std::string MFName){


      MachineBasicBlock *MBBptr;
      MachineInstr *MIptr;
      bool StartFLT = false;
      //------------------------------------------------------------------------
      // First, check where we should add the FLT:
      //  [1] In the end, this is the usual case.
      //  [2] In the beginning. This happens when the FLT is too large to cause
      //      a pc-relative error. In such case, add a trampoline in the begninning
      //      the will jump to the actual beginning of the function. Then add
      //      add the FLT. In such way we can avoid the problem of pc-relative erros.

      // read the max FID from JSON file and compare it to the pre-defined threshold
      if (FlagIdRoot[MFName][JSON_MAX_INFLAG].asUInt64() > MAX_APPEND_FLT_SIZE){

        // set MBBptr and MIptr to the beginning. Then add trampoline
        for (MachineBasicBlock &MBBStart: MF){

          for(MachineInstr &MIStart: MBBStart){

            MBBptr = &MBBStart;
            MIptr = &MIStart;
            StartFLT = true;
            break;

          }
          break;
        }

      }

      // if FLT @end
      else{

        MBBptr = &MBBEnd;
        MIptr = &MIEnd;

      }

      auto DbgLoc = MIptr->getDebugLoc();//MI.getDebugLoc();
      auto TlrI = std::next(MIptr->getIterator());

      // if FLT @start, add a trampoline
      if (StartFLT){
        MIB = BuildMI(*MBBptr, TlrI, DbgLoc,TII.get(ARM::INLINEASM))
            .add(MachineOperand::CreateES(
                   FlagIdRoot[MFName][JSON_TRAMPOLINE_INST].asCString()))
            .addImm(1)
            .setMIFlag(MachineInstr::RAIInstr);

      }


      // add the function exit label
      MIB = BuildMI(*MBBptr, TlrI, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES(
                 FlagIdRoot[MFName][JSON_EXIT_LBL].asCString()))
          .addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);



      // if no shifting or recursion occurs, use relative jump
      // directly with LR
      if (!FlagIdRoot[JSON_IS_SHIFTED].asBool() &&
          !FlagIdRoot[MFName][JSON_ISREC].asBool()){

        // add first relative-jump with LR directly
        MIB = BuildMI(*MBBptr, TlrI, DbgLoc,TII.get(ARM::INLINEASM))
            .add(MachineOperand::CreateES(FuncRet.c_str())).addImm(1)
            .setMIFlag(MachineInstr::RAIInstr);

      }


      // Otherwise, will mostly need to add the additional instructions
      // to handle segmentation.
      else{

        // First, check if we need to add the recursion routine to the function
        if (FlagIdRoot[MFName][JSON_ISREC].asBool()){

          // if it is multi recursive or cyclic
          if (FlagIdRoot[MFName][JSON_IS_MULTI_RECURSIVE].asBool() ||
              FlagIdRoot[MFName][JSON_ISPATHREC].asBool()){

            // first check the multi recursion bit
            MIB = BuildMI(*MBBptr, TlrI, DbgLoc,TII.get(ARM::INLINEASM))
                .add(MachineOperand::CreateES(ClzLRintoR12.c_str()))
                .addImm(1)
                .setMIFlag(MachineInstr::RAIInstr);
            // compare r12 to 0
            MIB = BuildMI(*MBBptr, TlrI, DbgLoc,TII.get(ARM::t2CMPri))
                .addReg(ARM::R12)
                .addImm(0)
                .add(predOps(ARMCC::AL))
                .setMIFlag(MachineInstr::RAIInstr);
            // IT
            MIB = BuildMI(*MBBptr, TlrI, DbgLoc,TII.get(ARM::INLINEASM))
                .add(MachineOperand::CreateES("it eq\n"))
                .addImm(1)
                .setMIFlag(MachineInstr::RAIInstr);
            // if not equal, execute the corresponding svc. Otherwise, it should
            // skip this svc if the bit is not set.
            MIB = BuildMI(*MBBptr, TlrI, DbgLoc,TII.get(ARM::tSVC))
                .addImm(SvcRecRestore)
                .add(predOps(ARMCC::AL))
                .setMIFlag(MachineInstr::RAIInstr);

          }

          // otherwise if single recursion
          else{

            // mov lr to r12 without leading bit
            MIB = BuildMI(*MBBptr, TlrI, DbgLoc,TII.get(ARM::INLINEASM))
                .add(MachineOperand::CreateES(MovLRToR12WithLSL1.c_str()))
                .addImm(1)
                .setMIFlag(MachineInstr::RAIInstr);
            // set r12 to the recursion counter value
            MIB = BuildMI(*MBBptr, TlrI, DbgLoc,TII.get(ARM::INLINEASM))
                .add(MachineOperand::CreateES(
                       FlagIdRoot[MFName][JSON_MOV_REC_TLR_INST_KEY]
                       .asCString()))
                .addImm(1)
                .setMIFlag(MachineInstr::RAIInstr);

            // compare r12 (i.e., the recursion counter) to 0
            MIB = BuildMI(*MBBptr, TlrI, DbgLoc,TII.get(ARM::t2CMPri))
                .addReg(ARM::R12)
                .addImm(0)
                .add(predOps(ARMCC::AL))
                .setMIFlag(MachineInstr::RAIInstr);

            // if recursion counter is not 0, then return to the recursive label
            MIB = BuildMI(*MBBptr, TlrI, DbgLoc,TII.get(ARM::t2Bcc))
                .addExternalSymbol(FlagIdRoot[MFName][JSON_RECURSION_TLR_LBL]
                                   .asCString())
                .addImm(ARMCC::NE)
                .addReg(ARM::CPSR)
                .setMIFlag(MachineInstr::RAIInstr);
          }

        }

        MIB = BuildMI(*MBBptr, TlrI, DbgLoc,TII.get(ARM::INLINEASM))
            .add(MachineOperand::CreateES(
                   FlagIdRoot[MFName][JSON_RET_INSTS][JSON_MOV1_INST]
                   .asCString()))
            .addImm(1)
            .setMIFlag(MachineInstr::RAIInstr);

        MIB = BuildMI(*MBBptr, TlrI, DbgLoc,TII.get(ARM::INLINEASM))
            .add(MachineOperand::CreateES(
                   FlagIdRoot[MFName][JSON_RET_INSTS][JSON_MOV2_INST]
                   .asCString()))
            .addImm(1)
            .setMIFlag(MachineInstr::RAIInstr);

        // add first relative-jump with Rx
        MIB = BuildMI(*MBBptr, TlrI, DbgLoc,TII.get(ARM::INLINEASM))
            .add(MachineOperand::CreateES(FuncRetWithSeg.c_str())).addImm(1)
            .setMIFlag(MachineInstr::RAIInstr);

      }



      // add the lookup table
      uint64_t MaxInflag = FlagIdRoot[MFName][JSON_MAX_INFLAG].asUInt64();
      // MaxInFlag is already considers x4 for each idx, the +2 is for allignment
      FLTOverhead += MaxInflag + 2;
      uint64_t flt_cntr = 0; // counter of used indicies in binary

      // The first entry of the lookup table is used, so it should point
      // to an error.
      MIB = BuildMI(*MBBptr, TlrI, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES(LTError.c_str())).addImm(1);
      MIB = BuildMI(*MBBptr, TlrI, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES(LTError.c_str())).addImm(1);

      // add the rest of the lookup table
      for (uint64_t i = 2; i <= MaxInflag; i += 4){
        std::string InFlagStr = std::to_string(i);
        // if i does not exist in lookp table, then replace it with
        // a direct jump to error since SR should not have that value.
        // Otherwise, add the direct jump from the JSON flag IDs
        // Note that the OR here is detect when optimizaitions reduce the number
        // of call sites available before at the IR level. If the label has not
        // been accessed already, it means it was optimized, so we should
        // NOT add it as if we do so there will be a linker error since
        // the label has not been added before in the binary.
        if (FlagIdRoot[MFName][JSON_INFLAGS].get(InFlagStr,"") == "" ||
            LabelsRoot.get(FlagIdRoot[MFName][JSON_INFLAGS][InFlagStr]
                           .asString(), "") == ""){
          // No FlagID == i, so add jump to error instead
          MIB = BuildMI(*MBBptr, TlrI, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES(LTError.c_str())).addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);

          MIB = BuildMI(*MBBptr, TlrI, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES(LTError.c_str())).addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);
        }
        else{

          // There is a FlagID == i in the LookupTable, so add it
          MIB = BuildMI(*MBBptr, TlrI, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES(
                     FlagIdRoot[MFName][JSON_INFLAGS][InFlagStr].asCString()))
                   .addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);

          // update flt counter
          flt_cntr += 1;

        }
      }

      // calculate the efficiency and add it to the bin efficiency vector
      if (MaxInflag != 0){
        float_t bin_eff = (float(flt_cntr)/( (MaxInflag + 2) / 4)) * 100.0;
        BinFltEff[MFName] = bin_eff;
      }


      // if the FLT is at the beginning of the function, then add a label of
      // function start right after the FLT so that the trampoline jumps to it.
      if (StartFLT){
        // add the start label
        MIB = BuildMI(*MBBptr, TlrI, DbgLoc,TII.get(ARM::INLINEASM))
            .add(MachineOperand::CreateES(
                   FlagIdRoot[MFName][JSON_START_LBL].asCString()))
            .addImm(1)
            .setMIFlag(MachineInstr::RAIInstr);
      }

    }

    void instrumentRAIDirectCall(MachineBasicBlock & MBB,
                                 MachineInstrBuilder & MIB,
                                 MachineInstr &MI,
                                 MachineBasicBlock::iterator I,
                                 MachineBasicBlock::iterator Iprev,
                                 MachineBasicBlock::iterator Inext,
                                 const ARMBaseInstrInfo &TII,
                                 std::string MFName,
                                 std::string LBL){

      std::string str;
      raw_string_ostream rso(str);
      auto DbgLoc = MI.getDebugLoc();

      // check if we need to reset SR, if so add SVC to save SR
      if (FlagIdRoot[MFName][JSON_KEYS_DICT][LBL][JSON_SR_RESET].asBool()){
        MIB = BuildMI(MBB, I, DbgLoc, TII.get(ARM::tSVC))
            .addImm(SvcAppSave)
            .add(predOps(ARMCC::AL))
            .setMIFlag(MachineInstr::RAIInstr);

        // update svc counter
        SVCResetCntr++;
      }

      // [1] Add encoding XOR
      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES(
                 FlagIdRoot[MFName][JSON_KEYS_DICT][LBL][JSON_XOR_INST]
                 .asCString())).addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

      // [2] Replace BL with B
      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES(
                 FlagIdRoot[MFName][JSON_KEYS_DICT][LBL][JSON_B_INST]
                 .asCString())).addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);


      // [3] instrument label after
      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES(
                 FlagIdRoot[MFName][JSON_KEYS_DICT][LBL][JSON_LABEL]
                 .asCString()))
          .addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

      // [4] Add decoding XOR
      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES(
                 FlagIdRoot[MFName][JSON_KEYS_DICT][LBL][JSON_XOR_INST]
                 .asCString())).addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

      // check if we need to restore SR, if so add SVC to restore SR
      if (FlagIdRoot[MFName][JSON_KEYS_DICT][LBL][JSON_SR_RESET].asBool()){
        MIB = BuildMI(MBB, I, DbgLoc, TII.get(ARM::tSVC))
            .addImm(SvcAppRestore)
            .add(predOps(ARMCC::AL))
            .setMIFlag(MachineInstr::RAIInstr);
      }


      auto ModMI = MIB.getInstr();
      rso << "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n";
      rso << *ModMI << "\n";
      DbgFd << rso.str();

    }


    void instrumentRAIRecursiveCall(MachineBasicBlock & MBB,
                                 MachineInstrBuilder & MIB,
                                 MachineInstr &MI,
                                 MachineBasicBlock::iterator I,
                                 MachineBasicBlock::iterator Iprev,
                                 MachineBasicBlock::iterator Inext,
                                 const ARMBaseInstrInfo &TII,
                                 std::string MFName,
                                 std::string LBL){

      std::string str;
      raw_string_ostream rso(str);
      auto DbgLoc = MI.getDebugLoc();

      // check if we need to reset SR, if so add SVC to save SR
      if (FlagIdRoot[MFName][JSON_KEYS_DICT][LBL][JSON_SR_RESET].asBool()){
        MIB = BuildMI(MBB, I, DbgLoc, TII.get(ARM::tSVC))
            .addImm(SvcAppSave)
            .add(predOps(ARMCC::AL))
            .setMIFlag(MachineInstr::RAIInstr);

        // update svc counter
        SVCResetCntr++;
      }

      //------------------------------------------------------------------------
      // if there is multiple recursion, or cyclic recursion
      if(FlagIdRoot[MFName][JSON_IS_MULTI_RECURSIVE].asBool() ||
              FlagIdRoot[MFName][JSON_ISPATHREC].asBool()){
        MIB = BuildMI(MBB, I, DbgLoc, TII.get(ARM::tSVC))
            .addImm(SvcRecSave)
            .add(predOps(ARMCC::AL))
            .setMIFlag(MachineInstr::RAIInstr);

        // Add the recursive call, but replace BL with B
        MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
            .add(MachineOperand::CreateES(
                   FlagIdRoot[MFName][JSON_KEYS_DICT][LBL][JSON_B_INST]
                   .asCString())).addImm(1)
            .setMIFlag(MachineInstr::RAIInstr);
      }

      //------------------------------------------------------------------------
      // otherwise, if there is only single recursion
      else{
        // [1] Add encoding ADD (i.e., increment recursion counter)
        MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
            .add(MachineOperand::CreateES(
                   FlagIdRoot[MFName][JSON_KEYS_DICT][LBL][JSON_ADD_REC_INST]
                   .asCString())).addImm(1)
            .setMIFlag(MachineInstr::RAIInstr);

        // [2] Replace BL with B
        MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
            .add(MachineOperand::CreateES(
                   FlagIdRoot[MFName][JSON_KEYS_DICT][LBL][JSON_B_INST]
                   .asCString())).addImm(1)
            .setMIFlag(MachineInstr::RAIInstr);


        // [3] instrument label after
        MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
            .add(MachineOperand::CreateES(
                   FlagIdRoot[MFName][JSON_KEYS_DICT][LBL][JSON_LABEL]
                   .asCString()))
            .addImm(1)
            .setMIFlag(MachineInstr::RAIInstr);

        // [4] Add decoding sub (i.e., decrement recursion counter)
        MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
            .add(MachineOperand::CreateES(
                   FlagIdRoot[MFName][JSON_KEYS_DICT][LBL][JSON_SUB_REC_INST]
                   .asCString())).addImm(1)
            .setMIFlag(MachineInstr::RAIInstr);
      }
      //------------------------------------------------------------------------

      // check if we need to restore SR, if so add SVC to restore SR
      if (FlagIdRoot[MFName][JSON_KEYS_DICT][LBL][JSON_SR_RESET].asBool()){
        MIB = BuildMI(MBB, I, DbgLoc, TII.get(ARM::tSVC))
            .addImm(SvcAppRestore)
            .add(predOps(ARMCC::AL))
            .setMIFlag(MachineInstr::RAIInstr);
      }


      auto ModMI = MIB.getInstr();
      rso << "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-\n";
      rso << "Modified RECURSION[" << LBL <<"]:\n";
      rso << *ModMI << "\n";
      rso << "*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-*-\n";
      DbgFd << rso.str();

    }


    bool isOptmizableExtlib(std::string FName){
      //if(ExtLibOptListJsonRoot.get(FName,"") != ""){
      //  std::string res = ExtLibOptListJsonRoot[FName].asString();
      //  if (res.compare(JSON_OPMTIMIZABLE_EXTLIB) == 0){
      //    return true;
      //  }
      //}
      return false;
    }

    void instrumentRAIUnsuprtdLib(MachineBasicBlock & MBB,
                                  MachineInstrBuilder & MIB,
                                  MachineInstr &MI,
                                  MachineBasicBlock::iterator Iprev,
                                  MachineBasicBlock::iterator Inext,
                                  const ARMBaseInstrInfo &TII,
                                  bool IsOpt){

      auto DbgLoc = MI.getDebugLoc();

      //------------------------------------------------------------------
      // There are 2 option when handling external pre-compiled libraries:
      //    1) Optimizable: Here, we can use wrap the call with mov instruction
      //                    instead of an SVC. This can reduce the overhead
      //                    without affecting the security.
      //    2) Not-optmizable: Here the call is wrapped with an SVC. This is
      //                       costly but is needed if the optmizaition is
      //                       not possible.

      // check if the optmization applies
      if (IsOpt){
        // increment optimized counter
        opt_extlib_cntr++;

        MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
            .add(MachineOperand::CreateES("ldr.w r12,[pc, #24]\n"))
            .addImm(1)
            .setMIFlag(MachineInstr::RAIInstr);

        MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
            .add(MachineOperand::CreateES("str.w r9,[r12]\n"))
            .addImm(1)
            .setMIFlag(MachineInstr::RAIInstr);

        // add mov r9, lr
        MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::tMOVr), ARM::R9)
            .addReg(ARM::LR)
            .add(predOps(ARMCC::AL))
            .setMIFlag(MachineInstr::RAIInstr);
      }
      // if not, then add an SVC
      else{
        // add an svc before to save SR
        MIB = BuildMI(MBB, Inext, DbgLoc, TII.get(ARM::tSVC))
            .addImm(SvcLibSave)
            .add(predOps(ARMCC::AL))
            .setMIFlag(MachineInstr::RAIInstr);
      }

      // re-add the instruction, we do this to make sure the instructions are
      // inlined correctly. The original instruction will be deleted after this
      // addition.
      MIB = BuildMI(MBB, Inext, DbgLoc, TII.get(MI.getOpcode()));
      for(MachineOperand OP: MI.operands()){
        // add the operands of the original instruction to the ext lib
        MIB.add(OP);
      }
      MIB.setMIFlags(MachineInstr::RAIInstr| MachineInstr::RAIExtLibCall);


      // restore SR

      // if the extlib is returning make sure to add the extlib flag for the svc
      if (MI.isReturn()){

        // restore using a mov
        if(IsOpt){


          // restore lr from t9
          MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::tMOVr), ARM::LR)
              .addReg(ARM::R9)
              .add(predOps(ARMCC::AL))
              .setMIFlag(MachineInstr::RAIInstr);

          MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES("ldr.w r12,[pc, #8]\n"))
              .addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);

          MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES("ldr.w r9,[r12]\n"))
              .addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);

          // add a branch after the constant
         std::string extlib_lbl = opt_extlib_lbl_str +
              std::to_string(opt_extlib_cntr);

         std::string extlib_branch = "b " + extlib_lbl + "\n";
         extlbls_branch_vctr.push_back(extlib_branch);
          MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES(
                     extlbls_branch_vctr[extlbls_branch_vctr.size()-1].c_str()))
              .addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);

          MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES(".long rai_extlib_var\n"))
              .addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);

          // add \n to extlib
          std::string extlib_lbl_const = extlib_lbl + ":\n";
          extlbls_vctr.push_back(extlib_lbl_const);
          MIB = BuildMI(MBB, Inext, DbgLoc, TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES(
                     extlbls_vctr[extlbls_vctr.size()-1].c_str()))
              .addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);

          MIB = BuildMI(MBB, Inext, DbgLoc, TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES(extlib_lbl.c_str()))
              .addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);

          MIB = BuildMI(MBB, Inext, DbgLoc, TII.get(ARM::INLINEASM))
                .add(MachineOperand::CreateES("nop.w\n"))
                .addImm(1)
                .setMIFlag(MachineInstr::RAIExtLibRet);


        }
        // restore using an svc
        else{
          MIB = BuildMI(MBB, Inext, DbgLoc, TII.get(ARM::tSVC))
              .addImm(SvcLibRestore)
              .add(predOps(ARMCC::AL))
              .setMIFlag(MachineInstr::RAIExtLibRet); // [rai-debug]: revise again to add RAIInstr
        }

      }
      // if the extlib is not returning (i.e., tail call) then do NOT add the
      // extlib return flag
      else{
        // restore using a mov
        if(IsOpt){


          // restore lr from t9
          MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::tMOVr), ARM::LR)
              .addReg(ARM::R9)
              .add(predOps(ARMCC::AL))
              .setMIFlag(MachineInstr::RAIInstr);

          MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES("ldr.w r12,[pc, #8]\n"))
              .addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);

          MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES("ldr.w r9,[r12]\n"))
              .addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);

          // add a branch after the constant
         std::string extlib_lbl = opt_extlib_lbl_str +
              std::to_string(opt_extlib_cntr);

         std::string extlib_branch = "b " + extlib_lbl + "\n";
         extlbls_branch_vctr.push_back(extlib_branch);
          MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES(
                     extlbls_branch_vctr[extlbls_branch_vctr.size()-1].c_str()))
              .addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);

          MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES(".long rai_extlib_var\n"))
              .addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);

          // add \n to extlib
          std::string extlib_lbl_const = extlib_lbl + ":\n";
          extlbls_vctr.push_back(extlib_lbl_const);
          MIB = BuildMI(MBB, Inext, DbgLoc, TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES(
                     extlbls_vctr[extlbls_vctr.size()-1].c_str()))
              .addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);

        }
        // restore using an svc
        else{
          MIB = BuildMI(MBB, Inext, DbgLoc, TII.get(ARM::tSVC))
              .addImm(SvcLibRestore)
              .add(predOps(ARMCC::AL))
              .setMIFlag(MachineInstr::RAIInstr);
        }
      }

      return;
    }


    void instrumentRAIEhSfi(MachineBasicBlock & MBB,
                                  MachineInstrBuilder & MIB,
                                  MachineInstr &MI,
                                  MachineBasicBlock::iterator Inext,
                                  const ARMBaseInstrInfo &TII){

      auto DbgLoc = MI.getDebugLoc();
      unsigned DstRegOpNum = getSTRDestRegOpNum(MI.getOpcode());
      MachineOperand DstReg = MI.getOperand(DstRegOpNum);

      // get rx, we generally use r12 or r9, whichever is available
      unsigned Regx = 0;
      unsigned mpu_cmp_idx = 0, vtor_cmp_idx = 0, mov1_idx = 0, mov2_idx = 0;
      if (DstReg.getReg() != ARM::R0){
        Regx = ARM::R0;
        mpu_cmp_idx = 0;
        vtor_cmp_idx = 1;
        mov1_idx = 0;
        mov2_idx = 1;
      }
      else{
        Regx = ARM::R1;
        mpu_cmp_idx = 2;
        vtor_cmp_idx = 3;
        mov1_idx = 2;
        mov2_idx = 3;
      }

      // only apply this if the destination is not SP
      if (DstReg.getReg() != ARM::SP){

        // updated EHSfi counter
        EHSFIStrInstrsCntr++;

        // update EHSFI mem overhead
        EHSFIMemOverhead += 46; // overhead bytes

        //------------------------------------------------------------------------
        // This part is only invoked when dynamically measuring store instructions
        // that are protected by EHSFI
        if ( ! (URAIEhSFIMeasurement.compare("-") == 0) ){
          MIB = BuildMI(MBB, Inext, DbgLoc, TII.get(ARM::tSVC))
              .addImm(SvcEhSFICntr)
              .add(predOps(ARMCC::AL))
              .setMIFlag(MachineInstr::RAIInstr);
        }

        //------------------------------------------------------------------------
        // MPU masking
        //  --------------------
        //  |   MPU RASR        |    MPU_RNR + 0x08
        //  --------------------
        //  |   MPU RBAR        |    MPU_RNR + 0x04
        //  --------------------
        //  |   MPU RNR         |    <----- 0xE000ED98 (MPU_RNR)
        //  --------------------
        //  |   MPU CTRL        |    MPU_RNR - 0x04
        //  --------------------
        //  |   MPU type        |    MPU_RNR - 0x08
        //  --------------------
        //
        //    1) subtract MPU_RNR from dest
        //    2) if offset is less or equal to 8, then it was pointing to MPU
        //    3) if true, jump to ERROR
        //    4) otherwise, just mask the safe region and execute the instruction

        // save register, this can be optimized by using an already
        // available register
        if (DstReg.getReg() != ARM::R0){
          MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::tPUSH))
              .addReg(ARM::R0)
              .add(predOps(ARMCC::AL))
              .setMIFlag(MachineInstr::RAIInstr);

          MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES(spec_msr_inst[mov1_idx].c_str()))
              .addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);

          MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::tPUSH))
              .addReg(ARM::R0)
              .add(predOps(ARMCC::AL))
              .setMIFlag(MachineInstr::RAIInstr);
        }
        else{
          MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES("push {r1}\n"))
              .addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);

          MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES(spec_msr_inst[mov1_idx].c_str()))
              .addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);

          MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES("push {r1}\n"))
              .addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);
        }


        MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
            .add(MachineOperand::CreateES(ehsfi_mov_inst[mov1_idx].c_str()))
            .addImm(1) // ;ED98
            .setMIFlag(MachineInstr::RAIInstr);

        MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
            .add(MachineOperand::CreateES(ehsfi_mov_inst[mov2_idx].c_str()))
            .addImm(1) // ;E000
            .setMIFlag(MachineInstr::RAIInstr);

        // subtract , rx = |rx -  rd|
        MIB = BuildMI(MBB, Inext, DbgLoc, TII.get(ARM::t2SUBrr), Regx)
            .addReg(Regx, RegState::Kill)
            .addReg(DstReg.getReg(), RegState::Kill)
            .add(predOps(ARMCC::AL))
            .add(condCodeOp())
            .setMIFlag(MachineInstr::RAIInstr);

        // mpu compare check
        MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
            .add(MachineOperand::CreateES(cmp_inst[mpu_cmp_idx].c_str()))
            .addImm(1)
            .setMIFlag(MachineInstr::RAIInstr);


        // conditional branch, if less than 8, then it was targeting the MPU
        MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::t2Bcc))
            .addExternalSymbol("__urai_error")
            .addImm(ARMCC::LS)
            .addReg(ARM::CPSR)
            .setMIFlag(MachineInstr::RAIInstr);

        // VTOR compare check
        MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
            .add(MachineOperand::CreateES(cmp_inst[vtor_cmp_idx].c_str()))
            .addImm(1)
            .setMIFlag(MachineInstr::RAIInstr);


        // conditional branch, if equal 0xd90 , then it was targeting the VTOR
        MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::t2Bcc))
            .addExternalSymbol("__urai_error")
            .addImm(ARMCC::EQ)
            .addReg(ARM::CPSR)
            .setMIFlag(MachineInstr::RAIInstr);


        // add bic to mask store
        BuildMI(MBB, Inext, DbgLoc, TII.get(ARM::t2BICri), DstReg.getReg())
            .addReg(DstReg.getReg())
            .addImm(0x10000000)
            .add(predOps(ARMCC::AL))
            .add(condCodeOp())
            .setMIFlag(MachineInstr::RAIInstr);

        // if all passes, then retrieve Rx and CPSR
        if (DstReg.getReg() != ARM::R0){
          MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::tPOP))
              .addReg(ARM::R0)
              .add(predOps(ARMCC::AL))
              .setMIFlag(MachineInstr::RAIInstr);

          MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES(spec_msr_inst[mov2_idx].c_str()))
              .addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);

          MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::tPOP))
              .addReg(ARM::R0)
              .add(predOps(ARMCC::AL))
              .setMIFlag(MachineInstr::RAIInstr);
        }
        else{
          MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES("pop {r1}\n"))
              .addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);

          MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES(spec_msr_inst[mov2_idx].c_str()))
              .addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);

          MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES("pop {r1}\n"))
              .addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);
        }

      } // End of -->if (DstReg.getReg() != ARM::SP)

      // re-add the instruction, we do this to make sure the instructions are
      // inlined correctly. (i.e., BIC then a store instruction)
      MIB = BuildMI(MBB, Inext, DbgLoc, TII.get(MI.getOpcode()));
      for(MachineOperand OP: MI.operands()){
        // add the operands of the original instruction to the ext lib
        MIB.add(OP);
      }
      // add RAIInstr flag to avoid duplicate instrumentation
      MIB.setMIFlag(MachineInstr::RAIInstr);

      return;
    }


    unsigned getSTRDestRegOpNum(unsigned Opcode){
      if (Opcode == ARM::tSTMIA_UPD || //y
          Opcode == ARM::t2STMDB || Opcode == ARM::t2STMDB_UPD || // n/y
          Opcode == ARM::t2STMIA || Opcode == ARM::t2STMIA_UPD // n/n
          ){
        return 0;

      }

      else if
          (Opcode == ARM::tSTRBi || Opcode == ARM::tSTRHi || // y/y
           Opcode == ARM::tSTRi || Opcode == ARM::tSTRspi || // y/y
           Opcode == ARM::t2STRBi8 || Opcode == ARM::t2STRBi12 || // y/y
           Opcode == ARM::t2STRBT || Opcode == ARM::t2STREX || // n/n
           Opcode == ARM::t2STREXB || Opcode == ARM::t2STREXD || // n/n
           Opcode == ARM::t2STREXH || Opcode == ARM::t2STRHi8 || // n/n
           Opcode == ARM::t2STRHi12 || // y
           Opcode == ARM::t2STRHT || // n
           Opcode == ARM::t2STRi8 || Opcode == ARM::t2STRi12 // n/y
           || Opcode == ARM::t2STRT
           ){

        return 1;

      }

      else if( Opcode == ARM::t2STRDi8 || Opcode == ARM::t2STRD_POST|| // y/n
               Opcode == ARM::t2STRs || Opcode == ARM::tSTRBr || // y/y
               Opcode == ARM::tSTRHr || Opcode == ARM::tSTRr || // n/y
               Opcode == ARM::t2STRD_PRE || // n
               Opcode == ARM::t2STR_preidx || // n
               Opcode == ARM::t2STR_PRE || Opcode == ARM::t2STRB_PRE || // y/y
               Opcode == ARM::t2STRB_POST || Opcode == ARM::t2STRH_PRE || // y/n
               Opcode == ARM::t2STR_POST || Opcode == ARM::t2STRH_POST|| // n/n
               Opcode == ARM::t2STRH_preidx || Opcode == ARM::t2STRHs || // n/n
               Opcode == ARM::t2STRB_preidx || // n
               Opcode == ARM::t2STRBs){ // n
        return 2;
      }

      else{
        // if unknown, return -1 to cause an error
        return -1;
      }


    }

    void addTCFICheck(MachineBasicBlock & MBB,
                      MachineInstrBuilder & MIB,
                      MachineInstr &MI,
                      MachineBasicBlock::iterator I,
                      MachineBasicBlock::iterator Iprev,
                      MachineBasicBlock::iterator Inext,
                      const ARMBaseInstrInfo &TII,
                      std::string MFName,
                      std::string LBL){

      auto DbgLoc = MI.getDebugLoc();
      uint32_t CalleeOpIdx = getCalleeOpIdx(MI, false);
      // get the register used in the indirect call instruction
      auto CallReg = MI.getOperand(CalleeOpIdx).getReg(); // operand 2 is the register in blx <register>

      IndirCallRegMap.insert(std::make_pair(LBL, CallReg));

      // add jump to start of indrect call routine at TCFI_handler
      MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES(
                 FlagIdRoot[LBL][JSON_TRAMPOLINE_INST]
                 .asCString())).addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

      // add the indirect label (i.e., TCFI exit)
      MIB = BuildMI(MBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES(
                 FlagIdRoot[LBL][JSON_TCFI_LBL]
                 .asCString())).addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

    }

    void addTCFIHandler(MachineFunction &MF,
                      MachineInstrBuilder & MIB,
                      const ARMBaseInstrInfo &TII,
                      std::string MFName){

      // get the pointer to the last BB and Instr of the function
      MachineBasicBlock *TcfiMBB;
      MachineInstr *TcfiMI;
      for (MachineBasicBlock &MBB: MF){
        for(MachineInstr &MI: MBB){
          TcfiMI = &MI;
        }
        TcfiMBB = &MBB;
      }

      // get debug location
      auto DbgLoc = TcfiMI->getDebugLoc();
      // get the iterators
      auto Inext = std::next(TcfiMI->getIterator());
      uint32_t nop_cntr = 0;


      // loop through the available indirect labels and add their instrumentation
      // one by one.
      for (auto const& IndirCall: IndirCallRegMap){
        //outs() << "LBL: " << IndirCall.first << " -> " << IndirCall.second << "\n";
        std::string IndirLBL = IndirCall.first;
        auto CallReg = IndirCall.second;
        unsigned SavedCallReg = CallReg;

        // add the indirect TCFI call start label
        MIB = BuildMI(*TcfiMBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
            .add(MachineOperand::CreateES(
                   FlagIdRoot[IndirLBL][JSON_START_LBL]
                   .asCString())).addImm(1)
            .setMIFlag(MachineInstr::RAIInstr);

        // verify that the indirct call is not done using R12, if so we need
        // to save r0, and mov r12 to it. Also change CallReg Here.
        if (CallReg == ARM::R12){
          // add push r0
          MIB = BuildMI(*TcfiMBB, Inext, DbgLoc,TII.get(ARM::tPUSH))
              .addReg(ARM::R0)
              .add(predOps(ARMCC::AL))
              .setMIFlag(MachineInstr::RAIInstr);

          // add mov r0, r12
          MIB = BuildMI(*TcfiMBB, Inext, DbgLoc,TII.get(ARM::tMOVr), ARM::R0)
              .addReg(ARM::R12)
              .add(predOps(ARMCC::AL))
              .setMIFlag(MachineInstr::RAIInstr);
          // set CallReg to R0
          CallReg = ARM::R0;

          // 2 instructions x 2 bytes per instruction
          TCFIOverhead += 4;

        }

        // instrument the TCFI check
        for (unsigned int i = 0; i < FlagIdRoot[IndirLBL][JSON_TCFI_SET].size(); i++){
          std::string TarName = FlagIdRoot[IndirLBL][JSON_TCFI_SET][i].asString();
          //outs() << "LBL-> " << IndirLBL << ", TarName [" << MFName << "]: " << TarName << "\n";

          // add load instruction (r12 = target func)
          MIB = BuildMI(*TcfiMBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES(
                     FlagIdRoot[IndirLBL][JSON_TCFI_INSTRMNT][TarName][JSON_LDR_INST]
                     .asCString())).addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);

          // add TEQ comparison
          MIB = BuildMI(*TcfiMBB, Inext, DbgLoc,TII.get(ARM::t2TEQrr), ARM::R12)
              .addReg(CallReg)
              .add(predOps(ARMCC::AL))
              .setMIFlag(MachineInstr::RAIInstr);
          // add branch to the target label if comparison passes
          MIB = BuildMI(*TcfiMBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES(
                     FlagIdRoot[IndirLBL][JSON_TCFI_INSTRMNT][TarName][JSON_B_INST]
                     .asCString())).addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);

          // 3 instructions x 4 bytes per instruction
          TCFIOverhead += 12;
        }

        // need to add a specific number of jump errors to keep the alignment
        // of the pc-relative data
        uint8_t tcfi_alignment_cntr = 2;//3;
        //if (FlagIdRoot[IndirLBL][JSON_TCFI_SET].size() % 2 == 0){
        //  tcfi_alignment_cntr = 2;
        //}

        // if none of the comparisons worked, add a branch to error
        for(uint8_t bkpt_cntr = 0; bkpt_cntr < tcfi_alignment_cntr; bkpt_cntr++){
          MIB = BuildMI(*TcfiMBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES("bkpt\n")).addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);
          TCFIOverhead += 2; // bkpt  = 2
        }


        // add nop for allignment
        //if (nop_cntr % 2 == 0){
        //  MIB = BuildMI(*TcfiMBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
        //      .add(MachineOperand::CreateES("nop\n"))
        //      .addImm(1)
        //      .setMIFlag(MachineInstr::RAIInstr);
        //}


        // add the TCFI pc relative data
        for (unsigned int i = 0; i < FlagIdRoot[IndirLBL][JSON_TCFI_SET].size(); i++){

          std::string *tcfi_metadata = new std::string(".long " +
                                                       FlagIdRoot[IndirLBL][JSON_TCFI_SET][i].asString()
                                                       + "\n");
          MIB = BuildMI(*TcfiMBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES(tcfi_metadata->c_str()))
              .addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);

          // each pc-relative data is 4 bytes
          TCFIOverhead += 4;
        }


        // add TCFI call per each possible target
        for (unsigned int i = 0; i < FlagIdRoot[IndirLBL][JSON_TCFI_SET].size(); i++){
          std::string TarName = FlagIdRoot[IndirLBL][JSON_TCFI_SET][i].asString();
          std::string TarKey = IndirLBL + "_" + TarName + "_0";
          // add TCFI label
          MIB = BuildMI(*TcfiMBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES(
                     FlagIdRoot[IndirLBL][JSON_TCFI_INSTRMNT][TarName][JSON_LABEL]
                     .asCString())).addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);


          // check if we need to restore r0, and setup R12 again
          if (SavedCallReg == ARM::R12){

            // add mov r12, r0
            MIB = BuildMI(*TcfiMBB, Inext, DbgLoc,TII.get(ARM::tMOVr), ARM::R12)
                .addReg(ARM::R0)
                .add(predOps(ARMCC::AL))
                .setMIFlag(MachineInstr::RAIInstr);

            // add pop r0
            MIB = BuildMI(*TcfiMBB, Inext, DbgLoc,TII.get(ARM::tPOP))
                .addReg(ARM::R0)
                .add(predOps(ARMCC::AL))
                .setMIFlag(MachineInstr::RAIInstr);

            // set CallReg to R12 again
            CallReg = SavedCallReg;

            // 2 instructions x 2 bytes per instruction
            TCFIOverhead += 4;

          }


          // check if we need to save SR, if so add SVC to save SR
          if (FlagIdRoot[MFName][JSON_KEYS_DICT][IndirLBL][JSON_SR_RESET].asBool()){
            MIB = BuildMI(*TcfiMBB, Inext, DbgLoc, TII.get(ARM::tSVC))
                .addImm(SvcAppSave)
                .add(predOps(ARMCC::AL))
                .setMIFlag(MachineInstr::RAIInstr);

            // update svc counter
            SVCResetCntr++;
          }

          // if it is a recursive label, instrument it using ADD, if it is a
          // regular call, then instrument it with an XOR
          if(FlagIdRoot[IndirLBL][JSON_KEYS_DICT][TarKey][JSON_ISREC].asBool()){

            if(FlagIdRoot[IndirLBL][JSON_KEYS_DICT][TarKey][JSON_ISPATHREC]
               .asBool() ||
               FlagIdRoot[IndirLBL][JSON_KEYS_DICT][TarKey]
               [JSON_IS_MULTI_RECURSIVE].asBool()){

              // add a nop to allign by 4. This is never executed but is needed
              // for allignment
              MIB = BuildMI(*TcfiMBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
                    .add(MachineOperand::CreateES("nop\n"))
                    .addImm(1)
                    .setMIFlag(MachineInstr::RAIInstr);
              // add svc to store recursion return location
              MIB = BuildMI(*TcfiMBB, Inext, DbgLoc, TII.get(ARM::tSVC))
                  .addImm(SvcRecSave)
                  .add(predOps(ARMCC::AL))
                  .setMIFlag(MachineInstr::RAIInstr);
            }

            else{
              MIB = BuildMI(*TcfiMBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
                  .add(MachineOperand::CreateES(
                         FlagIdRoot[IndirLBL][JSON_KEYS_DICT][TarKey]
                         [JSON_ADD_REC_INST].asCString()))
                  .addImm(1)
                  .setMIFlag(MachineInstr::RAIInstr);
            }


          }
          else{
            // add XOR instruction comparison
            MIB = BuildMI(*TcfiMBB, Inext, DbgLoc,TII.get(ARM::t2EORri),
                          ARM::LR)
                .addReg(ARM::LR, RegState::Kill)
                .addImm(FlagIdRoot[IndirLBL][JSON_KEYS_DICT][TarKey][JSON_KEY]
                        .asUInt64())
                .add(predOps(ARMCC::AL))
                .add(condCodeOp())
                .setMIFlag(MachineInstr::RAIInstr);
          }


          // add branch to the target
          MIB = BuildMI(*TcfiMBB, Inext, DbgLoc, TII.get(ARM::tBX))
              .addReg(CallReg)
              .add(predOps(ARMCC::AL))
              .setMIFlag(MachineInstr::RAIInstr);

          // add a nop to allign by 4. This is never executed but is needed
          // for allignment
          MIB = BuildMI(*TcfiMBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
                .add(MachineOperand::CreateES("nop\n"))
                .addImm(1)
                .setMIFlag(MachineInstr::RAIInstr);


          // add label
          MIB = BuildMI(*TcfiMBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES(
                     FlagIdRoot[IndirLBL][JSON_KEYS_DICT][TarKey][JSON_LABEL]
                     .asCString())).addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);

          // check if it is an indirect recursion, note that in case of using
          // a syscall no need to instrument after the label
          if (FlagIdRoot[IndirLBL][JSON_KEYS_DICT][TarKey][JSON_ISREC].asBool()
              &&
              !(
                FlagIdRoot[IndirLBL][JSON_KEYS_DICT][TarKey][JSON_ISPATHREC]
                .asBool() ||
                FlagIdRoot[IndirLBL][JSON_KEYS_DICT][TarKey]
                [JSON_IS_MULTI_RECURSIVE].asBool()
                )
              ){

            MIB = BuildMI(*TcfiMBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
                .add(MachineOperand::CreateES(
                       FlagIdRoot[IndirLBL][JSON_KEYS_DICT][TarKey]
                       [JSON_SUB_REC_INST].asCString()))
                .addImm(1)
                .setMIFlag(MachineInstr::RAIInstr);
          }
          else{
            // add the second XOR (decode)
            MIB = BuildMI(*TcfiMBB, Inext, DbgLoc,TII.get(ARM::t2EORri),
                          ARM::LR)
                .addReg(ARM::LR, RegState::Kill)
                .addImm(FlagIdRoot[IndirLBL][JSON_KEYS_DICT][TarKey][JSON_KEY]
                        .asUInt64())
                .add(predOps(ARMCC::AL))
                .add(condCodeOp())
                .setMIFlag(MachineInstr::RAIInstr);
          }


          // check if we needed to save SR, if so add SVC to restore SR
          if (FlagIdRoot[MFName][JSON_KEYS_DICT][IndirLBL][JSON_SR_RESET].asBool()){
            MIB = BuildMI(*TcfiMBB, Inext, DbgLoc, TII.get(ARM::tSVC))
                .addImm(SvcAppRestore)
                .add(predOps(ARMCC::AL))
                .setMIFlag(MachineInstr::RAIInstr);
          }

          //outs() << "before  @line 1181\n";
          // add branch to exit TCFI sequence
          MIB = BuildMI(*TcfiMBB, Inext, DbgLoc,TII.get(ARM::INLINEASM))
              .add(MachineOperand::CreateES(
                     FlagIdRoot[IndirLBL][JSON_TCFI_EXIT]
                     .asCString())).addImm(1)
              .setMIFlag(MachineInstr::RAIInstr);
        }

        nop_cntr++;

        // 2 instructions (4 + 2 = 6 bytes) from branching to and
        // returning from tcfi handler per indirect call
        TCFIOverhead += 6;

      }

    }


    void addIndirectCallNoLink(MachineBasicBlock & MBB,
                            MachineInstrBuilder & MIB,
                            MachineInstr &MI,
                            MachineBasicBlock::iterator I,
                            const ARMBaseInstrInfo &TII){

      // This function assumes that the given MI is BLX!

      auto DbgLoc = MI.getDebugLoc();
      // create new instruction
      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::tBX)).setMIFlag(MachineInstr::RAIInstr);
      // The new instruction should be the same except that we remove
      // the uses of LR
      int OpCntr = 0;
      for(MachineOperand OP: MI.operands()){
        // add operand if it is not LR
        if (OpCntr > 1){
          MIB.add(OP);
        }
        //MIB.add(OP);
        OpCntr++;
      }
    }

    std::string getCalleeName(MachineOperand OP){
      std::string CalleStr;
      std::string ResStr;
      raw_string_ostream CalleeRso(CalleStr);
      //get the callee name without the initial @ or &
      CalleeRso << OP;
      ResStr = CalleeRso.str();
      ResStr.erase(std::remove(ResStr.begin(), ResStr.end(), '@'), ResStr.end());
      ResStr.erase(std::remove(ResStr.begin(), ResStr.end(), '&'), ResStr.end());
      return ResStr;
    }

    std::string getURAILabel(std::string MFName, MachineOperand OP,
                             std::map<std::string, uint8_t> *CalleeCntrMap,
                             bool isDirectCall){
      std::string CalleStr;
      std::string ResStr;
      raw_string_ostream CalleeRso(CalleStr);
      if (isDirectCall){
        // First, get the callee name without the initial @
        CalleeRso << OP;
        ResStr = CalleeRso.str();
        ResStr.erase(std::remove(ResStr.begin(), ResStr.end(), '@'), ResStr.end());
        ResStr.erase(std::remove(ResStr.begin(), ResStr.end(), '&'), ResStr.end());

        // Now, check it exitst in CalleeCntrMap. If so, then update the counter.
        // If not, initialize it to 0
        if(CalleeCntrMap->find(ResStr) == CalleeCntrMap->end()){
          // No entry for the calle was found, initialize it to 0
          CalleeCntrMap->insert(std::make_pair(ResStr, 0));
        }
        else{
          // The callee name already exists in CalleeCntrMap, so update it
          CalleeCntrMap->at(ResStr) = CalleeCntrMap->at(ResStr) + 1;
        }
        // Form the final label and return it
        ResStr = MFName + "_" + ResStr + "_" + std::to_string(CalleeCntrMap->at(ResStr));
      }
      // if it is an indirect call
      else{
        ResStr = MFName + "_" + INDIR_SUFFIX;
        // Now, check it exitst in CalleeCntrMap. If so, then update the counter.
        // If not, initialize it to 0
        if(CalleeCntrMap->find(ResStr) == CalleeCntrMap->end()){
          // No entry for the calle was found, initialize it to 1 in case of indirect
          CalleeCntrMap->insert(std::make_pair(ResStr, 1));
        }
        else{
          // The callee name already exists in CalleeCntrMap, so update it
          CalleeCntrMap->at(ResStr) = CalleeCntrMap->at(ResStr) + 1;
        }
        ResStr = ResStr + std::to_string(CalleeCntrMap->at(ResStr));

      }

      return ResStr;
    }


    void instrumentISREntry(MachineBasicBlock & MBB,
                            MachineInstrBuilder & MIB,
                            MachineInstr &MI,
                            MachineBasicBlock::iterator I,
                            const ARMBaseInstrInfo &TII){

      auto DbgLoc = MI.getDebugLoc();
      // 1. save special value of lr
      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES("mov r0, lr\n")).addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES("ldr r1,=saved_lr_isr\n"))
          .addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES("str r0,[r1]\n"))
          .addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

      // 2. save pc from the stack, and mask it
      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES("ldr r0, [sp,#24]\n")).addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES("ldr r1,=saved_pc_isr\n"))
          .addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES("str r0,[r1]\n"))
          .addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES("mov r0, #0\n"))
          .addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES("str r0, [sp,#24]\n")).addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

      // 3. save lr (i.e., SR) from the stack, and mask it
      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES("ldr r0, [sp,#20]\n")).addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES("ldr r1,=saved_sr_isr\n"))
          .addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES("str r0,[r1]\n"))
          .addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES("mov r0, #0\n"))
          .addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES("str r0, [sp,#20]\n")).addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

      // set up lr to the initial value of SR
      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES("ldr lr,=initial_rai_sr\n"))
          .addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES("ldr lr,[lr]\n"))
          .addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);


    }

    void instrumentISRExit(MachineBasicBlock & MBB,
                            MachineInstrBuilder & MIB,
                            MachineInstr &MI,
                            MachineBasicBlock::iterator I,
                            const ARMBaseInstrInfo &TII){


      auto DbgLoc = MI.getDebugLoc();

      // 1. restore the special value of lr
      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES("ldr r12,=saved_lr_isr\n"))
          .addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES("ldr r12,[r12]\n")).addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES("mov lr, r12\n")).addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);


      // 2. restore pc on the stack
      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES("ldr r12,=saved_pc_isr\n"))
          .addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES("ldr r12,[r12]\n"))
          .addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES("str r12, [sp,#24]\n")).addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

      // 3. restore lr (i.e., SR) on the stack
      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES("ldr r12,=saved_sr_isr\n"))
          .addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES("ldr r12,[r12]\n"))
          .addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES("str r12, [sp,#20]\n")).addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

      // 4. Exit the ISR
      MIB = BuildMI(MBB, I, DbgLoc,TII.get(ARM::INLINEASM))
          .add(MachineOperand::CreateES("bx lr\n")).addImm(1)
          .setMIFlag(MachineInstr::RAIInstr);

    }


    bool doInitialization(Module &) override{
      if ( URAIInstrumentation.compare("-") == 0 ){
          return false;
      }

      errs() << "===========================================================\n";
      errs() << "@URAI Instrumentation: doInitialization \n";
      // print the path and name of the input file
      errs() << "[+] Opening file: ";
      errs() << "\n\t";
      errs().write_escaped(URAIInstrumentation) << "\n";
      std::string ext_lib_file = URAIBuildDir + EXT_LIB_FILE_NAME;
      std::string ext_lib_opt_list_file = URAIBuildDir + EXT_LIB_OPT_LIST_FILE_NAME;
      std::string mc_analysis_file = URAIBuildDir + URAI_MC_ANALYSIS_FILE_NAME;
      std::string mc_debug_file = URAIBuildDir + URAI_MC_DEBUG_FILE_NAME;
      // file containing used labels
      std::string lbl_file_name = URAIBuildDir + USED_LABELS_FILE;
      // read the encoding file
      InputFd.open(URAIInstrumentation);
      // check the file exists
      if (!InputFd){
        errs() << "[-] ERROR: Cannot open file: " << URAIInstrumentation << "\n";
      }
      // read the contents into FlagIdRoot
      InputFd >> FlagIdRoot;


      // read the used labels file
      LblsFd.open(lbl_file_name);
      // check the file exists
      if (!LblsFd){
        errs() << "[-] ERROR: Cannot open file: " << lbl_file_name << "\n";
      }
      // read the contents into LabelsRoot
      LblsFd >> LabelsRoot;


      // open the extlib dictionary
      ExtLibFd.open(ext_lib_file);
      if (!ExtLibFd){
        errs() << "[-] ERROR: Cannot open file: " << ext_lib_file << "\n";
      }
      // read the contents into ExtLibRoot
      ExtLibFd >> ExtLibJsonRoot;


      // open the optmized extlib dictionary
      ExtLibOptFd.open(ext_lib_opt_list_file);
      if (!ExtLibOptFd){
        errs() << "[-] ERROR: Cannot open file: " <<
                  ext_lib_opt_list_file<< "\n";
      }
      // read the contents into ExtLibOptFd
      ExtLibOptFd >> ExtLibOptListJsonRoot;


      // open analysis and debug files
      AnalysisFd.open(mc_analysis_file);
      DbgFd.open(mc_debug_file);

      // [urai-debug]: should change the below to true
      return false;
    }

    bool doFinalization(Module &) override{
      if ( URAIInstrumentation.compare("-") == 0 ){
          return false;
      }

      errs() << "[+] Closing files: ";
      errs() << "\n\t";
      errs().write_escaped(URAIInstrumentation) << "\n";
      AnalysisFd.close();
      errs() << "\n\t";
      errs().write_escaped(URAI_MC_DEBUG_FILE_NAME) << "\n";
      DbgFd.close();
      errs() << "===========================================================\n";
      //errs() << "INDIR Call Reg Map:\n";
      //for (auto const& IndirCall: IndirCallRegMap){
      //  outs() << "LBL: " << IndirCall.first << " -> " << IndirCall.second << "\n";
      //}

      // write mem-overhead-stats
      std::ofstream memOverheadJsonFile;
      std::string mem_oh_file = URAIBuildDir + MEM_OVERHEAD_STATS;
      errs() << "[+] writing " << mem_oh_file << " file\n";
      Json::Value mem_oh_root;
      mem_oh_root[JSON_TCFI_OH] = TCFIOverhead;
      mem_oh_root[JSON_FLT_OH] = FLTOverhead;
      mem_oh_root[JSON_EHSFI_OH] = EHSFIMemOverhead;
      memOverheadJsonFile.open(mem_oh_file);
      memOverheadJsonFile << mem_oh_root;
      memOverheadJsonFile.close();

      // write the bin-flt-eff
      std::ofstream binFltFile;
      std::string bin_flt_filename = URAIBuildDir + BIN_FLT_EFF;
      binFltFile.open(bin_flt_filename);
      errs() << "[+] writing " << bin_flt_filename << " file\n";
      binFltFile << BinFltEff;
      binFltFile.close();

      // write EHSFI stats
      std::ofstream SvcEhSfiFd;
      std::string svc_ehsfi_filename = URAIBuildDir + SVC_EHSFI_STATS;
      SvcEhSfiFd.open(svc_ehsfi_filename);
      errs() << "[+] writing " << svc_ehsfi_filename << " file\n";
      Json::Value svc_ehsfi_root;
      svc_ehsfi_root[JSON_EHSFI_INSTRS] = EHSFIStrInstrsCntr;
      svc_ehsfi_root[JSON_SVC_INSTRS] = SVCResetCntr;
      svc_ehsfi_root[JSON_NUM_DIR_CALLS] = DirCallsCntr;
      svc_ehsfi_root[JSON_NUM_URAI_CALLS] = DirCallsCntr - ExtLibCallsCntr;
      svc_ehsfi_root[JSON_NUM_INDIR_CALLS] = IndirCallsCntr;
      svc_ehsfi_root[JSON_NUM_EXTLIB_CALLS] = ExtLibCallsCntr;
      svc_ehsfi_root[JSON_NUM_TOT_CALLS] = TotCallsCntr;

      SvcEhSfiFd << svc_ehsfi_root;
      SvcEhSfiFd.close();


      errs() << "===========================================================\n";
      // [urai-debug]: should change the below to true
      return false;
    }

    StringRef getPassName() const override{
      return StringRef("Pass to instrument URAI");
    }

  };

  char URAIInstrumentationMCPass::ID = 0;

}

FunctionPass *llvm::createURAIInstrumentationMCPass(){
  return new URAIInstrumentationMCPass();
}


