//===- RAISFIAnalysis.cpp -------------------------------------------------===//
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


/// file name for debugging file during development
#define FULL_SFI_STATS             "full-sfi-stats.json"
#define RAISFI_MC_DEBUG_FILE_NAME  "FullSFI-Dbg.txt"


// These are the feilds of the input JSON file


// These are field names for mem-overhead-stats file
#define FULL_SFI_INSTRS           "full-sfi-instrs"







static cl::opt<std::string> RAISFI("raisfi-instrumentation",
                                  cl::desc("Flag to enable SFI instrumentation")
                                   , cl::init("-"),cl::value_desc("any str"));



static cl::opt<std::string> RAISFIBuildDir("raisfi-build-dir",
                                  cl::desc("The path to the build directory."),
                                  cl::init("-"),cl::value_desc("build dir"));

//===-----------------------------MainCode-------------------------------===//


namespace {
  class RAISFIPass : public MachineFunctionPass {
  public:
    static char ID;
    RAISFIPass() : MachineFunctionPass(ID) {}

    // used for Full SFI
    std::string spec_msr_inst[4] = {
      "mrs r0,apsr\n",
      "msr apsr,r0\n",
      "mrs r1,apsr\n",
      "msr apsr,r1\n"
    };

    // copied fron RAI's instrumentation, put here to avoid global duplication
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
    //


    std::ofstream DbgFd;      // File used for debugging only


    uint64_t FullSFIStrInstrsCntr = 0; // counter for FullSFI instrumented STRs


    bool runOnMachineFunction(MachineFunction &MF) override{
      bool returnVal = false;

      if ( RAISFI.compare("-") == 0 ){
          return false;
      }


      // str objs used to write instructions to debgging files
      std::string str;
      raw_string_ostream rso(str);
      // log results to analysis file
      std::string MFName = MF.getName().str();
      std::string line = "[FullSFI]->Func: " + MFName + "\n";
      DbgFd << "------------------------------------------------------------\n";
      DbgFd << line;


      // Initialize the machine instruction builder
      MachineInstrBuilder MIB;
      // get the target instruction info
      const ARMBaseInstrInfo &TII =
          *static_cast<const ARMBaseInstrInfo *>(MF.getSubtarget().getInstrInfo());


      DbgFd << "********************************************************\n";
      DbgFd << "Function: " << MFName << "\n";


      // loop through every basic block in function
      for (MachineBasicBlock &MBB: MF){

        // create a vector of instructions to be deleted (these are replaced by
        // our instrumented instructions)
        SmallVector<MachineInstr *, 32> DelInstVect;

        for(MachineInstr &MI: MBB){

          auto DbgLoc = MI.getDebugLoc();
          auto Inext = std::next(MI.getIterator());
          auto I = std::next(MI.getIterator());


          //--------------------------------------------------------------------
          // [rai-debug]: logging cbz/cbnz instructions
          if (
            (MI.getOpcode() == ARM::tCBZ || MI.getOpcode() == ARM::tCBNZ)
            //&& (MFName.compare("main") == 0)
            ){
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
          // Mask store instructions to apply SFI to EH context
          if (isSTRInstr(MI.getOpcode()) &&
              !MI.getFlag(MachineInstr::RAIInstr) &&
              (MFName.compare("SysTick_Handler") != 0) &&
              (MFName.compare("HAL_GetTick") != 0) &&
              // The below functions are  uncommented only for CoreMark
              // this actually under-approximates the overhead of SFI
              //(MFName.compare("ee_printf") != 0) &&
              //(MFName.compare("number") != 0) &&
              //(MFName.compare("HAL_GPIO_Init") != 0) &&
              //(MFName.compare("calc_func") != 0) &&
              //(MFName.compare("main") != 0) &&
              //--------------------------------------------------------
              // SFI requires excluding some functions to work, as otherwise
              // the app breaks. This again under-approximates SFI (which is
              // in favor of it)
              (MFName.compare("BSP_LCD_DrawBitmap") != 0) &&
              (MFName.compare("SD_initialize") != 0)){ 
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

            instrumentFullSfi(MBB, MIB, MI, Inext, TII);

            // updated EHSfi counter
            FullSFIStrInstrsCntr++;

            // delete the old str instruction
            DelInstVect.push_back(&MI);

            DbgFd << rso.str();
            rso.str().clear();

          }
          // end of [rai-debug]
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

      DbgFd << "********************************************************\n";

      // [raisfi-debug]: should change the below to true
      return returnVal;
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


    void instrumentFullSfi(MachineBasicBlock & MBB,
                                  MachineInstrBuilder & MIB,
                                  MachineInstr &MI,
                                  MachineBasicBlock::iterator Inext,
                                  const ARMBaseInstrInfo &TII){

      auto DbgLoc = MI.getDebugLoc();
      unsigned DstRegOpNum = getSTRDestRegOpNum(MI.getOpcode());
      MachineOperand DstReg = MI.getOperand(DstRegOpNum);

      // do not mask SP, assume it is pre-checked otherwise for full SFI
      if (DstReg.getReg() != ARM::SP){
        // add bic to mask store
        BuildMI(MBB, Inext, DbgLoc, TII.get(ARM::t2BICri), DstReg.getReg())
            .addReg(DstReg.getReg())
            .addImm(0x10000000) //0x10000000
            .add(predOps(ARMCC::AL))
            .add(condCodeOp())
            .setMIFlag(MachineInstr::RAIInstr);
      }

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



    bool doInitialization(Module &) override{
      if ( RAISFI.compare("-") == 0 ){
          return false;
      }

      errs() << "===========================================================\n";
      errs() << "@RAISFI Instrumentation: doInitialization \n";
      // print the path and name of the input file
      errs() << "[+] Opening file: ";
      errs() << "\n\t";
      errs().write_escaped(RAISFI) << "\n";
      std::string mc_debug_file = RAISFIBuildDir + RAISFI_MC_DEBUG_FILE_NAME;

      DbgFd.open(mc_debug_file);
      errs() << "===========================================================\n";

      // [raisfi-debug]: should change the below to true
      return false;
    }

    bool doFinalization(Module &) override{
      if ( RAISFI.compare("-") == 0 ){
          return false;
      }

      errs() << "[+] Closing files: ";
      errs() << "\n\t";
      errs().write_escaped(RAISFI) << "\n";
      errs() << "\n\t";
      errs().write_escaped(RAISFI_MC_DEBUG_FILE_NAME) << "\n";
      DbgFd.close();

      errs() << "===========================================================\n";
      // [raisfi-debug]: should change the below to true
      return false;
    }

    StringRef getPassName() const override{
      return StringRef("Pass to instrument RAISFI");
    }

  };

  char RAISFIPass::ID = 0;

}

FunctionPass *llvm::createRAISFIPass(){
  return new RAISFIPass();
}


