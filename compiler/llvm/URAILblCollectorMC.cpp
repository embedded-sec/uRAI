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





static cl::opt<std::string> URAILblCollector("urai-collector",
                                  cl::desc("Build Dir of JSON file the urai collector "
                                           "writes for used labels."),
                                  cl::init("-"),cl::value_desc("filename"));



#define URAI_COLLECTOR_RES_FILE   "USED_LABELS.json"

// These are the feilds of the input JSON file
#define JSON_KEY                    "KEY"
#define JSON_SHIFT                  "SHIFT"
#define JSON_XOR_INST               "XOR_INST_KEY"
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
#define JSON_IS_SHIFTED             "IS_SHIFTED"
#define JSON_ISREC                  "IS_RECURSIVE"
#define JSON_ISPATHREC              "IS_PATH_RECURSIVE"
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

//===-----------------------------MainCode-------------------------------===//


namespace {
  class URAILblCollectorMC : public MachineFunctionPass {
  public:
    static char ID;
    URAILblCollectorMC() : MachineFunctionPass(ID) {}

    std::ofstream ResFd;      // Analysis file
    Json::Value JsonLBLRoot;   // The root of the labels file
    Json::Value FlagIdRoot;   // The root of the key-flag-ids input file
    /// this map is used to check which label was actually used as in higher
    /// optimizations some call sites from the IR level are optimized. Whenever
    /// a label is actually added to the binary, it should be added to this map
    /// so that the FLT is instrumented correctly. That is, if a lable was
    /// optimized we should not add it to the FLTs.
    std::map<std::string, unsigned> LblAccessMap;

    std::map<std::string, unsigned> IndirCallRegMap;


    // A special case is the tcfi-handler, we add all of its instructions once
    // and return. It does not go through the same process as other functions.

    bool runOnMachineFunction(MachineFunction &MF) override{

      if ( URAILblCollector.compare("-") == 0 ){
          return false;
      }

      // a map between callees and the call number in the current function.
      // This is used to get the correct label, xor instruction, and key.
      std::map<std::string, uint8_t> CalleeCntrMap;
      //------------------------------------------------------------------------
      // This part should only run once in the entire pass to collect the
      // actually used labels

      if(MF.getFunction().hasFnAttribute("URAICall") &&
         MF.getName().find("llvm.") == std::string::npos &&
         MF.getName().find("__tcfi_handler") == std::string::npos){

         for (MachineBasicBlock &MBB: MF){

           for(MachineInstr &MI: MBB){
             if(MI.isCall() && MI.getOpcode() != ARM::tSVC){
               //errs() << "there is a call in: " << MF.getName() << "\n";
               // (1) if this is a direct call
               if (!isIndirectCall(MI.getOpcode())){

                 uint32_t CalleeOpIdx = getCalleeOpIdx(MI);
                 std::string LBL = getURAILabel(MF.getName(), MI.getOperand(CalleeOpIdx),
                                                &CalleeCntrMap, true);
               }
               // (2) indirect call
               else{
                 std::string LBL = getURAILabel(MF.getName(), MI.getOperand(2),
                                                &CalleeCntrMap, false);
               }
             }
           }
         }
      }

      // END of LABEL COLLECTION
      //------------------------------------------------------------------------

      return true;
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
          Opcode == ARM::tBLXi || Opcode == ARM::tBLXNSr){
        return true;
      }

      return false;
    }

    uint32_t getCalleeOpIdx(MachineInstr &MI){
      std::string str;
      raw_string_ostream rso(str);
      uint32_t idx = 0, callee_idx = 0;

      //outs() <<  "checking func: " << MI.getParent()->getParent()->getName() << "\n";
      //outs() << "MI: " << MI << "\n";
      for (MachineOperand OP: MI.operands()){
        //rso.str().clear();
        //outs() << "\t OP[" << idx << "]: " << OP << ", type: " << std::to_string(OP.getType()) <<"\n";
        //DbgFd << rso.str();
        if (OP.getType() == MachineOperand::MachineOperandType::MO_GlobalAddress){
          callee_idx = idx;
          //outs() << "\t callee idx = " << callee_idx << "\n";
          return callee_idx;
        }
        idx++;
      }
      callee_idx = 2;
      //outs() << "\t Did not find callee idx, defaulting to = " << callee_idx << "?\n";
      return callee_idx;
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

      // add label to label map
      std::string b_lbl = "b " + ResStr + "\n";
      if (LblAccessMap.find(b_lbl) ==  LblAccessMap.end()){

        LblAccessMap.insert(std::make_pair(b_lbl, 1));
      }
      else{
        LblAccessMap.at(b_lbl) = LblAccessMap.at(b_lbl) + 1;
      }

      // if this is an indirect call, add all labels from the target set
      if(!isDirectCall){
        for (unsigned int i = 0; i < FlagIdRoot[ResStr][JSON_TCFI_SET].size(); i++){
          std::string TarName = FlagIdRoot[ResStr][JSON_TCFI_SET][i].asString();
          std::string TarKey = ResStr + "_" + TarName + "_0";
          // add label to label map
          std::string b_lbl = "b " + TarKey + "\n";
          if (LblAccessMap.find(b_lbl) ==  LblAccessMap.end()){

            LblAccessMap.insert(std::make_pair(b_lbl, 1));
          }
          else{
            LblAccessMap.at(b_lbl) = LblAccessMap.at(b_lbl) + 1;
          }
        }

      }


      return ResStr;
    }


    void CollectLabel(std::string MFName, MachineOperand OP,
                             std::map<std::string, unsigned> *LabelAccMap,
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
        if(LabelAccMap->find(ResStr) == LabelAccMap->end()){
          // No entry for the calle was found, initialize it to 0
          LabelAccMap->insert(std::make_pair(ResStr, 0));
        }
        else{
          // The callee name already exists in LabelAccMap, so update it
          LabelAccMap->at(ResStr) = LabelAccMap->at(ResStr) + 1;
        }
        // Form the final label and return it
        ResStr = MFName + "_" + ResStr + "_" + std::to_string(LabelAccMap->at(ResStr));
      }
      // if it is an indirect call
      else{
        ResStr = MFName + "_" + INDIR_SUFFIX;
        // Now, check it exitst in LabelAccMap. If so, then update the counter.
        // If not, initialize it to 0
        if(LabelAccMap->find(ResStr) == LabelAccMap->end()){
          // No entry for the calle was found, initialize it to 1 in case of indirect
          LabelAccMap->insert(std::make_pair(ResStr, 1));
        }
        else{
          // The callee name already exists in CalleeCntrMap, so update it
          LabelAccMap->at(ResStr) = LabelAccMap->at(ResStr) + 1;
        }
        ResStr = ResStr + std::to_string(LabelAccMap->at(ResStr));

      }

      // add label to label map
      std::string b_lbl = "b " + ResStr + "\n";
      if (LabelAccMap->find(b_lbl) ==  LabelAccMap->end()){

        LabelAccMap->insert(std::make_pair(b_lbl, 1));
      }
      else{
        LabelAccMap->at(b_lbl) = LabelAccMap->at(b_lbl) + 1;
      }

      return;
    }

    bool doInitialization(Module &) override{
      if ( URAILblCollector.compare("-") == 0 ){
          return false;
      }

      errs() << "***********************************************************\n";
      errs() << "@URAI Label collectpr: doInitialization \n";
      std::ifstream FkFIDsInput;
      std::string input_file = URAILblCollector + "urai-keys-flag-ids.json";
      // read the encoding file
      FkFIDsInput.open(input_file);
      // check the file exists
      if (!FkFIDsInput){
        errs() << "[-] ERROR: Cannot open file: " << input_file << "\n";
      }
      // read the contents into FlagIdRoot
      FkFIDsInput >> FlagIdRoot;

      // [urai-debug]: should change the below to true
      return false;
    }

    bool doFinalization(Module &) override{
      if ( URAILblCollector.compare("-") == 0 ){
          return false;
      }

      //  errs() << "***********************************************************\n";

      std::ofstream jsonFile;
      std::string res_file = URAILblCollector + URAI_COLLECTOR_RES_FILE;

      //errs() << "LBL Call Map:\n";
      for (auto const& Lbl: LblAccessMap){
        //outs() << "LBL_ACCESS: " << Lbl.first << " -> " << Lbl.second << "\n";
        // we only care about the name of the label, 1 here is just a dummy value
        JsonLBLRoot[Lbl.first] = "1";
      }

      errs() << "[+] Writing label collector results to: ";
      errs().write_escaped(res_file) << "\n";
      jsonFile.open(res_file);
      jsonFile<<JsonLBLRoot;
      jsonFile.close();


      errs() << "***********************************************************\n";
      // [urai-debug]: should change the below to true
      return false;
    }

    StringRef getPassName() const override{
      return StringRef("Pass to collect URAI labels");
    }

  };


//INITIALIZE_PASS_BEGIN(URAILblCollectorMC, "URAILblCollectorMC","Collects used label after optimizations",false, false)
//INITIALIZE_PASS_END(URAILblCollectorMC, "URAILblCollectorMC","Collects used label after optimizations",false, false)
  char URAILblCollectorMC::ID = 0;
}




FunctionPass *llvm::createURAILblCollectorMCPass(){
  return new URAILblCollectorMC();
}


