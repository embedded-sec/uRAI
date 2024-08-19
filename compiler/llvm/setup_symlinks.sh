set -e
REPO_ROOT=$(readlink -f `dirname $0`/..)
PROJECT_ROOT_DIR=`dirname ${REPO_ROOT}`
THIS_DIR=`dirname \`readlink -f $0\``
LLVM_DIR=${PROJECT_ROOT_DIR}/llvm/llvm-release_70
CLANG_DIR=${PROJECT_ROOT_DIR}/llvm/clang-release_70


SYM_LINK='ln -sfn'

# json library files
mkdir -p ${LLVM_DIR}/include/json
${SYM_LINK} ${REPO_ROOT}/llvm/json-forwards.h ${LLVM_DIR}/include/json/json-forwards.h
${SYM_LINK} ${REPO_ROOT}/llvm/json.h ${LLVM_DIR}/include/json/json.h
${SYM_LINK} ${REPO_ROOT}/llvm/lib-Support-CMakeLists.txt ${LLVM_DIR}/lib/Support/CMakeLists.txt
${SYM_LINK} ${REPO_ROOT}/llvm/jsoncpp.cpp ${LLVM_DIR}/lib/Support/jsoncpp.cpp

# URAI passes
${SYM_LINK} ${REPO_ROOT}/llvm/URAIAnalysis.cpp ${LLVM_DIR}/lib/Transforms/Utils/URAIAnalysis.cpp
${SYM_LINK} ${REPO_ROOT}/llvm/lib-Transforms-Utils-CMakeLists.txt ${LLVM_DIR}/lib/Transforms/Utils/CMakeLists.txt

# add URAI passes to llvm
${SYM_LINK} ${REPO_ROOT}/llvm/InitializePasses.h ${LLVM_DIR}/include/llvm/InitializePasses.h
${SYM_LINK} ${REPO_ROOT}/llvm/Instrumentation.h ${LLVM_DIR}/include/llvm/Transforms/Instrumentation.h
${SYM_LINK} ${REPO_ROOT}/llvm/LinkAllPasses.h ${LLVM_DIR}/include/llvm/LinkAllPasses.h
${SYM_LINK} ${REPO_ROOT}/llvm/LTOCodeGenerator.cpp ${LLVM_DIR}/lib/LTO/LTOCodeGenerator.cpp
${SYM_LINK} ${REPO_ROOT}/llvm/PassManagerBuilder.cpp ${LLVM_DIR}/lib/Transforms/IPO/PassManagerBuilder.cpp
${SYM_LINK} ${REPO_ROOT}/llvm/Utils.cpp ${LLVM_DIR}/lib/Transforms/Utils/Utils.cpp
${SYM_LINK} ${REPO_ROOT}/llvm/Function.cpp ${LLVM_DIR}/lib/IR/Function.cpp
${SYM_LINK} ${REPO_ROOT}/llvm/Function.h ${LLVM_DIR}/include/llvm/IR/Function.h


# Backend
${SYM_LINK} ${REPO_ROOT}/llvm/URAIInstrumentationMC.cpp ${LLVM_DIR}/lib/Target/ARM/URAIInstrumentationMC.cpp
${SYM_LINK} ${REPO_ROOT}/llvm/URAILblCollectorMC.cpp ${LLVM_DIR}/lib/Target/ARM/URAILblCollectorMC.cpp
${SYM_LINK} ${REPO_ROOT}/llvm/lib-Target-ARM-CMakeLists.txt ${LLVM_DIR}/lib/Target/ARM/CMakeLists.txt
${SYM_LINK} ${REPO_ROOT}/llvm/ARM.h ${LLVM_DIR}/lib/Target/ARM/ARM.h
${SYM_LINK} ${REPO_ROOT}/llvm/ARMTargetMachine.cpp ${LLVM_DIR}/lib/Target/ARM/ARMTargetMachine.cpp

# file to reserve registers
${SYM_LINK} ${REPO_ROOT}/llvm/ARMBaseRegisterInfo.cpp ${LLVM_DIR}/lib/Target/ARM/ARMBaseRegisterInfo.cpp

# test pass to instrument SFI
${SYM_LINK} ${REPO_ROOT}/llvm/RAISFI.cpp ${LLVM_DIR}/lib/Target/ARM/RAISFI.cpp

${SYM_LINK} ${REPO_ROOT}/llvm/ARMInstrThumb.td ${LLVM_DIR}/lib/Target/ARM/ARMInstrThumb.td
${SYM_LINK} ${REPO_ROOT}/llvm/ARMInstrInfo.td ${LLVM_DIR}/lib/Target/ARM/ARMInstrInfo.td
# This file might help in ristrcting the use of LR as an operand (as GPR)
${SYM_LINK} ${REPO_ROOT}/llvm/ARMRegisterInfo.td ${LLVM_DIR}/lib/Target/ARM/ARMRegisterInfo.td

${SYM_LINK} ${REPO_ROOT}/llvm/ARMISelLowering.cpp ${LLVM_DIR}/lib/Target/ARM/ARMISelLowering.cpp
${SYM_LINK} ${REPO_ROOT}/llvm/ARMISelLowering.h ${LLVM_DIR}/lib/Target/ARM/ARMISelLowering.h

# For metadata
${SYM_LINK} ${REPO_ROOT}/llvm/Instructions.h ${LLVM_DIR}/include/llvm/IR/Instructions.h

# This file is for flagging URAI instructions
${SYM_LINK} ${REPO_ROOT}/llvm/MachineInstr.h ${LLVM_DIR}/include/llvm/CodeGen/MachineInstr.h


#

