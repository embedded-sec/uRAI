#!/bin/bash
#REPO_HOST=http://llvm.org/git


################################################################################
# This file was taken from ACES (https://github.com/embedded-sec/ACES).
# Orignial credit goes to them. It was modified here for uRAI.
################################################################################


#Needs to be run from root dir of repo
set e, x
COMPILER_DIR=$(readlink -f `dirname $0`/..)
PROJECT_ROOT_DIR=`dirname ${COMPILER_DIR}`
THIS_DIR=`dirname \`readlink -f $0\``
LLVM_DIR=${PROJECT_ROOT_DIR}/llvm/llvm-release_70
CLANG_DIR=${PROJECT_ROOT_DIR}/llvm/clang-release_70
SYM_LINK='ln -sfn'


# download llvm 7.0, clang 7.0, and arm-none-eabi-gcc
wget -O ${PROJECT_ROOT_DIR}/compiler/3rd_party/llvm-release_70.zip https://github.com/llvm-mirror/llvm/archive/release_70.zip

wget -O ${PROJECT_ROOT_DIR}/compiler/3rd_party/clang-release_70.zip https://github.com/llvm-mirror/clang/archive/release_70.zip


wget -O ${PROJECT_ROOT_DIR}/compiler/3rd_party/gcc-arm-none-eabi-6-2017-q1-update-src.tar.bz2 https://developer.arm.com/-/media/Files/downloads/gnu-rm/6_1-2017q1/gcc-arm-none-eabi-6-2017-q1-update-src.tar.bz2?revision=9a8be9e8-7ddd-4841-ac76-c6ccb81151ba?product=GNU-RM%20Downloads,Invariant,,Source,6-2017-q1-update


#################################  SETUP LLVM  #################################
# All paths used in this explaination are relative to the root dir of the repo
# Uses Release 70 of LLVM an Clang (Version 7.0) that was downloaded from then
# Github mirror.  Extracts these archives to ../llvm/llvm-release_70 and
# ../llvm/clang-release_70.  Then uses setup_symlinks, to patch in the URAI
# changes.  The source for the URAI changes are in <ThisRepoRoot>/llvm
################################################################################
if [ ! -e ${LLVM_DIR} ]
then

  mkdir -p ${PROJECT_ROOT_DIR}/llvm/build
  #  SYM_LINK in clang
  unzip -o ${COMPILER_DIR}/3rd_party/llvm-release_70.zip -d ${COMPILER_DIR}/../llvm/

fi

if [ ! -e ${CLANG_DIR} ]
then
  unzip -o ${COMPILER_DIR}/3rd_party/clang-release_70.zip -d ${COMPILER_DIR}/../llvm/
  ${SYM_LINK} ${CLANG_DIR} ${LLVM_DIR}/tools/clang
fi

${COMPILER_DIR}/llvm/setup_symlinks.sh

################################################################################


######################     Build GCC    ########################################
# Checks to see if the appropriate version of GCC has been build and placed at
# the correct location, if not builds it, using the archive src in this
# repo.  Uses a slightly modified (Builds linker with plugin support) archive.
################################################################################
if [ ! -e ${PROJECT_ROOT_DIR}/gcc/bins ]
then
  mkdir -p ${PROJECT_ROOT_DIR}/gcc
  cd ${PROJECT_ROOT_DIR}/gcc
  if [ ! -e gcc-arm-none-eabi-6-2017-q1-update/pkg ]
  then

     cp ${COMPILER_DIR}/3rd_party/gcc-arm-none-eabi-6-2017-q1-update-src.tar.bz2 .
     tar -xjf gcc-arm-none-eabi-6-2017-q1-update-src.tar.bz2
     cd gcc-arm-none-eabi-6-2017-q1-update
     cp ${COMPILER_DIR}/setup_scripts/gcc_build_toolchain.sh build-toolchain.sh
     cd src
     find -name '*.tar.*' | xargs -I% tar -xf %
     cd ..
     ./build-prerequisites.sh --skip_steps=mingw32
     ./build-toolchain.sh --skip_steps=mingw32
     cd ${PROJECT_ROOT_DIR}/gcc
  fi
  cd ${PROJECT_ROOT_DIR}/gcc/gcc-arm-none-eabi-6-2017-q1-update/pkg
  tar -xjf gcc-arm-none-eabi-6-2021-q1-update-linux.tar.bz2
  mv gcc-arm-none-eabi-6-2021-q1-update/* ../../bins/
  echo "Content was moved to ../../bins" > gcc-arm-none-eabi-6-2021-q1-update/README.md
  cd ${COMPILER_DIR}
fi


###############################################################################
