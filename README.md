# uRAI: Securing Embedded Systems with Return Address Integrity


This is a joint research effort between EPFL's [HexHive](http://hexhive.github.io/) and Purdue's [DCSL](https://engineering.purdue.edu/dcsl/) research groups.  The [paper](https://nebelwelt.net/publications/files/20NDSS.pdf) was published at [the The Network and Distributed System Security Symposium (NDSS20)](https://www.ndss-symposium.org/ndss2020/). 

Both groups have many more open sourced software:
*  [HexHive Software](https://github.com/HexHive)
*  [DCSL Software](https://github.com/purdue-dcsl)



## Prerequisites

```
build-essentials
make
texinfo
bison
flex
cmake
ninja-build
ncurses-dev
llvm-dev
clang
texlive-full
binutils-dev
python-networkx
python-matplotlib
python-pygraphviz
python-serial
pypip
autoconf
autogen
bison
dejagnu
flip
gawk
git
gperf
gzip
nsis
openssh-client
p7zip-full
perl
python-dev
libisl-dev
scons
tcl
tofrodos
wget
zip
texlive
texlive-extra-utils

```

```
pip install pydotplus
```

##  Setup
To setup the project for the first time clone repo then run.

```
cd compiler
./ci_scripts/init_project.sh
./ci_scripts/ci-build.sh
./mpu_configs/setup_mpu_config_sym_links.sh
```
This will download CLANG 7.0, LLVM 7.0, and arm-none-eabi-gcc. It will setup the directory structure, build a arm-none-eabi-ld with plug-in support (builds all gcc)
and build the uRAI compiler.  Which is an extension of LLVM.

The resulting directory structure will be as follows.

```
REPO_ROOT
  |-> compiler (Source for uRAI compiler)
    |-> llvm  (Src for llvm, this is symlinked in to llvm-release_70 below)
    |-> ci_scripts (ci_scripts)
    |-> urai-rt (Runtime src for this project)
    |-> tools  (tools frequently used with this project)
  |-> llvm (created by init script)
    |->llvm-release_70
    |->clang-release_70
    |->urai-rt-lib (where the urai-rt lib gets built to)
    |->build  (Cmake Build dir for llvm)
    |->bins (LLVM build outputs)
  |-> gcc (created by init script)
    |->gcc-arm-none-eabi-6-...  (GCC Source dir)
    |->bins (location of arm-none-eabi-gcc tool chain and dirs)
  |->test_apps
```

Now, build the uRAI's runtime library.

```
cd compiler/urai-rt
make all
```

## How to build an application?

All test applications require the STM32469I-EVAL board from STM. Make sure arm-none-eabi-gdb-py is in your path, if not it was build with gcc and can be 
found in <REPO_ROOT>/gcc/bins/bin


### 1. Create Makefile for application

cd to appropriate SW4STM32 directory under STM32Cube_FW_F4_V1.18.0/Projects/STM32469I_EVAL/Applications


```
cd STM32469I_EVAL
python {REPO_ROOT}/compiler/tools/built_tools/CubeMX2Makefile.py . <path to repo root> <Name of the app (e.g., FatFs_RAMDisk) >
```

### 2. Build the application

All apps can be built either in baseline mode or uRAI protection enabled. Note
that if you build something with uRAI's protection the baseline binary will not
work because of MPU faults...etc.

To build a baseline. Open a terminal in the app's <SW4STM32/STM32469I_EVAL> 
directory
```
make -j4 OPT=2 all
```

To build an app with uRAI's protection

```
make -j4 OPT=2 RAI_ENABLED=1 all
```



## License
Our modifications and tools are distributed using license in License.md


### NOTE

This project is a research tool and is not production ready. 

## Questions? Issues? Errors? Help?

Please raise an issue on the repository.