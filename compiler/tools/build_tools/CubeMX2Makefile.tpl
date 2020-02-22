######################################
# Makefile by CubeMX2Makefile.py
######################################

######################################
# target
######################################

TARGET=$TARGET

######################################
# building variables
######################################
# debug build?
ifdef OPT_VAL
# optimization
OPT_LEVEL = O$$(OPT_VAL)
OPT = $$(OPT_LEVEL)

else

OPT = O2

endif

#######################################
# pathes
#######################################
# Build path
BUILD_DIR = .build
URAI_DIR =$$(BUILD_DIR)/urai
BIN_DIR = bin
RESULT_BINS_DIR = result_bins

######################################
# source
######################################
$C_SOURCES

C_SOURCES += ../../Src/rai_mpu_configs.c

$ASM_SOURCES

#######################################
# binaries
#######################################
CLANG = $LLVM_PATH/bin/clang
LLVMGOLD = $LLVM_PATH/lib/LLVMgold.so
ARM_NONE_EABI_PATH = $GCC_PATH
CC = $$(CLANG)
AS = $$(CLANG)
LD = $$(ARM_NONE_EABI_PATH)/bin/arm-none-eabi-ld
CP = $$(ARM_NONE_EABI_PATH)/bin/arm-none-eabi-objcopy
AR = $$(ARM_NONE_EABI_PATH)/bin/arm-none-eabi-ar
SZ = $$(ARM_NONE_EABI_PATH)/bin/arm-none-eabi-size
HEX = $$(CP) -O ihex
BIN = $$(CP) -O binary -S

#######################################
# URAI defines
#######################################

URAI_SIZE_FILE = $$(URAI_DIR)/urai-size.json
URAI_ANALYSIS_FILE = $$(CURDIR)/$$(URAI_DIR)/urai-analysis.json
URAI_FLAG_IDS_FILE = $$(CURDIR)/$$(URAI_DIR)/urai-keys-flag-ids.json
#URAI_IR_FILE = $$(BIN_DIR)/$$(TARGET).elf.0.2.internalize.bc
URAI_IR_FILE = $$(BIN_DIR)/$$(TARGET).elf.0.5.precodegen.bc

URAI_RESERVE_LR_OPTION=--plugin-opt=-urai-reserve-lr=reserveLR
URAI_MEASURE_EHSFI_OPTION=--plugin-opt=-urai-ehsfi-measurement=measureEHSFI
URAI_BUILD_DIR_OPTION=--plugin-opt=-urai-build-dir=$$(CURDIR)/$$(URAI_DIR)/
URAI_COLLECTOR_OPTION=--plugin-opt=-urai-collector=$$(CURDIR)/$$(URAI_DIR)/
URAI_INIT_SR_OPTION:=--plugin-opt=-urai-sr-init=$$(URAI_FLAG_IDS_FILE)
URAI_APP_MAIN_OPTION:=--plugin-opt=-urai-main-init=main
URAI_ANALYSIS_OPTION:=--plugin-opt=-urai-analysis=$$(URAI_ANALYSIS_FILE)
URAI_INSTRUMENTATION_OPTION:=--plugin-opt=-urai-instrumentation=$$(URAI_FLAG_IDS_FILE)

# full SFI analysis
URAI_FULL_SFI_BUILD_DIR_OPTION=--plugin-opt=-raisfi-build-dir=$$(CURDIR)/$$(URAI_DIR)/
URAI_FULL_SFI_INSTR_OPTION=--plugin-opt=-raisfi-instrumentation=1

#######################################
# CFLAGS
#######################################
# macros for gcc
$AS_DEFS
$C_DEFS

ifeq ($$(RAI_ENABLED),1)
C_DEFS += -DRAI_ENABLED
endif

# includes for gcc
$AS_INCLUDES
$C_INCLUDES
# compile gcc flags

C_INCLUDES += -I$GCC_PATH/arm-none-eabi/include

ASFLAGS = $MCU $FLOAT_ABI $$(AS_DEFS) $$(AS_INCLUDES) $$(OPT) -Wall -fdata-sections -ffunction-sections -flto
CFLAGS = $MCU -mfloat-abi=$FLOAT_ABI $$(C_DEFS) $$(C_INCLUDES) -$$(OPT) -Wall -fdata-sections -ffunction-sections -target arm-none-eabi -mthumb
CFLAGS += --sysroot=$$(ARM_NONE_EABI_PATH)arm-none-eabi -fno-builtin -fshort-enums -fno-exceptions -flto -ffreestanding -fmessage-length=0 -ffunction-sections
#ifeq ($$(DEBUG), 1)
CFLAGS += -g -gdwarf-2
#endif
# Generate dependency information
#CFLAGS += -std=c99 -MD -MP -MF .dep/$$(@F).d

#######################################
# LDFLAGS
#######################################
# link script
$LDSCRIPT
# libraries
LIBS = -lc -lm
LIBDIR = $LD_STD_LIBS $LD_LIB_DIRS

LDFLAGS=-plugin=$$(LLVMGOLD) --plugin-opt=save-temps -g --plugin-opt=$MCU
LDFLAGS+=--plugin-opt=-float-abi=$FLOAT_ABI --plugin-opt=$$(OPT_LEVEL) --start-group -lc -lm -lgcc --end-group
LDFLAGS+= $$(LIBDIR) $$(LIBS) $LD_LIBS -Map=$$(BUILD_DIR)/$$(TARGET).map --gc-sections

##############################################################################
# default action: build all
# primary TARGETS

all: default urai

baseline: setup $$(BIN_DIR) $$(BIN_DIR)/$$(TARGET).elf cp_baseline

default: setup $$(BIN_DIR) $$(BIN_DIR)/$$(TARGET).elf

urai: setup $$(BIN_DIR) $$(BIN_DIR) $$(BIN_DIR)/$$(TARGET)--FullSFI.elf $$(BIN_DIR)/$$(TARGET)--urai.elf

ehsfi: setup $$(BIN_DIR) $$(BIN_DIR)/$$(TARGET)--ehsfi.elf

setup:
	export C_INCLUDE_PATH=$GCC_PATH/arm-none-eabi/include

FORCE :
#######################################
# build the application
#######################################
# list of ASM program objects
ASM_OBJECTS = $$(addprefix $$(BUILD_DIR)/,$$(notdir $$(ASM_SOURCES:.s=.o)))
vpath %.s $$(sort $$(dir $$(ASM_SOURCES)))

# list of objects
OBJECTS += $$(addprefix $$(BUILD_DIR)/,$$(notdir $$(C_SOURCES:.c=.o)))
vpath %.c $$(sort $$(dir $$(C_SOURCES)))

OBJECTS += $CLANG_SYSCALLS_LIB
###############################################
# Setup URAI applciations

URAI_ASM_OBJECTS = $$(addprefix $$(URAI_DIR)/,$$(notdir $$(ASM_SOURCES:.s=.o)))
vpath %.s $$(sort $$(dir $$(ASM_SOURCES)))

# list of objects
URAI_OBJECTS += $$(addprefix $$(URAI_DIR)/,$$(notdir $$(C_SOURCES:.c=.o)))
vpath %.c $$(sort $$(dir $$(C_SOURCES)))

URAI_OBJECTS += $CLANG_SYSCALLS_LIB


$$(BUILD_DIR)/%.o: %.c Makefile | $$(BUILD_DIR)
	$$(CC) -c $$(CFLAGS) $$< -o $$@

$$(BUILD_DIR)/%.o: %.s Makefile | $$(BUILD_DIR)
	$$(AS) -c $$(CFLAGS) $$< -o $$@

$$(BIN_DIR)/$$(TARGET).elf: $$(ASM_OBJECTS) $$(OBJECTS) Makefile
	$$(LD) $$(ASM_OBJECTS) $$(OBJECTS)	$$(LDFLAGS) -T$$(LDSCRIPT) \
	--plugin-opt=-info-output-file=$$@.stats -o $$@ -g
	$$(SZ) $$@



cp_baseline:
	mkdir -p $$(RESULT_BINS_DIR)
	cp $$(BIN_DIR)/$$(TARGET).elf $$(RESULT_BINS_DIR)/$$(TARGET)--baseline.elf


# This rule is to build a binary enforcing Full SFI (i.e., entire application)
$$(BIN_DIR)/$$(TARGET)--FullSFI.elf: $$(URAI_IR_FILE) Makefile | $$(URAI_DIR)
	$$(LD) $$(ASM_OBJECTS) $$(URAI_IR_FILE) \
	$$(LDFLAGS) --plugin-opt=-info-output-file=$$@.stats -T$$(LDSCRIPT) \
     $$(URAI_FULL_SFI_INSTR_OPTION) $$(URAI_FULL_SFI_BUILD_DIR_OPTION) -o $$@

$$(BUILD_DIR):
	mkdir -p $$@

$$(URAI_DIR)/%.o: %.c Makefile | $$(URAI_DIR)
	$$(CC) -c $$(CFLAGS) $$< -o $$@

$$(URAI_DIR)/%.o: %.s Makefile | $$(URAI_DIR)
	$$(AS) -c $$(CFLAGS) $$< -o $$@

# Build default saving intermediates
$$(URAI_IR_FILE): $$(BIN_DIR)/$$(TARGET).elf

# Run Analysis on IR
$$(URAI_ANALYSIS_FILE): $$(URAI_IR_FILE) Makefile | $$(URAI_DIR)
	$$(LD) $$(ASM_OBJECTS) $$(URAI_IR_FILE) $$(LDFLAGS) -T$$(LDSCRIPT) \
	--plugin-opt=-info-output-file=$$@.stats -o $$@ -g \
	$$(URAI_RESERVE_LR_OPTION) $$(URAI_ANALYSIS_OPTION) \
	-o $$(BIN_DIR)/$$(TARGET)--analysis.elf


# Generate keys/flag IDs for the functions
$$(URAI_FLAG_IDS_FILE): $$(URAI_ANALYSIS_FILE) Makefile | $$(URAI_DIR)
	python $URAI_KEY_FLAG_IDS_TOOL -f $$(URAI_ANALYSIS_FILE) -a $$(TARGET) -opt $$(OPT_VAL) -nodebug



# Generate a dummy binary to collect the used labels
$$(BIN_DIR)/$$(TARGET)--labels.elf: $$(URAI_IR_FILE) $$(URAI_FLAG_IDS_FILE) Makefile | $$(URAI_DIR)
	$$(LD) $$(ASM_OBJECTS) $$(URAI_IR_FILE) $URAI_RT_LIB \
	$$(LDFLAGS) --plugin-opt=-info-output-file=$$@.stats -T$$(LDSCRIPT) \
     $$(URAI_RESERVE_LR_OPTION) $$(URAI_ANALYSIS_OPTION) $$(URAI_INIT_SR_OPTION) $$(URAI_COLLECTOR_OPTION) -o $$@


# Generate Final Partitioned Binary
$$(BIN_DIR)/$$(TARGET)--ehsfi.elf: $$(BIN_DIR)/$$(TARGET)--labels.elf Makefile | $$(URAI_DIR)
	$$(LD) $$(ASM_OBJECTS) $$(URAI_IR_FILE) $URAI_RT_LIB \
	$$(LDFLAGS) --plugin-opt=-info-output-file=$$@.stats -T$$(LDSCRIPT) \
     $$(URAI_RESERVE_LR_OPTION) $$(URAI_ANALYSIS_OPTION) $$(URAI_INIT_SR_OPTION) \
      $$(URAI_APP_MAIN_OPTION) $$(URAI_BUILD_DIR_OPTION) \
       $$(URAI_INSTRUMENTATION_OPTION) $$(URAI_MEASURE_EHSFI_OPTION) -o $$@

# Generate Final Partitioned Binary
$$(BIN_DIR)/$$(TARGET)--urai.elf: $$(BIN_DIR)/$$(TARGET)--labels.elf Makefile | $$(URAI_DIR)
	$$(LD) $$(ASM_OBJECTS) $$(URAI_IR_FILE) $URAI_RT_LIB \
	$$(LDFLAGS) --plugin-opt=-info-output-file=$$@.stats -T$$(LDSCRIPT) \
     $$(URAI_RESERVE_LR_OPTION) $$(URAI_ANALYSIS_OPTION) $$(URAI_INIT_SR_OPTION) \
      $$(URAI_APP_MAIN_OPTION) $$(URAI_BUILD_DIR_OPTION) \
       $$(URAI_INSTRUMENTATION_OPTION) -o $$@
	

$$(URAI_DIR):
	mkdir -p $$@

$$(BIN_DIR):
	mkdir -p $$@


#######################################
# clean up
#######################################
clean:
	-rm -fR .dep $$(BUILD_DIR) $$(BIN_DIR)
	-rm -f *.dot
	-rm -f run.tmp

#######################################
# dependencies
#######################################
-include $$(shell mkdir .dep 2>/dev/null) $$(wildcard .dep/*)

.PHONY: clean all

# *** EOF ***