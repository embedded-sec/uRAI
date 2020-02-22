
BUILD_DIR = ../../llvm/urai-rt-lib
LLVM_PATH = ../../llvm/build/bin
INCLUDE_PATH = ../../gcc/bins/arm-none-eabi/include/
CLANG = $(LLVM_PATH)/clang
OPT_LEVEL = -O2


CFLAGS = -flto -fno-exceptions -I$(INCLUDE_PATH) -fshort-enums
CFLAGS += -fno-builtin -ffreestanding -fmessage-length=0 -ffunction-sections -g
CFLAGS += -gdwarf-2 -fdata-sections 


all: syscalls urai

urai: $(BUILD_DIR) $(BUILD_DIR)/urai-rt-v6-m.o \
				$(BUILD_DIR)/urai-rt-v7-m.o \
				$(BUILD_DIR)/urai-rt-v7e-m.o
	@echo Done Building urai-rt


syscalls: $(BUILD_DIR) $(BUILD_DIR)/syscalls-v6-m.o \
					$(BUILD_DIR)/syscalls-v7-m.o \
					$(BUILD_DIR)/syscalls-v7e-m.o
	@echo Done Building Syscalls

$(BUILD_DIR):
	mkdir -p $@

# ===========================Syscalls ==========================================
$(BUILD_DIR)/syscalls-v6-m.o: syscalls-v6-m.bc
	$(LLVM_PATH)/llvm-link $^ -o $(@)

$(BUILD_DIR)/syscalls-v7-m.o: syscalls-v7-m.bc
	$(LLVM_PATH)/llvm-link $^ -o $(@)

$(BUILD_DIR)/syscalls-v7e-m.o: syscalls-v7e-m.bc
	$(LLVM_PATH)/llvm-link $^ -o $(@)
# ======================End  Syscalls ==========================================


# ======================	URAI OBJ Lib   =====================================
$(BUILD_DIR)/urai-rt-v6-m.o: urai-rt-v6-m.bc
	$(LLVM_PATH)/llvm-link $^ -o $(@)

$(BUILD_DIR)/urai-rt-v7-m.o: urai-rt-v7-m.bc
	$(LLVM_PATH)/llvm-link $^ -o $(@)

$(BUILD_DIR)/urai-rt-v7e-m.o: urai-rt-v7e-m.bc
	$(LLVM_PATH)/llvm-link $^ -o $(@)
# ====================== End Hexbox Enforce Lib ================================


# ====================== Compile to BitCode ====================================
%-v6-m.bc: %.c
	@echo "$<"
	$(CLANG) $(OPT_LEVEL)  -c -target arm-none-eabi -mcpu=cortex-m0   \
	$(CFLAGS) $< -o $@

%-v7-m.bc: %.c
	$(CLANG) $(OPT_LEVEL) -c -target arm-none-eabi -mcpu=cortex-m3   \
	$(CFLAGS) $< -o $@

%-v7e-m.bc: %.c
	$(CLANG) $(OPT_LEVEL)  -c -target arm-none-eabi -mcpu=cortex-m4   \
	$(CFLAGS) $< -o $@
# ====================== End Compile to BitCode ================================

clean:
	rm -f *.o
	rm -f *.bc
	rm -f $(BUILD_DIR)/*.o
