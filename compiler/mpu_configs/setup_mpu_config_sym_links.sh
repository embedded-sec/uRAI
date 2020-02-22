#!/bin/bash

################################################################################
#
# This file is used to setup symbolic links for IoT2 files that are used inside
# mbed. Mainly to initialize IoT2 correctly and automate the configuration
# of runtime measurements.
#
################################################################################


################################## VARIABLS ##################################

CURR_DIR=`dirname \`readlink -f $0\``

CoreMark=${CURR_DIR}/../../test_apps/STM32Cube_FW_F4_V1.18.0/Projects/STM32469I_EVAL/Applications/rai_examples/coremark_port
PinLock=${CURR_DIR}/../../test_apps/STM32Cube_FW_F4_V1.18.0/Projects/STM32469I_EVAL/Applications/rai_examples/PinLock
FatFs=${CURR_DIR}/../../test_apps/STM32Cube_FW_F4_V1.18.0/Projects/STM32469I_EVAL/Applications/FatFs/FatFs_uSD
LCD_Display=${CURR_DIR}/../../test_apps/STM32Cube_FW_F4_V1.18.0/Projects/STM32469I_EVAL/Applications/Display/LCD_PicturesFromSDCard
LCD_Animation=${CURR_DIR}/../../test_apps/STM32Cube_FW_F4_V1.18.0/Projects/STM32469I_EVAL/Applications/Display/LCD_AnimatedPictureFromSDCard
FatFs_RAMDisk=${CURR_DIR}/../../test_apps/STM32Cube_FW_F4_V1.18.0/Projects/STM32469I_EVAL/Applications/FatFs/FatFs_RAMDisk



Src_Dir=Src
Inc_Dir=Inc

SYM_LINK='ln -sfn'

##################################  SETUP   ##################################


# Create symlinks

# symlinks for CoreMark
if ${SYM_LINK} ${CURR_DIR}/rai_mpu_configs.h ${CoreMark}/${Inc_Dir}/rai_mpu_configs.h

then
    echo "[+] Added symlink for rai_mpu_configs.h at: CoreMark"
else
    echo "[-] ERROR: Failed to add symlink for rai_mpu_configs.h at: CoreMark"
fi

# src
if ${SYM_LINK} ${CURR_DIR}/rai_mpu_configs.c ${CoreMark}/${Src_Dir}/rai_mpu_configs.c

then
    echo "[+] Added symlink for rai_mpu_configs.c at: CoreMark"
else
    echo "[-] ERROR: Failed to add symlink for rai_mpu_configs.c at: CoreMark"
fi


# symlinks for PinLock
if ${SYM_LINK} ${CURR_DIR}/rai_mpu_configs.h ${PinLock}/${Inc_Dir}/rai_mpu_configs.h

then
    echo "[+] Added symlink for rai_mpu_configs.h at: PinLock"
else
    echo "[-] ERROR: Failed to add symlink for rai_mpu_configs.h at: PinLock"
fi

# src
if ${SYM_LINK} ${CURR_DIR}/rai_mpu_configs.c ${PinLock}/${Src_Dir}/rai_mpu_configs.c

then
    echo "[+] Added symlink for rai_mpu_configs.c at: PinLock"
else
    echo "[-] ERROR: Failed to add symlink for rai_mpu_configs.c at: PinLock"
fi


# symlinks for FatFs
if ${SYM_LINK} ${CURR_DIR}/rai_mpu_configs.h ${FatFs}/${Inc_Dir}/rai_mpu_configs.h

then
    echo "[+] Added symlink for rai_mpu_configs.h at: FatFs"
else
    echo "[-] ERROR: Failed to add symlink for rai_mpu_configs.h at: FatFs"
fi

# src
if ${SYM_LINK} ${CURR_DIR}/rai_mpu_configs.c ${FatFs}/${Src_Dir}/rai_mpu_configs.c

then
    echo "[+] Added symlink for rai_mpu_configs.c at: FatFs"
else
    echo "[-] ERROR: Failed to add symlink for rai_mpu_configs.c at: FatFs"
fi


# symlinks for LCD_Display
if ${SYM_LINK} ${CURR_DIR}/rai_mpu_configs.h ${LCD_Display}/${Inc_Dir}/rai_mpu_configs.h

then
    echo "[+] Added symlink for rai_mpu_configs.h at: LCD_Display"
else
    echo "[-] ERROR: Failed to add symlink for rai_mpu_configs.h at: LCD_Display"
fi

# src
if ${SYM_LINK} ${CURR_DIR}/rai_mpu_configs.c ${LCD_Display}/${Src_Dir}/rai_mpu_configs.c

then
    echo "[+] Added symlink for rai_mpu_configs.c at: LCD_Display"
else
    echo "[-] ERROR: Failed to add symlink for rai_mpu_configs.c at: LCD_Display"
fi


# symlinks for LCD_Animated
if ${SYM_LINK} ${CURR_DIR}/rai_mpu_configs.h ${LCD_Animation}/${Inc_Dir}/rai_mpu_configs.h

then
    echo "[+] Added symlink for rai_mpu_configs.h at: LCD_Animation"
else
    echo "[-] ERROR: Failed to add symlink for rai_mpu_configs.h at: LCD_Animation"
fi

# src
if ${SYM_LINK} ${CURR_DIR}/rai_mpu_configs.c ${LCD_Animation}/${Src_Dir}/rai_mpu_configs.c

then
    echo "[+] Added symlink for rai_mpu_configs.c at: LCD_Animation"
else
    echo "[-] ERROR: Failed to add symlink for rai_mpu_configs.c at: LCD_Animation"
fi


# symlinks for FatFs
if ${SYM_LINK} ${CURR_DIR}/rai_mpu_configs.h ${FatFs_RAMDisk}/${Inc_Dir}/rai_mpu_configs.h

then
    echo "[+] Added symlink for rai_mpu_configs.h at: FatFs_RAMDisk"
else
    echo "[-] ERROR: Failed to add symlink for rai_mpu_configs.h at: FatFs_RAMDisk"
fi

# src
if ${SYM_LINK} ${CURR_DIR}/rai_mpu_configs.c ${FatFs_RAMDisk}/${Src_Dir}/rai_mpu_configs.c

then
    echo "[+] Added symlink for rai_mpu_configs.c at: FatFs_RAMDisk"
else
    echo "[-] ERROR: Failed to add symlink for rai_mpu_configs.c at: FatFs_RAMDisk"
fi
