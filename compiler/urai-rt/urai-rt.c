
#include "urai-rt.h"


extern const uint32_t initial_rai_sr;
uint32_t rai_extlib_var = 0;
__attribute__((used)) uint32_t rai_prv_str_cntr = 0;
int cntr = 0;

__attribute__((used)) const uint32_t svc_init_main = 101;
__attribute__((used)) const uint32_t svc_exit_main = 102;
__attribute__((used)) const uint32_t svc_lib_save = 103;
__attribute__((used)) const uint32_t svc_lib_restore = 104;
__attribute__((used)) const uint32_t svc_app_save = 105;
__attribute__((used)) const uint32_t svc_app_restore = 106;
__attribute__((used)) const uint32_t svc_elavate_priv = 107;
__attribute__((used)) const uint32_t svc_drop_priv = 108;
__attribute__((used)) const uint32_t svc_sfi_cntr = 109;
__attribute__((used)) const uint32_t svc_rec_save = 110;
__attribute__((used)) const uint32_t svc_rec_restore = 111;

__attribute__((used, section(".ccmram"))) uint32_t saved_sr = 0;
__attribute__((used, section(".ccmram"))) uint32_t saved_sr_lib = 0;
__attribute__((used, section(".ccmram"))) uint32_t saved_sr_isr = 0;
__attribute__((used, section(".ccmram"))) uint32_t saved_pc_isr = 0;
__attribute__((used, section(".ccmram"))) uint32_t saved_lr_isr = 0;
__attribute__((used, section(".ccmram"))) uint32_t saved_lr_main = 0;
__attribute__((used, section(".ccmram"))) uint32_t saved_sr_app = 0;


// recursion globals
const uint32_t max_rec_depth = 32;
const uint32_t max_rec_idx = 4 * (max_rec_depth - 2);
const uint32_t max_rec_canary =  0xBADC0FFE;

__attribute__((used, section(".ccmram"))) uint32_t saved_rec_idx = 0;
__attribute__((used, section(".ccmram"))) 
  uint32_t saved_lr_rec_arr[max_rec_depth] = {
    max_rec_canary,           // initialized to canary value
    [1 ... max_rec_depth-2] = 0,  // initialize all elements to 0
    max_rec_canary};          // last element also initialized to canary value


// external function to configure MPU for the used board
extern void config_mpu(void);

//===------------------------------MainCode--------------------------------===//

__attribute__((naked)) void SVC_Handler(void){

  __asm volatile(
    "b __urai_svc_handler\n"     // jump to urai handler
    );


}



__attribute__((used, optnone, naked)) void __urai_svc_handler(void){

  // first get the svc number
  __asm volatile(
    "ldr r0, [sp, #24]\n"         // r0 = pc
    "ldrb r0, [r0, #-2]\n"        // r0 = svc number
    "teq r0, %[lib_save]\n"       // if svc_num == svc_lib_save
    "beq __urai_extlib_save\n"
    "teq r0, %[lib_restore]\n"    // if svc_num == svc_lib_restore
    "beq __urai_extlib_restore\n"
    "teq r0, %[app_save]\n"       // if svc_num == svc_app_save
    "beq __urai_save\n"
    "teq r0, %[app_restore]\n"    // if svc_num == svc_app_restore
    "beq __urai_restore\n"
    "teq r0, %[evalate_priv]\n"    // if svc_num == svc_elavate_priv
    "beq __urai_elavate_priv\n"
    "teq r0, %[drop_priv]\n"      // if svc_num == svc_drop_priv
    "beq __urai_drop_priv\n"
    "teq r0, %[str_prv_cntr]\n"   // if svc_num == svc_sfi_cntr
    "beq __urai_sfi_cntr\n"
    "teq r0, %[rec_save]\n"       // if svc_num == svc_sfi_cntr
    "beq __urai_rec_save\n"
    "teq r0, %[rec_restore]\n"    // if svc_num == svc_sfi_cntr
    "beq __urai_rec_restore\n"
    "teq r0, %[exit_main]\n"      // if svc_num == svc_exit_main
    "beq __urai_exit_main\n"
    "b __urai_error\n"            // in case none worked, go to error
    :: [lib_save] "I" (svc_lib_save),
       [lib_restore] "I" (svc_lib_restore),
       [app_save] "I" (svc_app_save),
       [app_restore] "I" (svc_app_restore),
       [evalate_priv] "I" (svc_elavate_priv),
       [drop_priv] "I" (svc_drop_priv),
       [str_prv_cntr] "I" (svc_sfi_cntr),
       [rec_save] "I" (svc_rec_save),
       [rec_restore] "I" (svc_rec_restore),
       [exit_main] "I" (svc_exit_main)
    );



}


__attribute__((used, optnone)) void __urai_debug(void)
{
  
  __asm(
    "b __tcfi_handler\n"
    "bkpt\n"
    );
}


__attribute__((used, optnone)) void __urai_error(void)
{
  cntr += initial_rai_sr; // dummy line to keep llvm from removing initial SR
  cntr += rai_extlib_var; // dummy to keep llvm from removing rai_extlib_var
  __asm("bkpt\n");
}


__attribute__((used, optnone, naked)) void __urai_init(void){
  
  __asm volatile(
    "mov r0,lr\n"                     // r0 = lr
    "ldr r2,=saved_lr_main\n"         // r2 -> saved_lr_main
    "str r0,[r2]\n"                   // saved_lr_main = lr
    "bl __urai_init_ccmram_globals\n" // helper function to initialize globals
    "ldr r1,=initial_rai_sr\n"        // r1 -> initial_sr_value
    "ldr lr,[r1]\n"                   // lr = initial_sr_value
    "b __urai_config_mpu\n"
    "RAI_MPU_CONFIG:\n"
    "b RAI_INIT\n");              // this label is added right after 
                                  // the call to __urai_init
}


__attribute__((used, optnone, naked)) void __urai_exit_main(void){
  
  __asm volatile(
    "ldr lr,=saved_lr_main\n"     // lr -> saved_lr_main
    "ldr lr,[r1]\n"               // lr = saved_lr_main
    "bx lr\n");                   // exit main
}



/*
Stack:
|  xPSR  |    sp + 0x1c
----------
|   pc   |    sp + 0x18
----------
|   lr   |    sp + 0x14
----------
|   r12  |    sp + 0x10
----------
|   r3   |    sp + 0x0c
----------
|   r2   |    sp + 0x08
----------
|   r1   |    sp + 0x04
----------
|   r0   |   <----- Top of stack (SP)

*/


__attribute__((used, optnone, naked)) void __urai_save(void){
      __asm volatile(
      "ldr r0,=saved_sr_app\n"        // r0 -> saved_sr_app
      "ldr r1, [sp,#20]\n"            // r1 = lr from the stack
      "str r1, [r0]\n"                // saved_sr_app = lr on the stack
      "ldr r0,=initial_rai_sr\n"    // r0 -> initial_sr_value
      "ldr r0, [r0]\n"                // r0 = initial_sr_value
      "str r0, [sp, #20]\n"           // lr on stack = initial_sr_value
      "bx lr\n"                       // exit the syscall
        );
}


__attribute__((used, optnone, naked)) void __urai_restore(void){
      __asm volatile(
      "ldr r0,=saved_sr_app\n"        // r0 -> saved_sr_app
      "ldr r0, [r0]\n"                // r0 = saved_sr_app
      "str r0, [sp,#20]\n"            // lr on the stack = saved_sr_app
      "bx lr\n"                       // exit the syscall
        );
}


__attribute__((used, optnone, naked)) void __urai_extlib_save(void){
      __asm volatile(
      "ldr r1,=saved_sr_lib\n"        // r1 -> saved_sr_lib
      "ldr r0, [sp,#20]\n"            // r0 = lr from the stack
      "str r0, [r1]\n"                // saved_sr_lib = lr on the stack
      // change lr on the stack to point to the inlined svc_extlib_restore.
      // This is important especially in the case of a tail call, in order
      // to return correctly from the extlib call and the branch the original
      // function TLR.
      "ldr r0, [sp, #24]\n"           // r0 = pc from the stack
      "add r0, r0, #5\n"              // r0 = pc + 5 --> points to 
                                      // svc_extlib_restore, 4 + 1 for the last
                                      // bit must be set
      "str r0, [sp, #20]\n"           // store the corrected lr on the stack
      "bx lr\n"                       // exit the syscall
        );

}

__attribute__((used, optnone, naked)) void __urai_extlib_restore(void){
      __asm volatile(
      "ldr r1,=saved_sr_lib\n"        // r1 -> saved_sr_lib
      "ldr r1, [r1]\n"                // r1 = saved_sr_lib
      "str r1, [sp,#20]\n"            // lr on the stack = saved_sr_lib
      "bx lr\n"                       // exit the syscall
        );

}


__attribute__((used, optnone, naked)) void __urai_elavate_priv(void){
  __asm volatile (
    "mov r0, #0\n"
    "msr control, r0\n"  // elavate privileges
    "bx lr\n"            // return directly
    );
}

__attribute__((used, optnone, naked)) void __urai_drop_priv(void){
    __asm volatile (
    "mov r0, #1\n"
    "msr control, r0\n" // drop privileges
    "bx lr\n"           // return directly
    );
}


__attribute__((used, optnone)) void __urai_sfi_cntr(void)
{

  rai_prv_str_cntr++;
  __asm("bx lr\n");
}



__attribute__((used, optnone, naked)) void __urai_rec_save(void){
  __asm (
    "ldr r0,=saved_lr_rec_arr\n" // r0 -> saved_lr_rec_arr
    "ldr r1,=saved_rec_idx\n"    // r1 -> saved_rec_idx
    "ldr r1, [r1]\n"             // r1 = saved_rec_idx
    "cmp r1, %[max_idx]\n"       // r1 == max_rec_idx ?
    "beq __urai_debug\n"         // if so, throw an error
    "add r1, r1, #4\n"           // increment r1 to the next index
    "ldr r2, [sp,#24]\n"         // r2 = pc from the stack
    "add r2, r2, #4\n"           // increment r2 to point to the ret address
    "str r2, [r0, r1]\n"         // store r2 on recursion stack
    "ldr r0,=saved_rec_idx\n"    // r0 -> saved_rec_idx
    "str r1, [r0]\n"             // updated saved_rec_idx
    "mov r1, #2147483648\n"      // r1 = 0x8000000, to set multi_rec bit
    "ldr r0, [sp,#20]\n"         // r0 = lr from the stack
    "orr r0, r1\n"               // r0 = r0 | r1
    "str r0, [sp,#20]\n"         // set the first bit of lr
    "bx lr\n"                    // exit the syscall
    :: [max_idx] "I" (max_rec_idx)
  );
}


__attribute__((used, optnone, naked)) void __urai_rec_restore(void){
  __asm (
    "ldr r0,=saved_lr_rec_arr\n" // r0 -> saved_lr_rec_arr
    "ldr r1,=saved_rec_idx\n"    // r1 -> saved_rec_idx
    "ldr r1, [r1]\n"             // r1 = saved_rec_idx
    "cmp r1, #0\n"               // r1 == max_rec_idx ?
    "blt __urai_debug\n"         // if so, throw an error
    "ldr r2, [r0, r1]\n"         // get the return addr from the recursion stack
    "str r2, [sp,#24]\n"         // pc on the stack = r2
    "sub r1, r1, #4\n"           // decrement r1 to the previous index
    "ldr r0,=saved_rec_idx\n"    // r0 -> saved_rec_idx
    "str r1, [r0]\n"             // updated saved_rec_idx
    "cbnz r1, __urai_exit_rec_restore\n"
    "ldr r0, [sp,#20]\n"         // r0 = lr from the stack
    "bfc r0, #31, #1\n"          // clear the high order bit
    "str r0, [sp,#20]\n"         // store the result to lr on the exc* stack
    "__urai_exit_rec_restore:\n"
    "bx lr\n"                    // exit the syscall
  );
}


/// a simplified way to ensure initializing globals placed in ccmram
__attribute__((used, optnone)) void __urai_init_ccmram_globals(void){
  saved_sr = 0;
  saved_sr_lib = 0;
  saved_sr_isr = 0;
  saved_pc_isr = 0;
  saved_lr_isr = 0;
  saved_lr_main = 0;
  saved_sr_app = 0;

  saved_rec_idx = 0;
  for (uint32_t i =0; i < max_rec_depth; i++){
    if (i == 0 || i == (max_rec_depth-1)){
      saved_lr_rec_arr[i] = max_rec_canary;
    }
    else{
      saved_lr_rec_arr[i] = 0;
    }
  } 
}
