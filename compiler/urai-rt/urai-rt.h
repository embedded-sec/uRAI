

#ifndef __URAI_RT__
#define __URAI_RT__


#include <stdint.h>
#include <stddef.h>


__attribute__((used, optnone, naked)) void __urai_svc_handler(void);
__attribute__((used, optnone)) void __urai_debug(void);
__attribute__((used, optnone)) void __urai_error(void);
__attribute__((used, optnone, naked)) void __urai_init(void);
__attribute__((used, optnone, naked)) void __urai_exit_main(void);
__attribute__((used, optnone, naked)) void __urai_save(void);
__attribute__((used, optnone, naked)) void __urai_restore(void);
__attribute__((used, optnone, naked)) void __urai_extlib_save(void);
__attribute__((used, optnone, naked)) void __urai_extlib_restore(void);
__attribute__((used, optnone, naked)) void __urai_elavate_priv(void);
__attribute__((used, optnone, naked)) void __urai_drop_priv(void);
__attribute__((used, optnone)) void __urai_sfi_cntr(void);
__attribute__((used, optnone, naked)) void __urai_rec_save(void);
__attribute__((used, optnone, naked)) void __urai_rec_restore(void);
__attribute__((used, optnone)) void __urai_init_ccmram_globals(void);

#endif // __URAI_RT__