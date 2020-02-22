//=================================================================================================
//
// This file is used to customize the configuratoin of the IoT2 runtime metric
// collector library in addition to the IoT2_Config.h file.
//
// Some defenses require customization/annotations/modifications to enable the
// metric collector library. To enable this with out modifying the IoT2Lib files
// we use this file. The default configuration is to compile this as an empty
// file (as done with the baseline for the benchmarks). If a specific 
// configuration is needed you can use or add to the available configurations.
//=================================================================================================

// IoT2 configuration and special interface files
#include "rai_mpu_configs.h"



__attribute__((used)) void __urai_config_mpu(void){

#if defined(RAI_ENABLED)

    MPU_Region_InitTypeDef MPU_InitStruct;
    // diable mpu
    __DMB();
    // disable faults (mem, usage, and bus)
    SCB->SHCSR &= ~(SCB_SHCSR_MEMFAULTENA_Msk| 
                  SCB_SHCSR_USGFAULTENA_Msk| 
                  SCB_SHCSR_BUSFAULTENA_Msk); 

    // disable MPU control register
    MPU->CTRL = 0;

    //--------------------------------------------------------------------------
    // region 0: U-RW, P-RW
    MPU_InitStruct.Enable = MPU_REGION_ENABLE;
    MPU_InitStruct.BaseAddress = 0x00000000;
    MPU_InitStruct.Size = MPU_REGION_SIZE_4GB;
    MPU_InitStruct.AccessPermission = MPU_REGION_FULL_ACCESS;  
    MPU_InitStruct.IsBufferable = MPU_ACCESS_NOT_BUFFERABLE;
    MPU_InitStruct.IsCacheable = MPU_ACCESS_CACHEABLE;
    MPU_InitStruct.IsShareable = MPU_ACCESS_SHAREABLE;
    MPU_InitStruct.Number = MPU_REGION_NUMBER0;
    MPU_InitStruct.TypeExtField = MPU_TEX_LEVEL1;
    MPU_InitStruct.SubRegionDisable = 0x00;
    MPU_InitStruct.DisableExec = MPU_INSTRUCTION_ACCESS_DISABLE;  
    //HAL_MPU_ConfigRegion(&MPU_InitStruct);

      /* Set the Region number */
  MPU->RNR = MPU_InitStruct.Number;

  if ((MPU_InitStruct.Enable) != RESET)
  {
    
    MPU->RBAR = MPU_InitStruct.BaseAddress;
    MPU->RASR = ((uint32_t)MPU_InitStruct.DisableExec             << MPU_RASR_XN_Pos)   |
                ((uint32_t)MPU_InitStruct.AccessPermission        << MPU_RASR_AP_Pos)   |
                ((uint32_t)MPU_InitStruct.TypeExtField            << MPU_RASR_TEX_Pos)  |
                ((uint32_t)MPU_InitStruct.IsShareable             << MPU_RASR_S_Pos)    |
                ((uint32_t)MPU_InitStruct.IsCacheable             << MPU_RASR_C_Pos)    |
                ((uint32_t)MPU_InitStruct.IsBufferable            << MPU_RASR_B_Pos)    |
                ((uint32_t)MPU_InitStruct.SubRegionDisable        << MPU_RASR_SRD_Pos)  |
                ((uint32_t)MPU_InitStruct.Size                    << MPU_RASR_SIZE_Pos) |
                ((uint32_t)MPU_InitStruct.Enable                  << MPU_RASR_ENABLE_Pos);
  }
  else
  {
    MPU->RBAR = 0x00U;
    MPU->RASR = 0x00U;
  }


    
    //--------------------------------------------------------------------------
    // region 7 (FLASH): U-RX, P-RX
    MPU_InitStruct.BaseAddress = (0x08000000);//FLASH_ADDRESS_START;
    MPU_InitStruct.Size = MPU_REGION_SIZE_256MB;
    MPU_InitStruct.IsShareable = MPU_ACCESS_NOT_SHAREABLE;
    MPU_InitStruct.AccessPermission = MPU_REGION_PRIV_RO_URO ;
    MPU_InitStruct.Number = MPU_REGION_NUMBER7;//FLASH_REGION_NUMBER;
    MPU_InitStruct.DisableExec = MPU_INSTRUCTION_ACCESS_ENABLE;
    //HAL_MPU_ConfigRegion(&MPU_InitStruct);

          /* Set the Region number */
  MPU->RNR = MPU_InitStruct.Number;

  if ((MPU_InitStruct.Enable) != RESET)
  {
    
    MPU->RBAR = MPU_InitStruct.BaseAddress;
    MPU->RASR = ((uint32_t)MPU_InitStruct.DisableExec             << MPU_RASR_XN_Pos)   |
                ((uint32_t)MPU_InitStruct.AccessPermission        << MPU_RASR_AP_Pos)   |
                ((uint32_t)MPU_InitStruct.TypeExtField            << MPU_RASR_TEX_Pos)  |
                ((uint32_t)MPU_InitStruct.IsShareable             << MPU_RASR_S_Pos)    |
                ((uint32_t)MPU_InitStruct.IsCacheable             << MPU_RASR_C_Pos)    |
                ((uint32_t)MPU_InitStruct.IsBufferable            << MPU_RASR_B_Pos)    |
                ((uint32_t)MPU_InitStruct.SubRegionDisable        << MPU_RASR_SRD_Pos)  |
                ((uint32_t)MPU_InitStruct.Size                    << MPU_RASR_SIZE_Pos) |
                ((uint32_t)MPU_InitStruct.Enable                  << MPU_RASR_ENABLE_Pos);
  }
  else
  {
    MPU->RBAR = 0x00U;
    MPU->RASR = 0x00U;
  }


    //--------------------------------------------------------------------------
    // region 6 (CCRAM): U---, P:RW
    MPU_InitStruct.Enable = MPU_REGION_ENABLE;
    MPU_InitStruct.BaseAddress = (0x10000000);//CCRAM_ADDRESS_START;
    MPU_InitStruct.Size = MPU_REGION_SIZE_64KB;
    MPU_InitStruct.AccessPermission = MPU_REGION_PRIV_RW ;
    MPU_InitStruct.IsBufferable = MPU_ACCESS_NOT_BUFFERABLE;
    MPU_InitStruct.IsCacheable = MPU_ACCESS_NOT_CACHEABLE;
    MPU_InitStruct.IsShareable = MPU_ACCESS_NOT_SHAREABLE;
    MPU_InitStruct.Number = MPU_REGION_NUMBER6;//RAM_REGION_NUMBER;
    MPU_InitStruct.TypeExtField = MPU_TEX_LEVEL0;
    MPU_InitStruct.SubRegionDisable = 0x00;
    MPU_InitStruct.DisableExec = MPU_INSTRUCTION_ACCESS_DISABLE;
    //HAL_MPU_ConfigRegion(&MPU_InitStruct);
          /* Set the Region number */
  MPU->RNR = MPU_InitStruct.Number;

  if ((MPU_InitStruct.Enable) != RESET)
  {
    
    MPU->RBAR = MPU_InitStruct.BaseAddress;
    MPU->RASR = ((uint32_t)MPU_InitStruct.DisableExec             << MPU_RASR_XN_Pos)   |
                ((uint32_t)MPU_InitStruct.AccessPermission        << MPU_RASR_AP_Pos)   |
                ((uint32_t)MPU_InitStruct.TypeExtField            << MPU_RASR_TEX_Pos)  |
                ((uint32_t)MPU_InitStruct.IsShareable             << MPU_RASR_S_Pos)    |
                ((uint32_t)MPU_InitStruct.IsCacheable             << MPU_RASR_C_Pos)    |
                ((uint32_t)MPU_InitStruct.IsBufferable            << MPU_RASR_B_Pos)    |
                ((uint32_t)MPU_InitStruct.SubRegionDisable        << MPU_RASR_SRD_Pos)  |
                ((uint32_t)MPU_InitStruct.Size                    << MPU_RASR_SIZE_Pos) |
                ((uint32_t)MPU_InitStruct.Enable                  << MPU_RASR_ENABLE_Pos);
  }
  else
  {
    MPU->RBAR = 0x00U;
    MPU->RASR = 0x00U;
  }


    //--------------------------------------------------------------------------

/*


    MPU_InitStruct.Enable = MPU_REGION_ENABLE;
    MPU_InitStruct.BaseAddress = (0x20000000UL);//RAM_ADDRESS_START;
    MPU_InitStruct.Size = MPU_REGION_SIZE_512KB;
    MPU_InitStruct.AccessPermission = MPU_REGION_FULL_ACCESS ;
    MPU_InitStruct.IsBufferable = MPU_ACCESS_NOT_BUFFERABLE;
    MPU_InitStruct.IsCacheable = MPU_ACCESS_CACHEABLE;
    MPU_InitStruct.IsShareable = MPU_ACCESS_SHAREABLE;
    MPU_InitStruct.Number = MPU_REGION_NUMBER1;//RAM_REGION_NUMBER;
    MPU_InitStruct.TypeExtField = MPU_TEX_LEVEL0;
    MPU_InitStruct.SubRegionDisable = 0x00;
    MPU_InitStruct.DisableExec = MPU_INSTRUCTION_ACCESS_DISABLE;
  
    HAL_MPU_ConfigRegion(&MPU_InitStruct);


    // Peripherals
    MPU_InitStruct.BaseAddress = (0x40000000);//PERIPH_ADDRESS_START;
    MPU_InitStruct.Size = MPU_REGION_SIZE_512KB;//PERIPH_SIZE;
    MPU_InitStruct.IsShareable = MPU_ACCESS_NOT_SHAREABLE;
    MPU_InitStruct.AccessPermission = MPU_REGION_FULL_ACCESS;
    MPU_InitStruct.Number = MPU_REGION_NUMBER3;
    MPU_InitStruct.DisableExec = MPU_INSTRUCTION_ACCESS_DISABLE;
  
    HAL_MPU_ConfigRegion(&MPU_InitStruct);

*/

    // enable the MPU
    MPU->CTRL |= MPU_CTRL_ENABLE_Msk | MPU_CTRL_HFNMIENA_Msk;
    SCB->SHCSR |= SCB_SHCSR_MEMFAULTENA_Msk| 
                  SCB_SHCSR_USGFAULTENA_Msk| 
                  SCB_SHCSR_BUSFAULTENA_Msk;
    __DSB();
    __ISB();

    // drop privileges
    __set_CONTROL(0x01);
 
 #endif // RAI_ENABLED   
    // return to __urai_init
    __asm("b RAI_MPU_CONFIG\n");

}


