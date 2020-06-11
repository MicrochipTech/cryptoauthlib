HAL Directory - Purpose
===========================
This directory contains all the Hardware Abstraction Layer (HAL) files used to
adapt the upper levels of atca-ng and abstractions to physical hardware.

HAL contains physical implementations for I2C, SWI, SPI, UART and timers for
specific hardware platforms.

**Include just those HAL files you require based on platform type.**

CryptoAuthLib Supported HAL Layers
=============================================

HAL Layers files are combined into groups. Initial group is generic files that are typically included in a project.
Files are then broken out by uController Family and or Operating System Interface.


| Protocol Files | Interface  | Files                        | API         | Notes                              |
|----------------|------------|------------------------------|-------------|------------------------------------|
|atca            |            | atca_hal.c/h                 |             | For all projects                   |
|kit protocol    |            | kit_protocol.c/h             |             | For all Kit Protocol projects      |
|                |            | kit_phy.h                    |             |                                    |


Microchip Harmony 3 for all PIC32 & ARM products - Use the Harmony 3 Configurator to generate and configure prjects
--------------------------------------------
Obtain library and configure using [Harmony 3](https://github.com/Microchip-MPLAB-Harmony/Microchip-MPLAB-Harmony.github.io/wiki)

| Interface  | Files                        | API         | Notes                                           |
|------------|------------------------------|-------------|-------------------------------------------------|
|   I2C      | hal_i2c_harmony.c            | plib.h      |  For all Harmony 3 based projects               |
|   SPI      | hal_spi_harmony.c            | plib.h      |                                                 |

Microchip 8 & 16 bit products - AVR, PIC16/18, PIC24/DSPIC
--------------------------------------------
Obtain library and integration through [Microchip Code Configurator](https://www.microchip.com/mplab/mplab-code-configurator)


OS & RTOS integrations
--------------------------------------------
Use [CMake](https://cmake.org/download/) to configure the library in Linux, Windows, and MacOS environments

| OS             | Interface  | Files                            | API         | Notes                              |
|----------------|------------|----------------------------------|-------------|------------------------------------|
| Linux          |    I2C     | hal_linux_i2c_userspace.c/h      | i2c-dev     |                                    |
| Linux          |    SPI     | hal_linux_spi_userspace.c/h      | spidev      |                                    |
| Linux/Mac      |            | hal_linux.c                      |             | For all Linux/Mac projects         |
| Windows        |            | hal_windows.c                    |             | For all Windows projects
| All            |  kit-hid   | hal_all_platforms_kit_hidapi.c/h | hidapi      | Works for Windows, Linux, and Mac  |
| freeRTOS       |            | hal_freertos.c                   |             | freeRTOS common routines           |


Legacy Support - [Atmel START](https://www.microchip.com/start) for AVR, ARM based processesors (SAM)
---------------------------------------------

| Interface  | Files                        | API         | Notes                              |
|------------|------------------------------|-------------|------------------------------------|
|            | hal_timer_start.c            | START       | Timer implementation               |
|   I2C      | hal_i2c_start.c/h            | START       |                                    |
|   SWI      | swi_uart_start.c/h           | START       | SWI using UART                     |


Legacy Support - ASF3 for ARM Cortex-m0 & Cortex-m based processors (SAM)
---------------------------------------------

|SAM Micros      | Interface  | Files                        | API         | Notes                              |
|----------------|------------|------------------------------|-------------|------------------------------------|
| cortex-m0      |   I2C      | hal_sam0_i2c_asf.c/h         | ASF3        | SAMD21, SAMB11, etc                |
| cortex-m3/4/7  |   I2C      | hal_sam_i2c_asf.c/h          | ASF3        | SAM4S, SAMG55, SAMV71, etc         |
| all            |            | hal_sam_timer_asf.c          | ASF3        | Common timer hal for all platforms |



