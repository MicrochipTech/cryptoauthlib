/*
 * Code generated from MPLAB Harmony.
 *
 * This file will be overwritten when reconfiguring your MPLAB Harmony project.
 * Please copy examples or other code you want to keep to a separate file or main.c
 * to avoid loosing it when reconfiguring.
 */

#include "cryptoauthlib.h"

ATCAIfaceCfg ${NAME?lower_case}_${INDEX?string}_init_data = {
    .iface_type            = ${INTERFACE},
    .devtype               = ${NAME?upper_case},
<#if INTERFACE == "ATCA_I2C_IFACE">
<#assign plib_type = "i2c">
    .atcai2c.slave_address = 0x${I2C_ADDR?upper_case},
    .atcai2c.bus           = 0,
    .atcai2c.baud          = ${.vars["${HAL_INTERFACE?lower_case}"].I2C_CLOCK_SPEED}000,
<#elseif INTERFACE == "ATCA_SPI_IFACE">
<#assign plib_type = "spi">
    .atcaspi.bus           = 0,
    .atcaspi.select_pin    = PORT_PIN_${SPI_CS_PIN?upper_case},
    .atcaspi.baud          = ${.vars["${HAL_INTERFACE?lower_case}"].SPI_BAUD_RATE},
</#if>
    .wake_delay            = ${WAKEUP_DELAY},
    .rx_retries            = ${RECEIVE_RETRY},
    .cfg_data              = &${HAL_INTERFACE?lower_case}_plib_${plib_type}_api
};
