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
       .atcai2c.slave_address = 0x${I2C_ADDR?upper_case},
       .atcai2c.bus           = 0,
       .atcai2c.baud          = ${.vars["${DRV_I2C_PLIB?lower_case}"].I2C_CLOCK_SPEED},
       .wake_delay            = ${WAKEUP_DELAY},
       .rx_retries            = ${RECEIVE_RETRY},
       .cfg_data              = &${DRV_I2C_PLIB?lower_case}_plib_api
};
