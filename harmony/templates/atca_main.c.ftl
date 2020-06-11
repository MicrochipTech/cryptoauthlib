/*
 * Code generated from MPLAB Harmony.
 *
 * This file will be overwritten when reconfiguring your MPLAB Harmony project.
 * Please copy examples or other code you want to keep to a separate file or main.c
 * to avoid loosing it when reconfiguring.
 */

#include "cryptoauthlib_main.h"
#include "cryptoauthlib_interface_config.h"
#include "cryptoauthlib.h"

ATCAIfaceCfg CRYPTO_AUTHENTICATION_INTERFACE_0_desc = {        
       .iface_type            = ${.vars["${CAL_LIB_DEVICE?lower_case}"].DEVICE_INTF_USED},
       .devtype               = ${CAL_LIB_DEVICE},
       .atcai2c.slave_address = CONF_CRYPTO_AUTHENTICATION_INTERFACE_0_I2C_ADDRESS,
       .atcai2c.bus           = 0,
       .atcai2c.baud          = CONF_CRYPTO_AUTHENTICATION_INTERFACE_0_I2C_FREQUENCY,
       .wake_delay            = CONF_CRYPTO_AUTHENTICATION_INTERFACE_0_I2C_WAKEUP_DELAY,
       .rx_retries            = CONF_CRYPTO_AUTHENTICATION_INTERFACE_0_I2C_RXRETRY,
       .cfg_data              = NULL
};

void CRYPTO_AUTHENTICATION_INTERFACE_0_init(void)
{
	atcab_init(&CRYPTO_AUTHENTICATION_INTERFACE_0_desc);
}

void CRYPTO_AUTHENTICATION_INTERFACE_0_example(void)
{
	ATCA_STATUS status;
	uint8_t     serialnum[ATCA_SERIAL_NUM_SIZE];
	uint8_t     random_number[ATCA_KEY_SIZE];
	uint8_t     loop_count = 10;

	/* Init CRYPTO_AUTHENTICATION_INTERFACE_0 */
	CRYPTO_AUTHENTICATION_INTERFACE_0_init();

	do {
		/* Read device serial number... Unique value for each device and same on every read */
		if (ATCA_SUCCESS != (status = atcab_read_serial_number(serialnum)))
			break;

		/* Read random number... Unique value on every read */
		if (ATCA_SUCCESS != (status = atcab_random(random_number)))
			break;
	} while (loop_count--);
}
