#ifndef HAL_ARDUINO_H_
#define HAL_ARDUINO_H_

#define MAX_I2C_BUSES    1

typedef struct atcaI2Cmaster {
	int ref_ct;
	int bus_index;
} ATCAI2CMaster_t;

void change_i2c_speed( ATCAIface iface, uint32_t speed );

/** @} */
#endif /* HAL_ARDUINO_H_ */