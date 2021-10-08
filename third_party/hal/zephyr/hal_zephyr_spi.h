/*
 * Copyright (c) 2020 Microchip Technology Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef HAL_ZEPHYR_SPI_H_
#define HAL_ZEPHYR_SPI_H_

typedef struct atca_spi_host_config_s
{
    const char * device_name;
    const char * gpio_name;
} atca_spi_host_config_t;

#endif
