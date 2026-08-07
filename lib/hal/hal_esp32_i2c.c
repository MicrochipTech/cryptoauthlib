/*
 * Copyright 2018 Espressif Systems (Shanghai) PTE LTD
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <soc/soc_caps.h>
#include "esp_idf_version.h"

#if defined(CONFIG_ATCA_I2C_USE_LEGACY_DRIVER)
#include <driver/i2c.h>
#else
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 2, 0)
#include <driver/i2c_master.h>
#else
#include <driver/i2c.h>
#endif
#endif

#include "esp_err.h"
#include "esp_log.h"
#include "cryptoauthlib.h"

#define I2C0_SDA_PIN                       16
#define I2C0_SCL_PIN                       17
#define I2C1_SDA_PIN                       21
#define I2C1_SCL_PIN                       22
#define ACK_CHECK_EN                       0x1  /*!< I2C master will check ack from slave*/
#define ACK_CHECK_DIS                      0x0  /*!< I2C master will not check ack from slave */
#define ACK_VAL                            0x0  /*!< I2C ack value */
#define NACK_VAL                           0x1  /*!< I2C nack value */

#ifndef LOG_LOCAL_LEVEL
#define LOG_LOCAL_LEVEL                    ESP_LOG_INFO
#endif

#define MAX_I2C_BUSES 2 //ESP32 has 2 I2C bus

typedef struct atcaI2Cmaster
{
    int          id;
#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(5, 2, 0) || defined(CONFIG_ATCA_I2C_USE_LEGACY_DRIVER)
    i2c_config_t conf;
#else
    i2c_master_bus_config_t conf;
    i2c_device_config_t dev_conf;
    i2c_master_bus_handle_t bus_handle;
    i2c_master_dev_handle_t dev_handle;
#endif
    int          ref_ct;
} ATCAI2CMaster_t;

ATCAI2CMaster_t i2c_hal_data[MAX_I2C_BUSES];

const char* TAG = "HAL_I2C";

ATCA_STATUS status;

/** \brief method to change the bus speec of I2C
 * \param[in] iface  interface on which to change bus speed
 * \param[in] speed  baud rate (typically 100000 or 400000)
 */
ATCA_STATUS hal_i2c_change_baud(ATCAIface iface, uint32_t speed)
{
    esp_err_t rc;
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    int bus = cfg->atcai2c.bus;

#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(5, 2, 0) || defined(CONFIG_ATCA_I2C_USE_LEGACY_DRIVER)
    i2c_hal_data[bus].conf.master.clk_speed = speed;
    rc = i2c_param_config(i2c_hal_data[bus].id, &i2c_hal_data[bus].conf);
#else
    i2c_hal_data[bus].dev_conf.scl_speed_hz = speed;
    rc = i2c_master_bus_add_device(i2c_hal_data[bus].bus_handle, &i2c_hal_data[bus].dev_conf, &i2c_hal_data[bus].dev_handle);
#endif

    if (rc == ESP_OK)
    {
        //ESP_LOGD(TAG, "Baudrate Changed");
        return ATCA_SUCCESS;
    }
    else
    {
        //ESP_LOGW(TAG, "Baudrate Change Failed");
        return ATCA_COMM_FAIL;
    }
}

/** \brief
    - this HAL implementation assumes you've included the START Twi libraries in your project, otherwise,
    the HAL layer will not compile because the START TWI drivers are a dependency *
 */

/** \brief hal_i2c_init manages requests to initialize a physical interface.  it manages use counts so when an interface
 * has released the physical layer, it will disable the interface for some other use.
 * You can have multiple ATCAIFace instances using the same bus, and you can have multiple ATCAIFace instances on
 * multiple i2c buses, so hal_i2c_init manages these things and ATCAIFace is abstracted from the physical details.
 */

/** \brief initialize an I2C interface using given config
 * \param[in] hal - opaque ptr to HAL data
 * \param[in] cfg - interface configuration
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_init(ATCAIface iface, ATCAIfaceCfg *cfg)
{
    esp_err_t rc = ESP_FAIL;
    int bus = cfg->atcai2c.bus;

    if (bus >= 0 && bus < MAX_I2C_BUSES)
    {
        if (0 == i2c_hal_data[bus].ref_ct)
        {
            i2c_hal_data[bus].ref_ct = 1;

#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(5, 2, 0) || defined(CONFIG_ATCA_I2C_USE_LEGACY_DRIVER)

            i2c_hal_data[bus].conf.mode = I2C_MODE_MASTER;
            i2c_hal_data[bus].conf.sda_pullup_en = GPIO_PULLUP_DISABLE;
            i2c_hal_data[bus].conf.scl_pullup_en = GPIO_PULLUP_DISABLE;
            i2c_hal_data[bus].conf.master.clk_speed = 100000; // cfg->atcai2c.baud

            switch (bus)
            {
                case 0: i2c_hal_data[bus].id = I2C_NUM_0;
                        i2c_hal_data[bus].conf.sda_io_num = I2C0_SDA_PIN;
                        i2c_hal_data[bus].conf.scl_io_num = I2C0_SCL_PIN;
                        break;
                case 1: i2c_hal_data[bus].id = I2C_NUM_1;
                        i2c_hal_data[bus].conf.sda_io_num = I2C1_SDA_PIN;
                        i2c_hal_data[bus].conf.scl_io_num = I2C1_SCL_PIN;
                        break;
            }

            rc = i2c_param_config(i2c_hal_data[bus].id, &i2c_hal_data[bus].conf);
            if (rc == ESP_OK) {
                rc = i2c_driver_install(i2c_hal_data[bus].id, I2C_MODE_MASTER, 0, 0, 0);
            }

#else

            i2c_hal_data[bus].conf.i2c_port = (bus == 0) ? I2C_NUM_0 : I2C_NUM_1;
            i2c_hal_data[bus].conf.scl_io_num = (bus == 0) ? I2C0_SCL_PIN : I2C1_SCL_PIN;
            i2c_hal_data[bus].conf.sda_io_num = (bus == 0) ? I2C0_SDA_PIN : I2C1_SDA_PIN;
            i2c_hal_data[bus].conf.clk_source = I2C_CLK_SRC_DEFAULT;
            i2c_hal_data[bus].conf.glitch_ignore_cnt = 7;
            i2c_hal_data[bus].conf.flags.enable_internal_pullup = true;

            i2c_hal_data[bus].dev_conf.dev_addr_length = I2C_ADDR_BIT_LEN_7;
            i2c_hal_data[bus].dev_conf.scl_speed_hz = 100000; // cfg->atcai2c.baud

            rc = i2c_new_master_bus(&i2c_hal_data[bus].conf, &i2c_hal_data[bus].bus_handle);
            
#endif
        }
        else
        {
            i2c_hal_data[bus].ref_ct++;
        }

        iface->hal_data = &i2c_hal_data[bus];
    }

    return (ESP_OK == rc) ? ATCA_SUCCESS : ATCA_COMM_FAIL;
}


/** \brief HAL implementation of I2C post init
 * \param[in] iface  instance
 * \return ATCA_SUCCESS
 */
ATCA_STATUS hal_i2c_post_init(ATCAIface iface)
{
    return ATCA_SUCCESS;
}

/** \brief HAL implementation of I2C send
 * \param[in] iface         instance
 * \param[in] word_address  device transaction type
 * \param[in] txdata        pointer to space to bytes to send
 * \param[in] txlength      number of bytes to send
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t word_address, uint8_t *txdata, int txlength)
{
    ATCAIfaceCfg *cfg = iface->mIfaceCFG;
    esp_err_t rc;
    uint8_t device_address = 0xFFu;

    if (!cfg)
    {
        return ATCA_BAD_PARAM;
    }

#ifdef ATCA_ENABLE_DEPRECATED
    device_address = ATCA_IFACECFG_VALUE(cfg, atcai2c.slave_address);
#else
    device_address = ATCA_IFACECFG_VALUE(cfg, atcai2c.address);
#endif

    //ESP_LOGD(TAG, "txdata: %p , txlength: %d", txdata, txlength);
    //ESP_LOG_BUFFER_HEXDUMP(TAG, txdata, txlength, 3);
#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(5, 2, 0) || defined(CONFIG_ATCA_I2C_USE_LEGACY_DRIVER)

    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    (void)i2c_master_start(cmd);
    (void)i2c_master_write_byte(cmd, device_address | I2C_MASTER_WRITE, ACK_CHECK_EN);
    (void)i2c_master_write_byte(cmd, word_address, ACK_CHECK_EN);

    if (NULL != txdata && 0u < txlength)
    {
        (void)i2c_master_write(cmd, txdata, txlength, ACK_CHECK_EN);
    }
    (void)i2c_master_stop(cmd);
    rc = i2c_master_cmd_begin(cfg->atcai2c.bus, cmd, 10);
    (void)i2c_cmd_link_delete(cmd);

#else

    int bus = cfg->atcai2c.bus;
    uint8_t temp_buf[MAX_PACKET_SIZE] = {0};
    i2c_hal_data[bus].dev_conf.device_address = device_address >> 1;

    rc = i2c_master_bus_add_device(i2c_hal_data[bus].bus_handle, &i2c_hal_data[bus].dev_conf, &i2c_hal_data[bus].dev_handle);

    if (ESP_OK == rc)
    {
        temp_buf[0] = word_address;

        if (NULL != txdata)
        {
            memcpy(&temp_buf[1], txdata, txlength);
        }

        //! Add 1 byte for word address
        txlength += 1u;

        rc = i2c_master_transmit(i2c_hal_data[bus].dev_handle, temp_buf, txlength, 200);
    }

    (void)i2c_master_bus_rm_device(i2c_hal_data[bus].dev_handle);
    i2c_hal_data[bus].dev_handle = NULL;
    
#endif

    if (ESP_OK != rc)
    {
        return ATCA_COMM_FAIL;
    }
    else
    {
        return ATCA_SUCCESS;
    }
}

/** \brief HAL implementation of I2C receive function
 * \param[in]    iface          Device to interact with.
 * \param[in]    address        Device address
 * \param[out]   rxdata         Data received will be returned here.
 * \param[in,out] rxlength      As input, the size of the rxdata buffer.
 *                              As output, the number of bytes received.
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t address, uint8_t *rxdata, uint16_t *rxlength)
{
    ATCAIfaceCfg *cfg = iface->mIfaceCFG;
    esp_err_t rc;
    int bus = cfg->atcai2c.bus;
    
    ATCA_STATUS status = ATCA_COMM_FAIL;

    if ((NULL == cfg) || (NULL == rxlength) || (NULL == rxdata))
    {
        return ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer encountered");
    }

#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(5, 2, 0) || defined(CONFIG_ATCA_I2C_USE_LEGACY_DRIVER)
    i2c_cmd_handle_t cmd;

    cmd = i2c_cmd_link_create();
    (void)i2c_master_start(cmd);
    (void)i2c_master_write_byte(cmd, address | I2C_MASTER_READ, ACK_CHECK_EN);
    if (*rxlength > 1)
    {
        (void)i2c_master_read(cmd, rxdata, *rxlength - 1, ACK_VAL);
    }
    (void)i2c_master_read_byte(cmd, rxdata + (size_t)*rxlength - 1, NACK_VAL);
    (void)i2c_master_stop(cmd);
    rc = i2c_master_cmd_begin(cfg->atcai2c.bus, cmd, 10);
    (void)i2c_cmd_link_delete(cmd);

    //ESP_LOG_BUFFER_HEXDUMP(TAG, rxdata, *rxlength, 3);

#else

#ifdef ATCA_ENABLE_DEPRECATED
    i2c_hal_data[bus].dev_conf.device_address = ATCA_IFACECFG_VALUE(cfg, atcai2c.slave_address) >> 1;
#else
    i2c_hal_data[bus].dev_conf.device_address = ATCA_IFACECFG_VALUE(cfg, atcai2c.address) >> 1;
#endif
    
    rc = i2c_master_bus_add_device(i2c_hal_data[bus].bus_handle, &i2c_hal_data[bus].dev_conf, &i2c_hal_data[bus].dev_handle);

    if (ESP_OK == rc)
    {
        rc = i2c_master_receive(i2c_hal_data[bus].dev_handle, rxdata, *rxlength, 200);
    }

    (void)i2c_master_bus_rm_device(i2c_hal_data[bus].dev_handle);
    i2c_hal_data[bus].dev_handle = NULL;

#endif

    if (ESP_OK == rc)
    {
        status = ATCA_SUCCESS;
    }

    return status;

}

/** \brief manages reference count on given bus and releases resource if no more refences exist
 * \param[in] hal_data - opaque pointer to hal data structure - known only to the HAL implementation
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_release(void *hal_data)
{
    esp_err_t rc;
    ATCA_STATUS status = ATCA_EXECUTION_ERROR;
    ATCAI2CMaster_t *hal = (ATCAI2CMaster_t*)hal_data;

    if (hal->dev_handle) {
        rc = i2c_master_bus_rm_device(hal->dev_handle);
        hal->dev_handle = NULL;
    }

    if (hal && --(hal->ref_ct) <= 0)
    {
#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(5, 2, 0) || defined(CONFIG_ATCA_I2C_USE_LEGACY_DRIVER)
        rc = i2c_driver_delete(hal->id);
#else
        if (ESP_OK == rc)
        {
          if (hal->bus_handle) {
              rc = i2c_del_master_bus(hal->bus_handle);
          }
        }
#endif
    }

    if (ESP_OK == rc)
    {
        status = ATCA_SUCCESS;
    }

    return status;
}

/** \brief Perform control operations for the kit protocol
 * \param[in]     iface          Interface to interact with.
 * \param[in]     option         Control parameter identifier
 * \param[in]     param          Optional pointer to parameter value
 * \param[in]     paramlen       Length of the parameter
 * \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS hal_i2c_control(ATCAIface iface, uint8_t option, void* param, size_t paramlen)
{
    (void)param;
    (void)paramlen;

    if (iface && iface->mIfaceCFG)
    {
        if (ATCA_HAL_CHANGE_BAUD == option)
        {
            return hal_i2c_change_baud(iface, *(uint32_t*)param);
        }
        else
        {
            return ATCA_UNIMPLEMENTED;
        }
    }
    return ATCA_BAD_PARAM;
}
