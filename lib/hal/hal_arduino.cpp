#include <string.h>
#include <stdio.h>
#include <Arduino.h>

extern "C" {
#include "hal_arduino_twi.h"
}

#include "../atca_command.h"
#include "atca_hal.h"
#include "atca_device.h"
#include "hal_arduino.h"
#include "../basic/atca_basic.h"

#define LOG(_x) Serial.print(_x)

#ifndef NUM_ELEMS
#  define NUM_ELEMS(_array) (sizeof(_array)/sizeof((_array)[0]))
#endif

#ifndef MIN
#  define MIN(_x, _y) ((_x) <= (_y) ? (_x) : (_y))
#endif

extern "C" {

static bool wake_complete = false;

struct DevRev
{
  uint8_t rev[4];
  ATCADeviceType type;
};

static const DevRev g_devrevs[] = {
  {{ 0x00, 0x00, 0x50, 0x00 }, ATECC508A},
  {{ 0x80, 0x00, 0x10, 0x01 }, ATECC108A},
  {{ 0x00, 0x00, 0x10, 0x05 }, ATECC108A},
  {{ 0x00, 0x02, 0x00, 0x08 }, ATSHA204A},
  {{ 0x00, 0x02, 0x00, 0x09 }, ATSHA204A},
  {{ 0x00, 0x04, 0x05, 0x00 }, ATSHA204A},
};

ATCA_STATUS hal_i2c_discover_buses(int *buses, int buses_len)
{
  if (buses_len < 1) {
    return ATCA_SUCCESS;
  }
  buses[0] = 2;
  for (int i = 1; i < buses_len; ++i) {
    buses[i] = -1;
  }
  return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_discover_devices(int busNum, ATCAIfaceCfg *cfg, int *found)
{
  cfg->iface_type				= ATCA_I2C_IFACE;
  cfg->devtype				  = ATCA_DEV_UNKNOWN;
  cfg->wake_delay				= 800;
  cfg->rx_retries				= 3;
  cfg->atcai2c = {
    .slave_address	= 0x07,
    .bus			      = (uint8_t) busNum,
    .baud			      = 400000
  };

  uint8_t buff[4] = {0};
  if (atcab_info(buff) != ATCA_SUCCESS) {
    LOG("atcab_info failed");
    return ATCA_COMM_FAIL;
  }

  for (size_t i = 0 ; i < NUM_ELEMS(g_devrevs); ++i) {
    if (memcmp(buff, g_devrevs[i].rev, sizeof(buff)) == 0) {
      cfg->devtype = g_devrevs[i].type;
      break;
    }
  }

	return ATCA_SUCCESS;
}

static void nop1() {}
static void nop2(uint8_t*, int) {}

ATCA_STATUS hal_i2c_init(void *hal, ATCAIfaceCfg *cfg)
{
    twi_init();
    twi_attachSlaveTxEvent(nop1); // default callback must exist
    twi_attachSlaveRxEvent(nop2); // default callback must exist
	  return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_post_init(ATCAIface iface)
{
	  return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t *txdata, int txlength)
{
  const ATCAIfaceCfg *cfg = atgetifacecfg(iface);

  txdata[0] = 0x03;   // insert the Word Address Value, Command token
  txlength++;

  const uint8_t ret = twi_writeTo(
    cfg->atcai2c.slave_address >> 1, 
    txdata,
    txlength,
    1,
    true);
  switch (ret) {
    case 0:
      return ATCA_SUCCESS;

    case 1:
      /* Msg too long for buffer */
      return ATCA_BAD_PARAM;

    default:
      return ATCA_COMM_FAIL;
  }
}

ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t *rxdata, uint16_t *rxlength)
{
  if (*rxlength == 0) {
    return ATCA_SUCCESS;
  }

  ATCAIfaceCfg *cfg = atgetifacecfg(iface);
  int retries = cfg->rx_retries;
  const uint8_t addr = cfg->atcai2c.slave_address >> 1;

  // read msg length
  uint8_t msg_len = 0;
  while (twi_readFrom(addr, &msg_len, 1, true) < 1 && retries > 0) {
    delay(100);
    --retries;
  }
  if (retries <= 0) {
    LOG("no response\n");
    return ATCA_COMM_FAIL;
  }
  *(rxdata++) = msg_len;

  // read msg
  uint8_t to_read = MIN((uint8_t ) (msg_len - 1), *rxlength);
  retries = cfg->rx_retries;
  while (to_read > 0 && retries > 0) {
    const uint8_t read_len = twi_readFrom(addr, rxdata, to_read, true);
    if (read_len > to_read) {
      return ATCA_COMM_FAIL;
    }
    if (read_len == 0) {
      delay(100);
      --retries;
      continue;
    }
    to_read -= read_len;
    rxdata += read_len;
  }
  if (to_read > 0) {
    return ATCA_COMM_FAIL;
  }

  return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_wake(ATCAIface iface)
{
    ATCAIfaceCfg *cfg = atgetifacecfg(iface);
    int retries = cfg->rx_retries;
    const uint8_t addr = cfg->atcai2c.slave_address >> 1;

    twi_writeTo(0, NULL, 0, 1, true);

    atca_delay_us(cfg->wake_delay);

    // read response
    uint8_t buff[4] = {0};
    while (twi_readFrom(addr, buff, sizeof(buff), true) < 1 && retries > 0) {
      delay(100);
      --retries;
    }
    if (retries <= 0) {
      LOG("no response\n");
      return ATCA_COMM_FAIL;
    }

    if (wake_complete) {
        return ATCA_SUCCESS;
    }
    wake_complete = true;

    // check response
    if (hal_check_wake(buff, sizeof(buff)) != ATCA_SUCCESS) {
        LOG("incorrect response\n");
        return ATCA_COMM_FAIL;
    }

    return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_idle(ATCAIface iface)
{
  const ATCAIfaceCfg *cfg = atgetifacecfg(iface);

  uint8_t buff = 0x02; // idle word address value
  const uint8_t ret = twi_writeTo(
    cfg->atcai2c.slave_address >> 1, 
    &buff,
    sizeof(buff),
    1,
    true);
  if (ret != 0) {
    return ATCA_COMM_FAIL;
  }

  wake_complete = false;

  return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_sleep(ATCAIface iface)
{
  const ATCAIfaceCfg *cfg = atgetifacecfg(iface);

  uint8_t buff = 0x01; // sleep word address value
  const uint8_t ret = twi_writeTo(
    cfg->atcai2c.slave_address >> 1,
    &buff,
    sizeof(buff),
    1,
    true);
  if (ret != 0) {
    return ATCA_COMM_FAIL;
  }

  return ATCA_SUCCESS;
}

ATCA_STATUS hal_i2c_release( void *hal_data )
{
  return ATCA_SUCCESS;
}

void atca_delay_ms(uint32_t ms)
{
	delay(ms);
}

void atca_delay_us(uint32_t us)
{
	delayMicroseconds(us);
}

} // extern "C"