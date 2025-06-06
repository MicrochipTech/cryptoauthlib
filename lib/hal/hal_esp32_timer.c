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

#include "atca_hal.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

extern void ets_delay_us(uint32_t);

void hal_delay_us(uint32_t delay)
{
    ets_delay_us(delay);
}

void hal_delay_ms(uint32_t delay)
{
    ets_delay_us(delay * 1000);
}
