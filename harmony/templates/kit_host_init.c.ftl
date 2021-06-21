/**
 * \file
 * \brief Kit Host Initialization Structures and Functions

 * \copyright (c) 2021 Microchip Technology Inc. and its subsidiaries.
 *
 * \page License
 *
 * Subject to your compliance with these terms, you may use Microchip software
 * and any derivatives exclusively with Microchip products. It is your
 * responsibility to comply with third party license terms applicable to your
 * use of third party software (including open source software) that may
 * accompany Microchip software.
 *
 * THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
 * EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
 * WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
 * PARTICULAR PURPOSE. IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT,
 * SPECIAL, PUNITIVE, INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE
 * OF ANY KIND WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF
 * MICROCHIP HAS BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE
 * FORESEEABLE. TO THE FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL
 * LIABILITY ON ALL CLAIMS IN ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED
 * THE AMOUNT OF FEES, IF ANY, THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR
 * THIS SOFTWARE.
 */

#include "cryptoauthlib.h"
#include "kit_host/ascii_kit_host.h"

<#assign plib_name = HAL_INTERFACE?split("_")[0]>
static ATCAIfaceCfg kit_host_init_data = {
    .iface_type            = ATCA_UART_IFACE,
    .cfg_data              = &${plib_name?lower_case}_plib_uart_api
};

<#assign devcfglist = cryptoauthlib.CAL_DEV_CFG_LIST?word_list>

<#list devcfglist as devcfg_id>
extern ATCAIfaceCfg ${devcfg_id};
</#list>

static ATCAIfaceCfg * kit_host_iface_list[] = {
<#list devcfglist as devcfg_id>
    &${devcfg_id},
</#list>
};

static size_t kit_host_iface_list_count = sizeof(kit_host_iface_list) / sizeof(kit_host_iface_list[0]);

static atca_hal_kit_phy_t       kit_host_phy;
static atca_iface_t             kit_host_iface;


ATCA_STATUS kit_host_app_init(ascii_kit_host_context_t * ctx)
{
    ATCA_STATUS status = initATCAIface(&kit_host_init_data, &kit_host_iface);
    
    if (ATCA_SUCCESS == status)
    {
        status = kit_host_init_phy(&kit_host_phy, &kit_host_iface);
    }
    
    if (ATCA_SUCCESS == status)
    {
        status = kit_host_init(ctx, kit_host_iface_list, kit_host_iface_list_count,
                               &kit_host_phy, 0);
    }
    
    return status;
            
}
