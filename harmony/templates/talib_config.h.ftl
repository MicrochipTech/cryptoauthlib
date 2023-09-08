/* Auto-generated config file atca_config.h */
#ifndef TALIB_CONFIG_H
#define TALIB_CONFIG_H


/******************** Device Configuration Section *************************/

<#if CAL_ENABLE_TA10x_AES_AUTH>
/** TA10x Specific - Enable auth sessions that require AES (CMAC/GCM) from
   an external library */
#define TALIB_AES_AUTH_SUPPORT
</#if>

<#if CAL_ENABLE_TA10x_FCE>
/** TA10x Specific - Enable support for the FCE APIs for the TA10x devices */
#define TALIB_FCE_SUPPORT
</#if>

#endif // TALIB_CONFIG_H
