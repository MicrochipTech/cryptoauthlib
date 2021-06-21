#include "cryptoauthlib.h"

<#assign devcfglist = cryptoauthlib.CAL_DEV_CFG_LIST?word_list>
<#if devcfglist?size != 0>
<#list devcfglist as devcfg_id>
extern ATCAIfaceCfg ${devcfg_id};
</#list>
</#if>

<#if devcfglist?size != 0>
ATCAIfaceCfg *devcfg_list[] = {
<#list devcfglist as devcfg_id>
    &${devcfg_id},
</#list>
};
</#if>