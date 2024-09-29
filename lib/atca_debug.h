#ifndef ATCA_DEBUG_H
#define ATCA_DEBUG_H

#include "atca_status.h"

#ifndef LIBRARY_BUILD_EN
#include "atca_config.h"
#endif


ATCA_STATUS atca_trace(ATCA_STATUS status);
#ifdef ATCA_PRINTF
void atca_trace_config(FILE* fp);
ATCA_STATUS atca_trace_msg(ATCA_STATUS status, const char * msg);
#endif

#endif /* ATCA_DEBUG_H */
