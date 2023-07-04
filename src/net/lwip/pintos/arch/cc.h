#ifndef __LWIP_ARCH_CC_H
#define __LWIP_ARCH_CC_H

#include <debug.h>
#include <stdio.h>
#include "threads/interrupt.h"

// define basic types used by lWIP
typedef unsigned char  u8_t;
typedef unsigned short u16_t;
typedef unsigned int   u32_t;

typedef char           s8_t;
typedef short          s16_t;
typedef int            s32_t;

typedef int            mem_ptr_t;

// printf formatters for data types
#define U16_F "hu"
#define S16_F "d"
#define X16_F "hx"

#define U32_F "u"
#define S32_F "d"
#define X32_F "x"

#define SZT_F "uz"

#define LWIP_CHKSUM_ALGORITHM 2
#define LWIP_PLATFORM_DIAG(x)   printf x
#define LWIP_PLATFORM_ASSERT(x) ASSERT (x)

#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif

#define PACK_STRUCT_FIELD(x)  x
#define PACK_STRUCT_STRUCT
#define PACK_STRUCT_BEGIN
#define PACK_STRUCT_END

#endif

