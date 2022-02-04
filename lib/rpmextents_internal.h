#ifndef _RPMEXTENTS_INTERNAL_H
#define _RPMEXTENTS_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* magic value at end of file (64 bits) that indicates this is a transcoded
 * rpm.
 */
#define EXTENTS_MAGIC 3472329499408095051

typedef uint64_t extents_magic_t;

rpmRC isTranscodedRpm(FD_t fd);

#ifdef __cplusplus
}
#endif
#endif
