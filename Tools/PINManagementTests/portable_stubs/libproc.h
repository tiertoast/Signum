/* Linux-only adapters for compiling the actual macOS coordination source.
 * RSS sampling is not exercised or validated by the lock tests. */
#pragma once
#include <stdint.h>
struct proc_taskinfo { uint64_t pti_resident_size; };
struct proc_bsdinfo { int pbi_status; };
#define PROC_PIDTASKINFO 1
#define PROC_PIDTBSDINFO 2
int proc_pidinfo(int, int, uint64_t, void *, int);
