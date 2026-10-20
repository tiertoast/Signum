// Diagnostic only: not linked into shipped products.
#include <mach/mach.h>
#include <libproc.h>
#include <stdint.h>
#include <unistd.h>
uint64_t signum_profile_resident(void) {
    struct mach_task_basic_info info; mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    return task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info, &count) == KERN_SUCCESS ? info.resident_size : 0;
}
uint64_t signum_profile_disk(int write) {
    struct rusage_info_v4 info = {0};
    if (proc_pid_rusage(getpid(), RUSAGE_INFO_V4, (rusage_info_t *)&info)) return 0;
    return write ? info.ri_diskio_byteswritten : info.ri_diskio_bytesread;
}
