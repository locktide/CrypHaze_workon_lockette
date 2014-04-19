// Defines for debugging


// Defines for the trace printfs: Showing flow through the code.
// Use for things like announcing on entering and exiting a function.
#define TRACE_PRINTF 0

#if TRACE_PRINTF
#define trace_printf(fmt, ...) printf(fmt, ##__VA_ARGS__);
#else
#define trace_printf(fmt, ...) do {} while (0)
#endif


// Kernel launch printfs - things like the thread/block count, etc.
#define KERNEL_LAUNCH_PRINTF 0

#if KERNEL_LAUNCH_PRINTF
#define klaunch_printf(fmt, ...) printf(fmt, ##__VA_ARGS__);
#else
#define klaunch_printf(fmt, ...) do {} while (0)
#endif



// Multithreaded debugging related printfs
#define MT_PRINTF 0

#if MT_PRINTF
#define mt_printf(fmt, ...) printf(fmt, ##__VA_ARGS__);
#else
#define mt_printf(fmt, ...) do {} while (0)
#endif


// Static data setup printfs
#define STATIC_PRINTF 0

#if STATIC_PRINTF
#define static_printf(fmt, ...) printf(fmt, ##__VA_ARGS__);
#else
#define static_printf(fmt, ...) do {} while (0)
#endif


// Memory allocation printfs
#define MEMALLOC_PRINTF 0

#if MEMALLOC_PRINTF
#define memalloc_printf(fmt, ...) printf(fmt, ##__VA_ARGS__);
#else
#define memalloc_printf(fmt, ...) do {} while (0)
#endif
