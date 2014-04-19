/**
 * This file includes a lot of standard libraries used throughout the
 * Cryptohaze tools.  This does NOT import any platform-specific libraries
 * such as the CUDA or OpenCL libraries.  Just plain C and C+ stuff.
 */


#ifndef __CHCOMMONBUILDINCLUDES_H__
#define __CHCOMMONBUILDINCLUDES_H__

// Include all the host-only stuff - the CUDA compiler barfs on this.
#ifndef __CUDACC__
	#ifdef _WIN32
		#define _WINSOCKAPI_ // Prevent inclusion of winsock.h in windows.h
		#define WIN32_LEAN_AND_MEAN
		#include <winsock2.h>
		#include "pdcurs34/curses.h"
		#include "argtable2-13/src/argtable2.h"
		#include <time.h>
		#include <windows.h>
		#include <iostream>
	#else
		#include <argtable2.h>
		#include <unistd.h>
		#include <ncurses.h>
                #include <sys/time.h>
	#endif

	// C++ Headers - nvcc doesn't like templates.
	#include <iostream>
	#include <valarray>
	#include <new>
	#include <exception>
#endif

// C headers
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <math.h>
#include <signal.h>
#include <limits.h>

#ifdef _WIN32
	#include "windows/stdint.h"
#else
	#include <stdint.h>
#endif


#endif