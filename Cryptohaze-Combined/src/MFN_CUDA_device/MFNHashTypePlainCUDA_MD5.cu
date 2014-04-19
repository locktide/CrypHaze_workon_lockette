/*
Cryptohaze Multiforcer & Wordyforcer - low performance GPU password cracking
Copyright (C) 2011  Bitweasil (http://www.cryptohaze.com/)

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/


/**
 * @section DESCRIPTION
 *
 * This file implements MD5 multihash cracking.
 */

#include <stdint.h>
#include <stdio.h>
#include <cuda.h>

//#include "CUDA_Common/cuPrintf.cu"

#include "MFN_CUDA_device/MFN_CUDA_incrementors.h"
#include "MFN_CUDA_device/MFN_CUDA_Common.h"
#include "MFN_CUDA_device/MFN_CUDA_MD5.h"

#if !defined(__CUDACC__)
    // define the keywords, so that the IDE does not complain about them
    #define __global__
    #define __device__
    #define __shared__
    #define __constant__
    #define blockIdx.x 1
    #define blockDim.x 1
    #define threadIdx.x 1
    #define __align__() /**/
#endif

/**
 * The maximum password length supported by this hash type.
 */
#define MFN_HASH_TYPE_PLAIN_CUDA_MD5_MAX_PASSLEN 48

/**
 * The maximum charset length supported by this hash type.
 */
#define MFN_HASH_TYPE_PLAIN_CUDA_MD5_MAX_CHARSET_LENGTH 128


// Define the constant types used by the kernels here.
__device__ __constant__ __align__(16) uint8_t deviceCharsetPlainMD5[MFN_HASH_TYPE_PLAIN_CUDA_MD5_MAX_CHARSET_LENGTH * \
    MFN_HASH_TYPE_PLAIN_CUDA_MD5_MAX_PASSLEN];
__device__ __constant__ __align__(16) uint8_t deviceReverseCharsetPlainMD5[MFN_HASH_TYPE_PLAIN_CUDA_MD5_MAX_CHARSET_LENGTH * \
    MFN_HASH_TYPE_PLAIN_CUDA_MD5_MAX_PASSLEN];
__device__ __constant__ uint8_t charsetLengthsPlainMD5[MFN_HASH_TYPE_PLAIN_CUDA_MD5_MAX_PASSLEN];
__device__ __constant__ __align__(16) uint8_t  constantBitmapAPlainMD5[8192];

/**
 * Constant parameters go here instead of getting passed as kernel arguments.
 * This allows for faster accesses (as they are cached, and all threads will
 * be accessing the same element), and also reduces the shared memory usage,
 * which may allow for better occupancy in the future.  The kernels will load
 * these as needed, and theoretically will not need registers for some of them,
 * which will help reduce the register pressure on kernels.  Hopefully.
 */

// Password length.  Needed for some offset calculations.
__device__ __constant__ uint8_t passwordLengthPlainMD5;

// Number of hashes present in memory.
__device__ __constant__ uint64_t numberOfHashesPlainMD5;

// Address of the hashlist in global memory.
__device__ __constant__ uint8_t *deviceGlobalHashlistAddressPlainMD5;

// Addresses of the various global bitmaps.
__device__ __constant__ uint8_t *deviceGlobalBitmapAPlainMD5;
__device__ __constant__ uint8_t *deviceGlobalBitmapBPlainMD5;
__device__ __constant__ uint8_t *deviceGlobalBitmapCPlainMD5;
__device__ __constant__ uint8_t *deviceGlobalBitmapDPlainMD5;

// Addresses of the arrays for found passwords & success flags
__device__ __constant__ uint8_t *deviceGlobalFoundPasswordsPlainMD5;
__device__ __constant__ uint8_t *deviceGlobalFoundPasswordFlagsPlainMD5;

__device__ __constant__ uint8_t *deviceGlobalStartPointsPlainMD5;
__device__ __constant__ uint32_t *deviceGlobalStartPasswords32PlainMD5;

__device__ __constant__ uint32_t deviceNumberStepsToRunPlainMD5;
__device__ __constant__ uint64_t deviceNumberThreadsPlainMD5;





// Defined if we are using the loadPasswords32/storePasswords32
#define USE_NEW_PASSWORD_LOADING 1


#define MAKE_MFN_MD5_KERNEL1_8LENGTH(pass_len) \
__global__ void MFNHashTypePlainCUDA_MD5_GeneratedKernel_##pass_len () { \
    uint32_t b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, a, b, c, d; \
    uint32_t password_count = 0, passOffset; \
    __shared__ uint8_t __align__(16) sharedCharsetPlainMD5[MFN_HASH_TYPE_PLAIN_CUDA_MD5_MAX_CHARSET_LENGTH * pass_len]; \
    __shared__ uint8_t __align__(16) sharedReverseCharsetPlainMD5[MFN_HASH_TYPE_PLAIN_CUDA_MD5_MAX_CHARSET_LENGTH * pass_len]; \
    __shared__ uint8_t sharedCharsetLengthsPlainMD5[pass_len]; \
    __shared__ uint8_t __align__(16) sharedBitmap[8192]; \
    if (threadIdx.x == 0) { \
        uint64_t *sharedCharset64 = (uint64_t *)sharedCharsetPlainMD5; \
        uint64_t *deviceCharset64 = (uint64_t *)deviceCharsetPlainMD5; \
        uint64_t *sharedReverseCharset64 = (uint64_t *)sharedReverseCharsetPlainMD5; \
        uint64_t *deviceReverseCharset64 = (uint64_t *)deviceReverseCharsetPlainMD5; \
        uint64_t *constantBitmap64 = (uint64_t *)constantBitmapAPlainMD5; \
        uint64_t *sharedBitmap64 = (uint64_t *)sharedBitmap; \
        for (a = 0; a < ((MFN_HASH_TYPE_PLAIN_CUDA_MD5_MAX_CHARSET_LENGTH * pass_len) / 8); a++) { \
            sharedCharset64[a] = deviceCharset64[a]; \
            sharedReverseCharset64[a] = deviceReverseCharset64[a]; \
        } \
        for (a = 0; a < pass_len; a++) { \
            sharedCharsetLengthsPlainMD5[a] = charsetLengthsPlainMD5[a]; \
        } \
        for (a = 0; a < 8192 / 8; a++) { \
            sharedBitmap64[a] = constantBitmap64[a]; \
        } \
    } \
    syncthreads(); \
    b0 = b1 = b2 = b3 = b4 = b5 = b6 = b7 = b8 = b9 = b10 = b11 = b12 = b13 = b14 = b15 = 0; \
    b14 = pass_len * 8; \
    if (USE_NEW_PASSWORD_LOADING) { \
        loadPasswords32(deviceGlobalStartPasswords32PlainMD5, deviceNumberThreadsPlainMD5, pass_len); \
    } else {\
        if (charsetLengthsPlainMD5[1] == 0) { \
            loadPasswordSingle(sharedCharsetPlainMD5, deviceGlobalStartPointsPlainMD5, deviceNumberThreadsPlainMD5, pass_len); \
        } else { \
            loadPasswordMultiple(sharedCharsetPlainMD5, deviceGlobalStartPointsPlainMD5, deviceNumberThreadsPlainMD5, pass_len, MFN_HASH_TYPE_PLAIN_CUDA_MD5_MAX_CHARSET_LENGTH); \
        } \
        ResetCharacterAtPosition(0x80, pass_len, b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15); \
    } \
    while (password_count < deviceNumberStepsToRunPlainMD5) { \
        MD5_FIRST_3_ROUNDS(); \
        if (pass_len <= 8) { \
            MD5II (a, b, c, d, b0, MD5S41, 0xf4292244); \
            MD5II (d, a, b, c, b7, MD5S42, 0x432aff97); \
            MD5II (c, d, a, b, b14, MD5S43, 0xab9423a7); \
            MD5II (b, c, d, a, b5, MD5S44, 0xfc93a039); \
            MD5II (a, b, c, d, b12, MD5S41, 0x655b59c3); \
            if ((sharedBitmap[(a & 0x0000ffff) >> 3] >> (a & 0x00000007)) & 0x00000001) { \
                if (!(deviceGlobalBitmapAPlainMD5) || ((deviceGlobalBitmapAPlainMD5[(a >> 3) & 0x07FFFFFF] >> (a & 0x7)) & 0x1)) { \
                    MD5II (d, a, b, c, b3, MD5S42, 0x8f0ccc92); \
                    if (!deviceGlobalBitmapDPlainMD5 || ((deviceGlobalBitmapDPlainMD5[(d >> 3) & 0x07FFFFFF] >> (d & 0x7)) & 0x1)) { \
                        MD5II (c, d, a, b, b10, MD5S43, 0xffeff47d); \
                        if (!deviceGlobalBitmapCPlainMD5 || ((deviceGlobalBitmapCPlainMD5[(c >> 3) & 0x07FFFFFF] >> (c & 0x7)) & 0x1)) { \
                            MD5II (b, c, d, a, b1, MD5S44, 0x85845dd1); \
                            if (!deviceGlobalBitmapBPlainMD5 || ((deviceGlobalBitmapBPlainMD5[(b >> 3) & 0x07FFFFFF] >> (b & 0x7)) & 0x1)) { \
                                checkHashList128LE(a, b, c, d, b0, b1, b2, b3, \
                                    deviceGlobalFoundPasswordsPlainMD5, deviceGlobalFoundPasswordFlagsPlainMD5, \
                                    deviceGlobalHashlistAddressPlainMD5, numberOfHashesPlainMD5, \
                                    passwordLengthPlainMD5); \
            }   }   }   }   } \
        } else if (pass_len > 8) { \
            MD5II (a, b, c, d, b0, MD5S41, 0xf4292244); \
            MD5II (d, a, b, c, b7, MD5S42, 0x432aff97); \
            MD5II (c, d, a, b, b14, MD5S43, 0xab9423a7); \
            MD5II (b, c, d, a, b5, MD5S44, 0xfc93a039); \
            MD5II (a, b, c, d, b12, MD5S41, 0x655b59c3); \
            MD5II (d, a, b, c, b3, MD5S42, 0x8f0ccc92); \
            MD5II (c, d, a, b, b10, MD5S43, 0xffeff47d); \
            MD5II (b, c, d, a, b1, MD5S44, 0x85845dd1); \
            MD5II (a, b, c, d, b8, MD5S41, 0x6fa87e4f); \
            MD5II (d, a, b, c, b15, MD5S42, 0xfe2ce6e0); \
            MD5II (c, d, a, b, b6, MD5S43, 0xa3014314); \
            MD5II (b, c, d, a, b13, MD5S44, 0x4e0811a1); \
            MD5II (a, b, c, d, b4, MD5S41, 0xf7537e82);  \
            if ((sharedBitmap[(a & 0x0000ffff) >> 3] >> (a & 0x00000007)) & 0x00000001) { \
                if (!(deviceGlobalBitmapAPlainMD5) || ((deviceGlobalBitmapAPlainMD5[(a >> 3) & 0x07FFFFFF] >> (a & 0x7)) & 0x1)) { \
                    MD5II (d, a, b, c, b11, MD5S42, 0xbd3af235); \
                    if (!deviceGlobalBitmapDPlainMD5 || ((deviceGlobalBitmapDPlainMD5[(d >> 3) & 0x07FFFFFF] >> (d & 0x7)) & 0x1)) { \
                        MD5II (c, d, a, b, b2, MD5S43, 0x2ad7d2bb);  \
                        if (!deviceGlobalBitmapCPlainMD5 || ((deviceGlobalBitmapCPlainMD5[(c >> 3) & 0x07FFFFFF] >> (c & 0x7)) & 0x1)) { \
                            MD5II (b, c, d, a, b9, MD5S44, 0xeb86d391); \
                            if (!deviceGlobalBitmapBPlainMD5 || ((deviceGlobalBitmapBPlainMD5[(b >> 3) & 0x07FFFFFF] >> (b & 0x7)) & 0x1)) { \
                            checkHashList128LE(a, b, c, d, b0, b1, b2, b3, \
                                    deviceGlobalFoundPasswordsPlainMD5, deviceGlobalFoundPasswordFlagsPlainMD5, \
                                    deviceGlobalHashlistAddressPlainMD5, numberOfHashesPlainMD5, \
                                    passwordLengthPlainMD5); \
            }   }   }   }   }\
        } \
        if (charsetLengthsPlainMD5[1] == 0) { \
                makeMFNSingleIncrementors##pass_len (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5); \
        } else { \
                makeMFNMultipleIncrementors##pass_len (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5); \
        } \
        password_count++; \
    } \
    if (USE_NEW_PASSWORD_LOADING) { \
        storePasswords32(deviceGlobalStartPasswords32PlainMD5, deviceNumberThreadsPlainMD5, pass_len); \
    } \
}

MAKE_MFN_MD5_KERNEL1_8LENGTH(1);
MAKE_MFN_MD5_KERNEL1_8LENGTH(2);
MAKE_MFN_MD5_KERNEL1_8LENGTH(3);
MAKE_MFN_MD5_KERNEL1_8LENGTH(4);
MAKE_MFN_MD5_KERNEL1_8LENGTH(5);
MAKE_MFN_MD5_KERNEL1_8LENGTH(6);
MAKE_MFN_MD5_KERNEL1_8LENGTH(7);
MAKE_MFN_MD5_KERNEL1_8LENGTH(8);
MAKE_MFN_MD5_KERNEL1_8LENGTH(9);
MAKE_MFN_MD5_KERNEL1_8LENGTH(10);
MAKE_MFN_MD5_KERNEL1_8LENGTH(11);
MAKE_MFN_MD5_KERNEL1_8LENGTH(12);
MAKE_MFN_MD5_KERNEL1_8LENGTH(13);
MAKE_MFN_MD5_KERNEL1_8LENGTH(14);
MAKE_MFN_MD5_KERNEL1_8LENGTH(15);
MAKE_MFN_MD5_KERNEL1_8LENGTH(16);

extern "C" cudaError_t MFNHashTypePlainCUDA_MD5_CopyValueToConstant(
        const char *symbolName, void *hostDataAddress, size_t bytesToCopy) {
    return cudaMemcpyToSymbol(symbolName, hostDataAddress, bytesToCopy);
}

extern "C" cudaError_t MFNHashTypePlainCUDA_MD5_LaunchKernel(uint32_t passwordLength, uint32_t Blocks, uint32_t Threads) {
    //printf("MFNHashTypePlainCUDA_MD5_LaunchKernel()\n");

    //cudaPrintfInit();
    switch (passwordLength) {
        case 1:
            MFNHashTypePlainCUDA_MD5_GeneratedKernel_1 <<< Blocks, Threads >>> ();
            break;
        case 2:
            MFNHashTypePlainCUDA_MD5_GeneratedKernel_2 <<< Blocks, Threads >>> ();
            break;
        case 3:
            MFNHashTypePlainCUDA_MD5_GeneratedKernel_3 <<< Blocks, Threads >>> ();
            break;
        case 4:
            MFNHashTypePlainCUDA_MD5_GeneratedKernel_4 <<< Blocks, Threads >>> ();
            break;
        case 5:
            MFNHashTypePlainCUDA_MD5_GeneratedKernel_5 <<< Blocks, Threads >>> ();
            break;
        case 6:
            MFNHashTypePlainCUDA_MD5_GeneratedKernel_6 <<< Blocks, Threads >>> ();
            break;
        case 7:
            MFNHashTypePlainCUDA_MD5_GeneratedKernel_7 <<< Blocks, Threads >>> ();
            break;
        case 8:
            MFNHashTypePlainCUDA_MD5_GeneratedKernel_8 <<< Blocks, Threads >>> ();
            break;
        case 9:
            MFNHashTypePlainCUDA_MD5_GeneratedKernel_9 <<< Blocks, Threads >>> ();
            break;
        case 10:
            MFNHashTypePlainCUDA_MD5_GeneratedKernel_10 <<< Blocks, Threads >>> ();
            break;
        case 11:
            MFNHashTypePlainCUDA_MD5_GeneratedKernel_11 <<< Blocks, Threads >>> ();
            break;
        case 12:
            MFNHashTypePlainCUDA_MD5_GeneratedKernel_12 <<< Blocks, Threads >>> ();
            break;
        case 13:
            MFNHashTypePlainCUDA_MD5_GeneratedKernel_13 <<< Blocks, Threads >>> ();
            break;
        case 14:
            MFNHashTypePlainCUDA_MD5_GeneratedKernel_14 <<< Blocks, Threads >>> ();
            break;
        case 15:
            MFNHashTypePlainCUDA_MD5_GeneratedKernel_15 <<< Blocks, Threads >>> ();
            break;
        case 16:
            MFNHashTypePlainCUDA_MD5_GeneratedKernel_16 <<< Blocks, Threads >>> ();
            break;
        default:
            printf("Password length %d unsupported!\n", passwordLength);
            exit(1);
            break;
            
    }
    //cudaPrintfDisplay(stdout, true);
    //cudaPrintfEnd();

    return cudaGetLastError();
}
