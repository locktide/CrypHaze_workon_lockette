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
 * This file implements NTLM multihash cracking.
 */

#include <stdint.h>
#include <stdio.h>
#include <cuda.h>

#include "MFN_CUDA_device/MFN_CUDA_NTLM_incrementors.h"
#include "MFN_CUDA_device/MFN_CUDA_Common.h"
#include "MFN_CUDA_device/MFN_CUDA_MD4.h"

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
#define MFN_HASH_TYPE_PLAIN_CUDA_NTLM_MAX_PASSLEN 28

/**
 * The maximum charset length supported by this hash type.
 */
#define MFN_HASH_TYPE_PLAIN_CUDA_NTLM_MAX_CHARSET_LENGTH 128


// Define the constant types used by the kernels here.
__device__ __constant__ __align__(16) uint8_t deviceCharsetPlainNTLM[MFN_HASH_TYPE_PLAIN_CUDA_NTLM_MAX_CHARSET_LENGTH * \
    MFN_HASH_TYPE_PLAIN_CUDA_NTLM_MAX_PASSLEN];
__device__ __constant__ __align__(16) uint8_t deviceReverseCharsetPlainNTLM[MFN_HASH_TYPE_PLAIN_CUDA_NTLM_MAX_CHARSET_LENGTH * \
    MFN_HASH_TYPE_PLAIN_CUDA_NTLM_MAX_PASSLEN];
__device__ __constant__ uint8_t charsetLengthsPlainNTLM[MFN_HASH_TYPE_PLAIN_CUDA_NTLM_MAX_PASSLEN];
__device__ __constant__ __align__(16) uint8_t  constantBitmapAPlainNTLM[8192];

/**
 * Constant parameters go here instead of getting passed as kernel arguments.
 * This allows for faster accesses (as they are cached, and all threads will
 * be accessing the same element), and also reduces the shared memory usage,
 * which may allow for better occupancy in the future.  The kernels will load
 * these as needed, and theoretically will not need registers for some of them,
 * which will help reduce the register pressure on kernels.  Hopefully.
 */

// Password length.  Needed for some offset calculations.
__device__ __constant__ uint8_t passwordLengthPlainNTLM;

// Number of hashes present in memory.
__device__ __constant__ uint64_t numberOfHashesPlainNTLM;

// Address of the hashlist in global memory.
__device__ __constant__ uint8_t *deviceGlobalHashlistAddressPlainNTLM;

// Addresses of the various global bitmaps.
__device__ __constant__ uint8_t *deviceGlobalBitmapAPlainNTLM;
__device__ __constant__ uint8_t *deviceGlobalBitmapBPlainNTLM;
__device__ __constant__ uint8_t *deviceGlobalBitmapCPlainNTLM;
__device__ __constant__ uint8_t *deviceGlobalBitmapDPlainNTLM;

// Addresses of the arrays for found passwords & success flags
__device__ __constant__ uint8_t *deviceGlobalFoundPasswordsPlainNTLM;
__device__ __constant__ uint8_t *deviceGlobalFoundPasswordFlagsPlainNTLM;

__device__ __constant__ uint8_t *deviceGlobalStartPointsPlainNTLM;
__device__ __constant__ uint32_t *deviceGlobalStartPasswords32PlainNTLM;

__device__ __constant__ uint32_t deviceNumberStepsToRunPlainNTLM;
__device__ __constant__ uint64_t deviceNumberThreadsPlainNTLM;


/**
 * The loadPassword32 and storePassword32 methods are the preferred method for loading plains.
 * 
 * These work by loading the b0,b1,b2, etc directly from the memory space
 * as plaintext passwords.  At the end of each kernel execution, the current
 * passwords are stored back to the array.  This prevents the need to transfer
 * more plain start points to each thread when the kernel starts again.
 * 
 * @param pa Password initial array
 * @param dt Device number threads
 * @param pl Password length
 */
#define loadNTLMPasswords32(pa, dt, pl) { \
a = thread_index; \
b = pa[a]; \
b0 = (b & 0xff) | ((b & 0xff00) << 8); \
if (pl > 1) {b1 = ((b & 0xff0000) >> 16) | ((b & 0xff000000) >> 8);} \
if (pl > 3) {a += dt; b = pa[a]; b2 = (b & 0xff) | ((b & 0xff00) << 8);} \
if (pl > 5) {b3 = ((b & 0xff0000) >> 16) | ((b & 0xff000000) >> 8);} \
if (pl > 7) {a += dt; b = pa[a]; b4 = (b & 0xff) | ((b & 0xff00) << 8);} \
if (pl > 9) {b5 = ((b & 0xff0000) >> 16) | ((b & 0xff000000) >> 8);} \
if (pl > 11) {a += dt; b6 = pa[a]; b6 = (b & 0xff) | ((b & 0xff00) << 8);} \
if (pl > 13) {b7 = ((b & 0xff0000) >> 16) | ((b & 0xff000000) >> 8);} \
}

#define storeNTLMPasswords32(pa, dt, pl) { \
b = (b0 & 0xff) | ((b0 & 0xff0000) >> 8); \
if (pl > 1) {b |= (b1 & 0xff) << 16 | ((b1 & 0xff0000) << 8);} \
pa[thread_index + 0] = b; \
if (pl > 3) {b = (b2 & 0xff) | ((b2 & 0xff0000) >> 8);} \
if (pl > 5) {b |= (b3 & 0xff) << 16 | ((b3 & 0xff0000) << 8);} \
if (pl > 3) {pa[thread_index + (dt * 1)] = b;} \
if (pl > 7) {b = (b4 & 0xff) | ((b4 & 0xff0000) >> 8);} \
if (pl > 9) {b |= (b5 & 0xff) << 16 | ((b5 & 0xff0000) << 8);} \
if (pl > 7) {pa[thread_index + (dt * 2)] = b;} \
if (pl > 11) {b = (b6 & 0xff) | ((b6 & 0xff0000) >> 8);} \
if (pl > 13) {b |= (b7 & 0xff) << 16 | ((b7 & 0xff0000) << 8);} \
if (pl > 11) {pa[thread_index + (dt * 3)] = b;} \
}


/**
 * Searches for a 128 bit little endian NTLM hash in the global memory.
 *
 * This function takes the calculated hash values (a, b, c, d), the password
 * in b0, b1, etc (as NTLM style!), and the various global memory pointers
 * and searches for the hash.  If it is found, it reports it in the appropriate
 * method.
 *
 * @param a,b,c,d The calculated hash values.
 * @param b0-b7 The registers containing the input block in NTLM format
 * @param sharedBitmapA The address of the 8kb bitmap ideally in shared memory
 * @param deviceGlobalBitmap{A,B,C,D} The addresses (or null) of the device global bitmaps.
 * @param deviceGlobalFoundPasswords The address of the found-password array
 * @param deviceGlobalFoundPasswordFlags The address of the found-password flag array
 * @param deviceGlobalHashlistAddress The address of the 128-bit hash global hashlist
 * @param numberOfHashes The number of hashes being searched for currently
 * @param passwordLength The current password length
 */
__device__ inline void checkHash128LENTLM(uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d,
        uint32_t &b0, uint32_t &b1, uint32_t &b2, uint32_t &b3, 
        uint32_t &b4, uint32_t &b5, uint32_t &b6, uint32_t &b7, 
        uint8_t *sharedBitmapA,
        uint8_t *deviceGlobalBitmapA, uint8_t *deviceGlobalBitmapB,
        uint8_t *deviceGlobalBitmapC, uint8_t *deviceGlobalBitmapD,
        uint8_t *deviceGlobalFoundPasswords, uint8_t *deviceGlobalFoundPasswordFlags,
        uint8_t *deviceGlobalHashlistAddress, uint64_t numberOfHashes,
        uint8_t passwordLength) {
    if ((sharedBitmapA[(a & 0x0000ffff) >> 3] >> (a & 0x00000007)) & 0x00000001) {
        if (!(deviceGlobalBitmapA) || ((deviceGlobalBitmapA[(a >> 3) & 0x07FFFFFF] >> (a & 0x7)) & 0x1)) {
            if (!deviceGlobalBitmapB || ((deviceGlobalBitmapB[(b >> 3) & 0x07FFFFFF] >> (b & 0x7)) & 0x1)) {
                if (!deviceGlobalBitmapC || ((deviceGlobalBitmapC[(c >> 3) & 0x07FFFFFF] >> (c & 0x7)) & 0x1)) {
                    if (!deviceGlobalBitmapD || ((deviceGlobalBitmapD[(d >> 3) & 0x07FFFFFF] >> (d & 0x7)) & 0x1)) {
                        uint32_t search_high, search_low, search_index, current_hash_value;
                        uint32_t *DEVICE_Hashes_32 = (uint32_t *) deviceGlobalHashlistAddress;
                        search_high = numberOfHashes;
                        search_low = 0;
                        while (search_low < search_high) {
                            // Midpoint between search_high and search_low
                            search_index = search_low + (search_high - search_low) / 2;
                            current_hash_value = DEVICE_Hashes_32[4 * search_index];
                            // Adjust search_high & search_low to work through space
                            if (current_hash_value < a) {
                                search_low = search_index + 1;
                            } else {
                                search_high = search_index;
                            }
                            if ((a == current_hash_value) && (search_low < numberOfHashes)) {
                                // Break out of the search loop - search_index is on a value
                                break;
                            }
                        }
                        // Broke out of the while loop

                        // If the loaded value does not match, there are no matches - just return.
                        if (a != current_hash_value) {
                            return;
                        }
                        // We've broken out of the loop, search_index should be on a matching value
                        // Loop while the search index is the same - linear search through this to find all possible
                        // matching passwords.
                        // We first need to move backwards to the beginning, as we may be in the middle of a set of matching hashes.
                        // If we are index 0, do NOT subtract, as we will wrap and this goes poorly.

                        while (search_index && (a == DEVICE_Hashes_32[(search_index - 1) * 4])) {
                            search_index--;
                        }
                        while ((a == DEVICE_Hashes_32[search_index * 4])) {
                            if (b == DEVICE_Hashes_32[search_index * 4 + 1]) {
                                if (c == DEVICE_Hashes_32[search_index * 4 + 2]) {
                                    if (d == DEVICE_Hashes_32[search_index * 4 + 3]) {
                                        // Copy the password to the correct location.
                                        switch (passwordLength) {
                                            case 16:
                                                deviceGlobalFoundPasswords[search_index * passwordLength + 15] = (b7 >> 16) & 0xff;
                                            case 15:
                                                deviceGlobalFoundPasswords[search_index * passwordLength + 14] = (b7 >> 0) & 0xff;
                                            case 14:
                                                deviceGlobalFoundPasswords[search_index * passwordLength + 13] = (b6 >> 16) & 0xff;
                                            case 13:
                                                deviceGlobalFoundPasswords[search_index * passwordLength + 12] = (b6 >> 0) & 0xff;
                                            case 12:
                                                deviceGlobalFoundPasswords[search_index * passwordLength + 11] = (b5 >> 16) & 0xff;
                                            case 11:
                                                deviceGlobalFoundPasswords[search_index * passwordLength + 10] = (b5 >> 0) & 0xff;
                                            case 10:
                                                deviceGlobalFoundPasswords[search_index * passwordLength + 9] = (b4 >> 16) & 0xff;
                                            case 9:
                                                deviceGlobalFoundPasswords[search_index * passwordLength + 8] = (b4 >> 0) & 0xff;
                                            case 8:
                                                deviceGlobalFoundPasswords[search_index * passwordLength + 7] = (b3 >> 16) & 0xff;
                                            case 7:
                                                deviceGlobalFoundPasswords[search_index * passwordLength + 6] = (b3 >> 0) & 0xff;
                                            case 6:
                                                deviceGlobalFoundPasswords[search_index * passwordLength + 5] = (b2 >> 16) & 0xff;
                                            case 5:
                                                deviceGlobalFoundPasswords[search_index * passwordLength + 4] = (b2 >> 0) & 0xff;
                                            case 4:
                                                deviceGlobalFoundPasswords[search_index * passwordLength + 3] = (b1 >> 16) & 0xff;
                                            case 3:
                                                deviceGlobalFoundPasswords[search_index * passwordLength + 2] = (b1 >> 0) & 0xff;
                                            case 2:
                                                deviceGlobalFoundPasswords[search_index * passwordLength + 1] = (b0 >> 16) & 0xff;
                                            case 1:
                                                deviceGlobalFoundPasswords[search_index * passwordLength + 0] = (b0 >> 0) & 0xff;
                                        }
                                        deviceGlobalFoundPasswordFlags[search_index] = (unsigned char) 1;
                                    }
                                }
                            }
                            search_index++;
                        }
                    }
                }
            }
        }
    }
}


#define MAKE_MFN_NTLM_KERNEL1_8LENGTH(pass_len) \
__global__ void MFNHashTypePlainCUDA_NTLM_GeneratedKernel_##pass_len () { \
    uint32_t b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, a, b, c, d; \
    uint32_t password_count = 0, passOffset; \
    __shared__ uint8_t __align__(16) sharedCharsetPlainNTLM[MFN_HASH_TYPE_PLAIN_CUDA_NTLM_MAX_CHARSET_LENGTH * pass_len]; \
    __shared__ uint8_t __align__(16) sharedReverseCharsetPlainNTLM[MFN_HASH_TYPE_PLAIN_CUDA_NTLM_MAX_CHARSET_LENGTH * pass_len]; \
    __shared__ uint8_t __align__(16) sharedCharsetLengthsPlainNTLM[pass_len]; \
    __shared__ uint8_t __align__(16) sharedBitmap[8192]; \
    if (threadIdx.x == 0) { \
        uint64_t *sharedCharset64 = (uint64_t *)sharedCharsetPlainNTLM; \
        uint64_t *deviceCharset64 = (uint64_t *)deviceCharsetPlainNTLM; \
        uint64_t *sharedReverseCharset64 = (uint64_t *)sharedReverseCharsetPlainNTLM; \
        uint64_t *deviceReverseCharset64 = (uint64_t *)deviceReverseCharsetPlainNTLM; \
        uint64_t *constantBitmap64 = (uint64_t *)constantBitmapAPlainNTLM; \
        uint64_t *sharedBitmap64 = (uint64_t *)sharedBitmap; \
        for (a = 0; a < ((MFN_HASH_TYPE_PLAIN_CUDA_NTLM_MAX_CHARSET_LENGTH * pass_len) / 8); a++) { \
            sharedCharset64[a] = deviceCharset64[a]; \
            sharedReverseCharset64[a] = deviceReverseCharset64[a]; \
        } \
        for (a = 0; a < pass_len; a++) { \
            sharedCharsetLengthsPlainNTLM[a] = charsetLengthsPlainNTLM[a]; \
        } \
        for (a = 0; a < 8192 / 8; a++) { \
            sharedBitmap64[a] = constantBitmap64[a]; \
        } \
    } \
    syncthreads(); \
    b0 = b1 = b2 = b3 = b4 = b5 = b6 = b7 = b8 = b9 = b10 = b11 = b12 = b13 = b14 = b15 = 0; \
    b14 = pass_len * 16; \
    loadNTLMPasswords32(deviceGlobalStartPasswords32PlainNTLM, deviceNumberThreadsPlainNTLM, pass_len); \
    while (password_count < deviceNumberStepsToRunPlainNTLM) { \
        MD4_FIRST_2_ROUNDS(); \
        MD4HH (a, b, c, d, b0, MD4S31); \
        MD4HH (d, a, b, c, b8, MD4S32); \
        MD4HH (c, d, a, b, b4, MD4S33); \
        MD4HH (b, c, d, a, b12, MD4S34); \
        MD4HH (a, b, c, d, b2, MD4S31); \
        MD4HH (d, a, b, c, b10, MD4S32); \
        MD4HH (c, d, a, b, b6, MD4S33); \
        MD4HH (b, c, d, a, b14, MD4S34); \
        MD4HH (a, b, c, d, b1, MD4S31); \
        if (pass_len > 6) { \
            MD4HH (d, a, b, c, b9, MD4S32); \
            MD4HH (c, d, a, b, b5, MD4S33); \
            MD4HH (b, c, d, a, b13, MD4S34); \
            MD4HH (a, b, c, d, b3, MD4S31); \
            if (pass_len > 14) { \
                MD4HH (d, a, b, c, b11, MD4S32); \
                MD4HH (c, d, a, b, b7, MD4S33); \
            } \
        } \
        checkHash128LENTLM(a, b, c, d, b0, b1, b2, b3, \
            b4, b5, b6, b7, sharedBitmap, \
            deviceGlobalBitmapAPlainNTLM, deviceGlobalBitmapBPlainNTLM, \
            deviceGlobalBitmapCPlainNTLM, deviceGlobalBitmapDPlainNTLM, \
            deviceGlobalFoundPasswordsPlainNTLM, deviceGlobalFoundPasswordFlagsPlainNTLM, \
            deviceGlobalHashlistAddressPlainNTLM, numberOfHashesPlainNTLM, \
            passwordLengthPlainNTLM); \
        if (charsetLengthsPlainNTLM[1] == 0) { \
                makeMFNSingleIncrementorsNTLM##pass_len (sharedCharsetPlainNTLM, sharedReverseCharsetPlainNTLM, sharedCharsetLengthsPlainNTLM); \
        } else { \
                makeMFNMultipleIncrementorsNTLM##pass_len (sharedCharsetPlainNTLM, sharedReverseCharsetPlainNTLM, sharedCharsetLengthsPlainNTLM); \
        } \
        password_count++; \
    } \
    storeNTLMPasswords32(deviceGlobalStartPasswords32PlainNTLM, deviceNumberThreadsPlainNTLM, pass_len); \
}


MAKE_MFN_NTLM_KERNEL1_8LENGTH(1);
MAKE_MFN_NTLM_KERNEL1_8LENGTH(2);
MAKE_MFN_NTLM_KERNEL1_8LENGTH(3);
MAKE_MFN_NTLM_KERNEL1_8LENGTH(4);
MAKE_MFN_NTLM_KERNEL1_8LENGTH(5);
MAKE_MFN_NTLM_KERNEL1_8LENGTH(6);
MAKE_MFN_NTLM_KERNEL1_8LENGTH(7);
MAKE_MFN_NTLM_KERNEL1_8LENGTH(8);
MAKE_MFN_NTLM_KERNEL1_8LENGTH(9);
MAKE_MFN_NTLM_KERNEL1_8LENGTH(10);
MAKE_MFN_NTLM_KERNEL1_8LENGTH(11);
MAKE_MFN_NTLM_KERNEL1_8LENGTH(12);
MAKE_MFN_NTLM_KERNEL1_8LENGTH(13);
MAKE_MFN_NTLM_KERNEL1_8LENGTH(14);
MAKE_MFN_NTLM_KERNEL1_8LENGTH(15);
MAKE_MFN_NTLM_KERNEL1_8LENGTH(16);

extern "C" cudaError_t MFNHashTypePlainCUDA_NTLM_CopyValueToConstant(
        const char *symbolName, void *hostDataAddress, size_t bytesToCopy) {
    return cudaMemcpyToSymbol(symbolName, hostDataAddress, bytesToCopy);
}

extern "C" cudaError_t MFNHashTypePlainCUDA_NTLM_LaunchKernel(uint32_t passwordLength, uint32_t Blocks, uint32_t Threads) {
    //printf("MFNHashTypePlainCUDA_NTLM_LaunchKernel()\n");
    
    //cudaPrintfInit();
//    cudaError_t errbefore = cudaGetLastError();
//    if( cudaSuccess != errbefore)
//      {
//        printf("MFNHashTypePlainCUDA_NTLM Cuda errorbefore: %s.\n", cudaGetErrorString( errbefore) );
//      } else {
//        printf("No error before\n");
//      }

    
    switch (passwordLength) {
        case 1:
            MFNHashTypePlainCUDA_NTLM_GeneratedKernel_1 <<< Blocks, Threads >>> ();
            break;
        case 2:
            MFNHashTypePlainCUDA_NTLM_GeneratedKernel_2 <<< Blocks, Threads >>> ();
            break;
        case 3:
            MFNHashTypePlainCUDA_NTLM_GeneratedKernel_3 <<< Blocks, Threads >>> ();
            break;
        case 4:
            MFNHashTypePlainCUDA_NTLM_GeneratedKernel_4 <<< Blocks, Threads >>> ();
            break;
        case 5:
            MFNHashTypePlainCUDA_NTLM_GeneratedKernel_5 <<< Blocks, Threads >>> ();
            break;
        case 6:
            MFNHashTypePlainCUDA_NTLM_GeneratedKernel_6 <<< Blocks, Threads >>> ();
            break;
        case 7:
            MFNHashTypePlainCUDA_NTLM_GeneratedKernel_7 <<< Blocks, Threads >>> ();
            break;
        case 8:
            MFNHashTypePlainCUDA_NTLM_GeneratedKernel_8 <<< Blocks, Threads >>> ();
            break;
        case 9:
            MFNHashTypePlainCUDA_NTLM_GeneratedKernel_9 <<< Blocks, Threads >>> ();
            break;
        case 10:
            MFNHashTypePlainCUDA_NTLM_GeneratedKernel_10 <<< Blocks, Threads >>> ();
            break;
        case 11:
            MFNHashTypePlainCUDA_NTLM_GeneratedKernel_11 <<< Blocks, Threads >>> ();
            break;
        case 12:
            MFNHashTypePlainCUDA_NTLM_GeneratedKernel_12 <<< Blocks, Threads >>> ();
            break;
        case 13:
            MFNHashTypePlainCUDA_NTLM_GeneratedKernel_13 <<< Blocks, Threads >>> ();
            break;
        case 14:
            MFNHashTypePlainCUDA_NTLM_GeneratedKernel_14 <<< Blocks, Threads >>> ();
            break;
        case 15:
            MFNHashTypePlainCUDA_NTLM_GeneratedKernel_15 <<< Blocks, Threads >>> ();
            break;
        case 16:
            MFNHashTypePlainCUDA_NTLM_GeneratedKernel_16 <<< Blocks, Threads >>> ();
            break;
        default:
            printf("Password length %d unsupported!\n", passwordLength);
            exit(1);
            break;

    }
    //cudaPrintfDisplay(stdout, true);
    //cudaPrintfEnd();
    cudaError_t err = cudaGetLastError();
    if( cudaSuccess != err)
      {
        printf("MFNHashTypePlainCUDA_NTLM Cuda error: %s.\n", cudaGetErrorString( err) );
      }

    return err;
}
