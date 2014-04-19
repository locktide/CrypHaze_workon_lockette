/*
Cryptohaze GPU Rainbow Tables
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

// CUDA MD5 kernels for table generation.

// This is here so Netbeans doesn't error-spam my IDE
#if !defined(__CUDACC__)
    // define the keywords, so that the IDE does not complain about them
    #define __global__
    #define __device__
    #define __shared__
    #define __constant__
    #define blockIdx.x 1
    #define blockDim.x 1
    #define threadIdx.x 1
#endif

#include <cuda.h>
#include <cutil.h>
#include <cuda_runtime_api.h>

#ifdef _WIN32
#include "windows/stdint.h"
#else
#include <stdint.h>
#endif

// Some CUDA variables
__device__ __constant__ unsigned char MD5_Generate_Device_Charset_Constant[512]; // Constant space for charset
__device__ __constant__ uint32_t MD5_Generate_Device_Charset_Length; // Character set length
__device__ __constant__ uint32_t MD5_Generate_Device_Chain_Length; // May as well pull it from constant memory... faster.
__device__ __constant__ uint32_t MD5_Generate_Device_Number_Of_Chains; // Same, may as well be constant.
__device__ __constant__ uint32_t MD5_Generate_Device_Table_Index;
__device__ __constant__ uint32_t MD5_Generate_Device_Number_Of_Threads; // It needs this, and can't easily calculate it


#include "../../inc/CUDA_Common/CUDA_MD5.h"
#include "../../inc/CUDA_Common/Hash_Common.h"
#include "../../inc/GRT_CUDA_device/CUDA_Reduction_Functions.h"
#include "../../inc/GRT_CUDA_device/CUDA_Load_Store_Registers.h"

/*
__global__ void MakeMD5ChainLen10(unsigned char *InitialPasswordArray, unsigned char *OutputHashArray,
    uint32_t PasswordSpaceOffset, uint32_t StartChainIndex, uint32_t StepsToRun, uint32_t charset_offset) {

    // Needed variables for generation
    uint32_t CurrentStep, PassCount, password_index;

    // Hash variables
    uint32_t b0,b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15;
    uint32_t a,b,c,d;

    // Word-width access to the arrays
    uint32_t *InitialArray32;
    uint32_t *OutputArray32;
    // 32-bit accesses to the hash arrays
    InitialArray32 = (uint32_t *)InitialPasswordArray;
    OutputArray32 = (uint32_t *)OutputHashArray;


    __shared__ char charset[512];

    // Generic "copy charset to shared memory" function
    copySingleCharsetToShared(charset, Device_Charset_Constant);

    // Figure out which password we are working on.
    password_index = ((blockIdx.x*blockDim.x + threadIdx.x) + (PasswordSpaceOffset * Device_Number_Of_Threads));

    // Return if this thread is working on something beyond the end of the password space
    if (password_index >= Device_Number_Of_Chains) {
        return;
    }

    clearB0toB15(b0,b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15);
    // Load b0/b1 out of memory
    b0 = (uint32_t)InitialArray32[0 * Device_Number_Of_Chains + password_index];
    b1 = (uint32_t)InitialArray32[1 * Device_Number_Of_Chains + password_index];
    b2 = (uint32_t)InitialArray32[2 * Device_Number_Of_Chains + password_index];

    for (PassCount = 0; PassCount < StepsToRun; PassCount++) {
        CurrentStep = PassCount + StartChainIndex;

        padMDHash(10, b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15);
        CUDA_MD5(b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, a, b, c, d);
        reduceSingleCharsetNormal(b0, b1, b2, a, b, c, d, CurrentStep, charset, charset_offset, 10, Device_Table_Index);

        charset_offset++;
        if (charset_offset >= Device_Charset_Length) {
            charset_offset = 0;
        }
    }
    // Done with the number of steps we need to run

    // If we are done (or have somehow overflowed), store the result
    if (CurrentStep >= (Device_Chain_Length - 1)) {
        OutputArray32[0 * Device_Number_Of_Chains + password_index] = a;
        OutputArray32[1 * Device_Number_Of_Chains + password_index] = b;
        OutputArray32[2 * Device_Number_Of_Chains + password_index] = c;
        OutputArray32[3 * Device_Number_Of_Chains + password_index] = d;
    }
    // Else, store the b0/b1 values back to the initial array for the next loop
    else {
        InitialArray32[0 * Device_Number_Of_Chains + password_index] = b0;
        InitialArray32[1 * Device_Number_Of_Chains + password_index] = b1;
        InitialArray32[2 * Device_Number_Of_Chains + password_index] = b2;
    }
}
*/



#define CREATE_MD5_GEN_KERNEL(length) \
__global__ void MakeMD5ChainLen##length(unsigned char *InitialPasswordArray, unsigned char *OutputHashArray, \
    uint32_t PasswordSpaceOffset, uint32_t StartChainIndex, uint32_t StepsToRun, uint32_t charset_offset) { \
    const int pass_length = length; \
    uint32_t CurrentStep, PassCount, password_index; \
    uint32_t b0,b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15; \
    uint32_t a,b,c,d; \
    uint32_t *InitialArray32; \
    uint32_t *OutputArray32; \
    InitialArray32 = (uint32_t *)InitialPasswordArray; \
    OutputArray32 = (uint32_t *)OutputHashArray; \
    __shared__ char charset[512]; \
    copySingleCharsetToShared(charset, MD5_Generate_Device_Charset_Constant); \
    password_index = ((blockIdx.x*blockDim.x + threadIdx.x) + (PasswordSpaceOffset * MD5_Generate_Device_Number_Of_Threads)); \
    if (password_index >= MD5_Generate_Device_Number_Of_Chains) { \
        return; \
    } \
    clearB0toB15(b0,b1,b2,b3,b4,b5,b6,b7,b8,b9,b10,b11,b12,b13,b14,b15); \
    LoadMD5RegistersFromGlobalMemory(b0,b1,b2,b3,b4,b5,b6,b7,b8,b9,b10,b11,b12,b13,b14,b15, \
        InitialArray32, MD5_Generate_Device_Number_Of_Chains, password_index, pass_length); \
    for (PassCount = 0; PassCount < StepsToRun; PassCount++) { \
        CurrentStep = PassCount + StartChainIndex; \
        padMDHash(pass_length, b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15); \
        CUDA_MD5(b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, a, b, c, d); \
        reduceSingleCharsetNormal(b0, b1, b2, a, b, c, d, CurrentStep, charset, charset_offset, pass_length, MD5_Generate_Device_Table_Index); \
        charset_offset++; \
        if (charset_offset >= MD5_Generate_Device_Charset_Length) { \
            charset_offset = 0; \
        } \
    } \
    if (CurrentStep >= (MD5_Generate_Device_Chain_Length - 1)) { \
        OutputArray32[0 * MD5_Generate_Device_Number_Of_Chains + password_index] = a; \
        OutputArray32[1 * MD5_Generate_Device_Number_Of_Chains + password_index] = b; \
        OutputArray32[2 * MD5_Generate_Device_Number_Of_Chains + password_index] = c; \
        OutputArray32[3 * MD5_Generate_Device_Number_Of_Chains + password_index] = d; \
    } \
    else { \
    SaveMD5RegistersIntoGlobalMemory(b0,b1,b2,b3,b4,b5,b6,b7,b8,b9,b10,b11,b12,b13,b14,b15, \
        InitialArray32, MD5_Generate_Device_Number_Of_Chains, password_index, pass_length); \
    } \
}




CREATE_MD5_GEN_KERNEL(6)
CREATE_MD5_GEN_KERNEL(7)
CREATE_MD5_GEN_KERNEL(8)
CREATE_MD5_GEN_KERNEL(9)
CREATE_MD5_GEN_KERNEL(10)




extern "C" void copyConstantsToMD5(unsigned char *HOST_Charset, uint32_t HOST_Charset_Length,
    uint32_t HOST_Chain_Length, uint32_t HOST_Number_Of_Chains, uint32_t HOST_Table_Index,
    uint32_t HOST_Number_Of_Threads) {

    cudaMemcpyToSymbol("MD5_Generate_Device_Charset_Constant",HOST_Charset, 512);
    cudaMemcpyToSymbol("MD5_Generate_Device_Charset_Length", &HOST_Charset_Length, sizeof(uint32_t));

    // Copy general table parameters to constant space
    cudaMemcpyToSymbol("MD5_Generate_Device_Chain_Length", &HOST_Chain_Length, sizeof(uint32_t));
    cudaMemcpyToSymbol("MD5_Generate_Device_Number_Of_Chains", &HOST_Number_Of_Chains, sizeof(uint32_t));
    cudaMemcpyToSymbol("MD5_Generate_Device_Table_Index", &HOST_Table_Index, sizeof(uint32_t));
    cudaMemcpyToSymbol("MD5_Generate_Device_Number_Of_Threads", &HOST_Number_Of_Threads, sizeof(HOST_Number_Of_Threads));
}


extern "C" void LaunchGenerateKernelMD5(int passwordLength, uint32_t CUDA_Blocks,
        uint32_t CUDA_Threads, unsigned char *DEVICE_Initial_Passwords,
        unsigned char *DEVICE_End_Hashes, uint32_t PasswordSpaceOffset,
        uint32_t CurrentChainStartOffset, uint32_t StepsPerInvocation, uint32_t CharsetOffset) {
    switch (passwordLength) {
            case 6:
                MakeMD5ChainLen6 <<< CUDA_Blocks, CUDA_Threads >>>
                    (DEVICE_Initial_Passwords, DEVICE_End_Hashes, PasswordSpaceOffset,
                    CurrentChainStartOffset, StepsPerInvocation, CharsetOffset);
                break;
            case 7:
                MakeMD5ChainLen7 <<< CUDA_Blocks, CUDA_Threads >>>
                    (DEVICE_Initial_Passwords, DEVICE_End_Hashes, PasswordSpaceOffset,
                    CurrentChainStartOffset, StepsPerInvocation, CharsetOffset);
                break;
            case 8:
                MakeMD5ChainLen8 <<< CUDA_Blocks, CUDA_Threads >>>
                    (DEVICE_Initial_Passwords, DEVICE_End_Hashes, PasswordSpaceOffset,
                    CurrentChainStartOffset, StepsPerInvocation, CharsetOffset);
                break;
            case 9:
                MakeMD5ChainLen9 <<< CUDA_Blocks, CUDA_Threads >>>
                    (DEVICE_Initial_Passwords, DEVICE_End_Hashes, PasswordSpaceOffset,
                    CurrentChainStartOffset, StepsPerInvocation, CharsetOffset);
                break;
            case 10:
                MakeMD5ChainLen10 <<< CUDA_Blocks, CUDA_Threads >>>
                    (DEVICE_Initial_Passwords, DEVICE_End_Hashes, PasswordSpaceOffset,
                    CurrentChainStartOffset, StepsPerInvocation, CharsetOffset);
                break;
            default:
                printf("Password length %d not supported!", passwordLength);
                exit(1);
        }
}