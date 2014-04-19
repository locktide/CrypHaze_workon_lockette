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

#include "GRT_CUDA_host/GRTGenerateTableNTLM.h"
#include <stdio.h>

extern "C" void copyConstantsToNTLM(char *HOST_Charset, UINT4 HOST_Charset_Length,
    UINT4 HOST_Chain_Length, UINT4 HOST_Number_Of_Chains, UINT4 HOST_Table_Index,
    UINT4 HOST_Number_Of_Threads);

extern "C" void LaunchGenerateKernelNTLM(int passwordLength, UINT4 CUDA_Blocks, UINT4 CUDA_Threads,
        unsigned char *DEVICE_Initial_Passwords,
    unsigned char *DEVICE_End_Hashes, UINT4 PasswordSpaceOffset, UINT4 CurrentChainStartOffset,
    UINT4 StepsPerInvocation, UINT4 CharsetOffset);


// Copy the constant values to the GPU.  This is per-hash-implementation specific.
void GRTGenerateTableNTLM::copyConstantsToGPU(char *HOST_Charset, UINT4 HOST_Charset_Length,
        UINT4 HOST_Chain_Length, UINT4 HOST_Number_Of_Chains, UINT4 HOST_Table_Index,
        UINT4 HOST_Number_Of_Threads) {

    copyConstantsToNTLM(HOST_Charset, HOST_Charset_Length,
    HOST_Chain_Length, HOST_Number_Of_Chains, HOST_Table_Index,
    HOST_Number_Of_Threads);
}


GRTGenerateTableNTLM::GRTGenerateTableNTLM() : GRTGenerateTable(16, 16) {
    return;
}

void GRTGenerateTableNTLM::runKernel(int passwordLength, UINT4 CUDA_Blocks,
        UINT4 CUDA_Threads, unsigned char *DEVICE_Initial_Passwords,
        unsigned char *DEVICE_End_Hashes, UINT4 PasswordSpaceOffset,
        UINT4 CurrentChainStartOffset, UINT4 StepsPerInvocation, UINT4 CharsetOffset) {
    LaunchGenerateKernelNTLM(passwordLength, CUDA_Blocks,
        CUDA_Threads, DEVICE_Initial_Passwords,
        DEVICE_End_Hashes, PasswordSpaceOffset,
        CurrentChainStartOffset, StepsPerInvocation, CharsetOffset);
}
