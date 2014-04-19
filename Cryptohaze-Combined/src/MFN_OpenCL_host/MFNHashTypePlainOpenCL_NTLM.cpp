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

#include "MFN_OpenCL_host/MFNHashTypePlainOpenCL_NTLM.h"
#include "GRT_OpenCL_host/GRTCLUtils.h"
#include "MFN_Common/MFNDebugging.h"


#define MD4ROTATE_RIGHT(x, n) (((x) >> (n)) | ((x) << (32-(n))))
#define MD4ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

#define MD4H(x, y, z) ((x) ^ (y) ^ (z))

#define MD4HH(a, b, c, d, x, s) { \
    (a) += MD4H ((b), (c), (d)) + (x) + (uint32_t)0x6ed9eba1; \
    (a) = MD4ROTATE_LEFT ((a), (s)); \
  }

#define REV_HH(a,b,c,d,data,shift) \
    a = MD4ROTATE_RIGHT((a), shift) - data - (uint32_t)0x6ed9eba1 - (b ^ c ^ d);



#define MD4S31 3
#define MD4S32 9
#define MD4S33 11
#define MD4S34 15


MFNHashTypePlainOpenCL_NTLM::MFNHashTypePlainOpenCL_NTLM() :  MFNHashTypePlainOpenCL(16) {
    trace_printf("MFNHashTypePlainOpenCL_NTLM::MFNHashTypePlainOpenCL_NTLM()\n");
}

void MFNHashTypePlainOpenCL_NTLM::launchKernel() {
    trace_printf("MFNHashTypePlainOpenCL_NTLM::launchKernel()\n");
    cl_event kernelLaunchEvent;
    cl_int errorCode;
    size_t numberWorkgroups;
    size_t numberWorkitems;

    numberWorkgroups = this->GPUBlocks * this->GPUThreads;
    numberWorkitems = this->GPUThreads;

    
    klaunch_printf("T %d: Platform/Device: %d/%d\n", this->threadId, this->openCLPlatformId, this->gpuDeviceId);
    klaunch_printf("T %d: Workgroups/Workitems: %d/%d\n", this->threadId, numberWorkgroups, numberWorkitems);

    // Copy the per-step value to the kernel
    errorCode = clSetKernelArg (this->HashKernel, 14, sizeof(cl_uint), &this->perStep);
    if (errorCode != CL_SUCCESS) {
        printf("Error 1: %s\n", print_cl_errstring(errorCode));
        exit(1);
    }

    errorCode = clEnqueueNDRangeKernel(this->OpenCL->getCommandQueue(),
            this->HashKernel,
            1 /* numDims */,
            NULL /* offset */,
            &numberWorkgroups,
            &numberWorkitems,
            NULL, NULL,
            &kernelLaunchEvent);
    
    if (errorCode != CL_SUCCESS) {
        printf("Error 2: %s\n", print_cl_errstring(errorCode));
        exit(1);
    }

    if (clWaitForEvents(1, &kernelLaunchEvent) != CL_SUCCESS) {
        printf("\nError on wait for event!\n");
        fflush(stdout);
    };
}

void MFNHashTypePlainOpenCL_NTLM::printLaunchDebugData() {
//    printf("Debug data for kernel launch: Thread %d, CUDA Device %d\n", this->threadId, this->gpuDeviceId);
//
//    printf("Host value passwordLengthPlainNTLM: %d\n", this->passwordLength);
//    printf("Host value numberOfHashesPlainNTLM: %lu\n", this->activeHashesProcessed.size());
//    printf("Host value deviceGlobalHashlistAddressPlainNTLM: 0x%16x\n", this->DeviceHashlistAddress);
//    printf("Host value deviceGlobalBitmapAPlainNTLM: 0x%16x\n", this->DeviceBitmap128mb_a_Address);
//    printf("Host value deviceGlobalBitmapBPlainNTLM: 0x%16x\n", this->DeviceBitmap128mb_b_Address);
//    printf("Host value deviceGlobalBitmapCPlainNTLM: 0x%16x\n", this->DeviceBitmap128mb_c_Address);
//    printf("Host value deviceGlobalBitmapDPlainNTLM: 0x%16x\n", this->DeviceBitmap128mb_d_Address);
//    printf("Host value deviceGlobalFoundPasswordsPlainNTLM: 0x%16x\n", this->DeviceFoundPasswordsAddress);
//    printf("Host value deviceGlobalFoundPasswordFlagsPlainNTLM: 0x%16x\n", this->DeviceSuccessAddress);
//    printf("Host value deviceGlobalStartPointsPlainNTLM: 0x%16x\n", this->DeviceStartPointAddress);
}

std::vector<uint8_t> MFNHashTypePlainOpenCL_NTLM::preProcessHash(std::vector<uint8_t> rawHash) {
    trace_printf("MFNHashTypePlainOpenCL_NTLM::preProcessHash()\n");
    
    uint32_t a, b, c, d;
    uint32_t *hash32 = (uint32_t *)&rawHash[0];
    
    /*
    printf("Raw Hash: ");
    for (i = 0; i < rawHash.size(); i++) {
        printf("%02x", rawHash[i]);
    }
    printf("\n");
    */
    a = hash32[0];
    b = hash32[1];
    c = hash32[2];
    d = hash32[3];
    
        
    // Always unwind the final constants
    a -= 0x67452301;
    b -= 0xefcdab89;
    c -= 0x98badcfe;
    d -= 0x10325476;

    // Always unwinding b15 - length field, always 0x00
    REV_HH(b, c, d, a, 0x00, MD4S34);

    if (this->passwordLength < 6) {
        // Unwind back through b9, with b3 = 0x00
        REV_HH (c, d, a, b, 0x00, MD4S33);
        REV_HH (d, a, b, c, 0x00, MD4S32);
        REV_HH (a, b, c, d, 0x00, MD4S31);
        REV_HH (b, c, d, a, 0x00, MD4S34);
        REV_HH (c, d, a, b, 0x00, MD4S33);
        REV_HH (d, a, b, c, 0x00, MD4S32);
    } else if (this->passwordLength == 6) {
        // Unwind through b9, with b3 = 0x00000080
        REV_HH (c, d, a, b, 0x00, MD4S33);
        REV_HH (d, a, b, c, 0x00, MD4S32);
        REV_HH (a, b, c, d, 0x80, MD4S31);
        REV_HH (b, c, d, a, 0x00, MD4S34);
        REV_HH (c, d, a, b, 0x00, MD4S33);
        REV_HH (d, a, b, c, 0x00, MD4S32);
    } else if (this->passwordLength < 14) {
        // Rewind through b3 with b7 = 0x00
        REV_HH (c, d, a, b, 0x00, MD4S33);
        REV_HH (d, a, b, c, 0x00, MD4S32);
    } else if (this->passwordLength == 14) {
        // Rewind through b3 with b7 = 0x80
        REV_HH (c, d, a, b, 0x80, MD4S33);
        REV_HH (d, a, b, c, 0x00, MD4S32);
    }
    
    hash32[0] = a;
    hash32[1] = b;
    hash32[2] = c;
    hash32[3] = d;
    
    /*
    printf("Preprocessed Hash: ");
    for (i = 0; i < rawHash.size(); i++) {
        printf("%02x", rawHash[i]);
    }
    printf("\n");
    
    printf("Returning rawHash\n");
    */
    return rawHash;
}

std::vector<uint8_t> MFNHashTypePlainOpenCL_NTLM::postProcessHash(std::vector<uint8_t> processedHash) {
    trace_printf("MFNHashTypePlainOpenCL_NTLM::postProcessHash()\n");

    uint32_t a, b, c, d;
    uint32_t *hash32 = (uint32_t *)&processedHash[0];

    a = hash32[0];
    b = hash32[1];
    c = hash32[2];
    d = hash32[3];
    
    if (this->passwordLength < 6) {
        // Rewind back through b9, with b3 = 0x00
        MD4HH (d, a, b, c, 0x00, MD4S32);
        MD4HH (c, d, a, b, 0x00, MD4S33);
        MD4HH (b, c, d, a, 0x00, MD4S34);
        MD4HH (a, b, c, d, 0x00, MD4S31);
        MD4HH (d, a, b, c, 0x00, MD4S32);
        MD4HH (c, d, a, b, 0x00, MD4S33);
    } else if (this->passwordLength == 6) {
        // Rewind with b3 = 0x80
        MD4HH (d, a, b, c, 0x00, MD4S32);
        MD4HH (c, d, a, b, 0x00, MD4S33);
        MD4HH (b, c, d, a, 0x00, MD4S34);
        MD4HH (a, b, c, d, 0x80, MD4S31);
        MD4HH (d, a, b, c, 0x00, MD4S32);
        MD4HH (c, d, a, b, 0x00, MD4S33);
    } else if (this->passwordLength < 14) {
        // Rewind through b3 with b7 = 0x00
        MD4HH (d, a, b, c, 0x00, MD4S32);
        MD4HH (c, d, a, b, 0x00, MD4S33);
    } else if (this->passwordLength == 14) {
        // Rewind through b3 with b7 = 0x80
        MD4HH (d, a, b, c, 0x80, MD4S32);
        MD4HH (c, d, a, b, 0x00, MD4S33);
    }

    // Always add b15 - will always be 0 (length field)
    MD4HH (b, c, d, a, 0x00, MD4S34);
    a += 0x67452301;
    b += 0xefcdab89;
    c += 0x98badcfe;
    d += 0x10325476;

    hash32[0] = a;
    hash32[1] = b;
    hash32[2] = c;
    hash32[3] = d;


    return processedHash;
}

void MFNHashTypePlainOpenCL_NTLM::copyConstantDataToDevice() {
    trace_printf("MFNHashTypePlainOpenCL_NTLM::copyConstantDataToDevice()\n");

    cl_int errorCode;

    
    // Begin copying constant data to the device.
    
    errorCode = clEnqueueWriteBuffer (this->OpenCL->getCommandQueue(),
            this->DeviceForwardCharsetAddress,
            CL_TRUE /* blocking write */,
            0 /* offset */,
            this->charsetForwardLookup.size() /* bytes to copy */,
            (void *)&this->charsetForwardLookup[0],
            NULL, NULL, NULL /* event list stuff */);
    if (errorCode != CL_SUCCESS) {
        printf("Error: %s\n", print_cl_errstring(errorCode));
        exit(1);
    }

    errorCode = clEnqueueWriteBuffer (this->OpenCL->getCommandQueue(),
            this->DeviceReverseCharsetAddress,
            CL_TRUE /* blocking write */,
            0 /* offset */,
            this->charsetReverseLookup.size() /* bytes to copy */,
            (void *)&this->charsetReverseLookup[0],
            NULL, NULL, NULL /* event list stuff */);
    if (errorCode != CL_SUCCESS) {
        printf("Error: %s\n", print_cl_errstring(errorCode));
        exit(1);
    }

    errorCode = clEnqueueWriteBuffer (this->OpenCL->getCommandQueue(),
            this->DeviceCharsetLengthsAddress,
            CL_TRUE /* blocking write */,
            0 /* offset */,
            this->charsetLengths.size() /* bytes to copy */,
            (void *)&this->charsetLengths[0],
            NULL, NULL, NULL /* event list stuff */);
    if (errorCode != CL_SUCCESS) {
        printf("Error: %s\n", print_cl_errstring(errorCode));
        exit(1);
    }

    errorCode = clEnqueueWriteBuffer (this->OpenCL->getCommandQueue(),
            this->DeviceBitmap8kb_a_Address,
            CL_TRUE /* blocking write */,
            0 /* offset */,
            8192 /* bytes to copy */,
            (void *)&this->sharedBitmap8kb_a[0],
            NULL, NULL, NULL /* event list stuff */);
    if (errorCode != CL_SUCCESS) {
        printf("Error: %s\n", print_cl_errstring(errorCode));
        exit(1);
    }
    
    // Copy the values into a variable that can be accessed as a pointer.
    uint64_t localNumberHashes = this->activeHashesProcessed.size();
    uint64_t localNumberThreads = this->TotalKernelWidth;
    
    errorCode = 0;
    errorCode |= clSetKernelArg (this->HashKernel,  0, sizeof(cl_mem), &this->DeviceForwardCharsetAddress);
    errorCode |= clSetKernelArg (this->HashKernel,  1, sizeof(cl_mem), &this->DeviceReverseCharsetAddress);
    errorCode |= clSetKernelArg (this->HashKernel,  2, sizeof(cl_mem), &this->DeviceCharsetLengthsAddress);
    errorCode |= clSetKernelArg (this->HashKernel,  3, sizeof(cl_mem), &this->DeviceBitmap8kb_a_Address);
    
    errorCode |= clSetKernelArg (this->HashKernel,  4, sizeof(cl_ulong), &localNumberHashes);
    errorCode |= clSetKernelArg (this->HashKernel,  5, sizeof(cl_mem), &this->DeviceHashlistAddress);
    errorCode |= clSetKernelArg (this->HashKernel,  6, sizeof(cl_mem), &this->DeviceFoundPasswordsAddress);
    errorCode |= clSetKernelArg (this->HashKernel,  7, sizeof(cl_mem), &this->DeviceSuccessAddress);

    errorCode |= clSetKernelArg (this->HashKernel,  8, sizeof(cl_mem), &this->DeviceBitmap128mb_a_Address);
    errorCode |= clSetKernelArg (this->HashKernel,  9, sizeof(cl_mem), &this->DeviceBitmap128mb_b_Address);
    errorCode |= clSetKernelArg (this->HashKernel, 10, sizeof(cl_mem), &this->DeviceBitmap128mb_c_Address);
    errorCode |= clSetKernelArg (this->HashKernel, 11, sizeof(cl_mem), &this->DeviceBitmap128mb_d_Address);

    errorCode |= clSetKernelArg (this->HashKernel, 12, sizeof(cl_mem), &this->DeviceStartPointAddress);
    errorCode |= clSetKernelArg (this->HashKernel, 13, sizeof(cl_ulong), &localNumberThreads);
    
    errorCode |= clSetKernelArg (this->HashKernel, 15, sizeof(cl_mem), &this->DeviceStartPasswords32Address);
    

    if (errorCode != CL_SUCCESS) {
        printf("Thread %d, dev %d: OpenCL error 5: %s. Exiting.\n",
                this->threadId, this->gpuDeviceId, print_cl_errstring(errorCode));
        exit(1);
    }
}

std::vector<std::string> MFNHashTypePlainOpenCL_NTLM::getHashFileNames() {
    trace_printf("MFNHashTypePlainOpenCL_NTLM::getHashFileNames()\n");
    
    std::vector<std::string> returnHashFilenames;
    std::string hashFilename;
    
    hashFilename = "./inc/MFN_OpenCL_device/MFN_OpenCL_NTLM_incrementors.h";
    returnHashFilenames.push_back(hashFilename);
    hashFilename = "./src/MFN_OpenCL_device/MFNHashTypePlainOpenCL_NTLM.cl";
    returnHashFilenames.push_back(hashFilename);
    return returnHashFilenames;
}
    
std::string MFNHashTypePlainOpenCL_NTLM::getHashKernelName() {
    trace_printf("MFNHashTypePlainOpenCL_NTLM::getHashKernelName()\n");
    
    std::string hashKernel = "MFNHashTypePlainOpenCL_NTLM";
    return hashKernel;
}
