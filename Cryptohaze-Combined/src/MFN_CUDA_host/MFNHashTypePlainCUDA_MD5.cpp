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

#include "MFN_CUDA_host/MFNHashTypePlainCUDA_MD5.h"
#include "MFN_Common/MFNDebugging.h"

#define MD5ROTATE_RIGHT(x, n) (((x) >> (n)) | ((x) << (32-(n))))

#define REV_II(a,b,c,d,data,shift,constant) \
    a = MD5ROTATE_RIGHT((a - b), shift) - data - constant - (c ^ (b | (~d)));

#define MD5I(x, y, z) ((y) ^ ((x) | (~z)))
#define MD5ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))
#define MD5II(a, b, c, d, x, s, ac) { \
 (a) += MD5I ((b), (c), (d)) + (x) + (uint32_t)(ac); \
 (a) = MD5ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }

#define MD5S41 6
#define MD5S42 10
#define MD5S43 15
#define MD5S44 21

MFNHashTypePlainCUDA_MD5::MFNHashTypePlainCUDA_MD5() :  MFNHashTypePlainCUDA(16) {
    trace_printf("MFNHashTypePlainCUDA_MD5::MFNHashTypePlainCUDA_MD5()\n");
}

void MFNHashTypePlainCUDA_MD5::launchKernel() {
    trace_printf("MFNHashTypePlainCUDA_MD5::launchKernel()\n");

    // Copy the per-step data to the device.
    MFNHashTypePlainCUDA_MD5_CopyValueToConstant("deviceNumberStepsToRunPlainMD5",
        &this->perStep, sizeof(uint32_t));

    //this->printLaunchDebugData(threadData);
    
    MFNHashTypePlainCUDA_MD5_LaunchKernel(this->passwordLength, this->GPUBlocks, this->GPUThreads);
    
}

void MFNHashTypePlainCUDA_MD5::printLaunchDebugData() {
    printf("Debug data for kernel launch: Thread %d, CUDA Device %d\n", this->threadId, this->gpuDeviceId);

    printf("Host value passwordLengthPlainMD5: %d\n", this->passwordLength);
    printf("Host value numberOfHashesPlainMD5: %lu\n", this->activeHashesProcessed.size());
    printf("Host value deviceGlobalHashlistAddressPlainMD5: 0x%16x\n", this->DeviceHashlistAddress);
    printf("Host value deviceGlobalBitmapAPlainMD5: 0x%16x\n", this->DeviceBitmap128mb_a_Address);
    printf("Host value deviceGlobalBitmapBPlainMD5: 0x%16x\n", this->DeviceBitmap128mb_b_Address);
    printf("Host value deviceGlobalBitmapCPlainMD5: 0x%16x\n", this->DeviceBitmap128mb_c_Address);
    printf("Host value deviceGlobalBitmapDPlainMD5: 0x%16x\n", this->DeviceBitmap128mb_d_Address);
    printf("Host value deviceGlobalFoundPasswordsPlainMD5: 0x%16x\n", this->DeviceFoundPasswordsAddress);
    printf("Host value deviceGlobalFoundPasswordFlagsPlainMD5: 0x%16x\n", this->DeviceSuccessAddress);
    printf("Host value deviceGlobalStartPointsPlainMD5: 0x%16x\n", this->DeviceStartPointAddress);
}

std::vector<uint8_t> MFNHashTypePlainCUDA_MD5::preProcessHash(std::vector<uint8_t> rawHash) {
    trace_printf("MFNHashTypePlainCUDA_MD5::preProcessHash()\n");
    uint32_t a, b, c, d;
    uint32_t *hash32 = (uint32_t *)&rawHash[0];

    /*
    printf("MFNHashTypePlainCUDA_MD5::preProcessHash()\n");
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
    
    a -= 0x67452301;
    b -= 0xefcdab89;
    c -= 0x98badcfe;
    d -= 0x10325476;
    
    if (this->passwordLength < 8) {
        REV_II (b, c, d, a, 0x00 /*b9*/, MD5S44, 0xeb86d391); //64
        REV_II (c, d, a, b, 0x00 /*b2*/, MD5S43, 0x2ad7d2bb); //63
        REV_II (d, a, b, c, 0x00 /*b11*/, MD5S42, 0xbd3af235); //62
        REV_II (a, b, c, d, 0x00 /*b4*/, MD5S41, 0xf7537e82); //61
        REV_II (b, c, d, a, 0x00 /*b13*/, MD5S44, 0x4e0811a1); //60
        REV_II (c, d, a, b, 0x00 /*b6*/, MD5S43, 0xa3014314); //59
        REV_II (d, a, b, c, 0x00 /*b15*/, MD5S42, 0xfe2ce6e0); //58
        REV_II (a, b, c, d, 0x00 /*b8*/, MD5S41, 0x6fa87e4f); //57
    } else if (this->passwordLength == 8) {
        REV_II (b, c, d, a, 0x00 /*b9*/, MD5S44, 0xeb86d391); //64
        // Padding bit will be set
        REV_II (c, d, a, b, 0x00000080 /*b2*/, MD5S43, 0x2ad7d2bb); //63
        REV_II (d, a, b, c, 0x00 /*b11*/, MD5S42, 0xbd3af235); //62
        REV_II (a, b, c, d, 0x00 /*b4*/, MD5S41, 0xf7537e82); //61
        REV_II (b, c, d, a, 0x00 /*b13*/, MD5S44, 0x4e0811a1); //60
        REV_II (c, d, a, b, 0x00 /*b6*/, MD5S43, 0xa3014314); //59
        REV_II (d, a, b, c, 0x00 /*b15*/, MD5S42, 0xfe2ce6e0); //58
        REV_II (a, b, c, d, 0x00 /*b8*/, MD5S41, 0x6fa87e4f); //57
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

std::vector<uint8_t> MFNHashTypePlainCUDA_MD5::postProcessHash(std::vector<uint8_t> processedHash) {
    trace_printf("MFNHashTypePlainCUDA_MD5::postProcessHash()\n");
    
    uint32_t a, b, c, d;
    uint32_t *hash32 = (uint32_t *)&processedHash[0];
    
    a = hash32[0];
    b = hash32[1];
    c = hash32[2];
    d = hash32[3];

    if (this->passwordLength < 8) {
        MD5II(a, b, c, d, 0x00, MD5S41, 0x6fa87e4f); /* 57 */
        MD5II(d, a, b, c, 0x00, MD5S42, 0xfe2ce6e0); /* 58 */
        MD5II(c, d, a, b, 0x00, MD5S43, 0xa3014314); /* 59 */
        MD5II(b, c, d, a, 0x00, MD5S44, 0x4e0811a1); /* 60 */
        MD5II(a, b, c, d, 0x00, MD5S41, 0xf7537e82); /* 61 */
        MD5II(d, a, b, c, 0x00, MD5S42, 0xbd3af235); /* 62 */
        MD5II(c, d, a, b, 0x00, MD5S43, 0x2ad7d2bb); /* 63 */
        MD5II(b, c, d, a, 0x00, MD5S44, 0xeb86d391); /* 64 */
    } else if (this->passwordLength == 8) {
        MD5II(a, b, c, d, 0x00, MD5S41, 0x6fa87e4f); /* 57 */
        MD5II(d, a, b, c, 0x00, MD5S42, 0xfe2ce6e0); /* 58 */
        MD5II(c, d, a, b, 0x00, MD5S43, 0xa3014314); /* 59 */
        MD5II(b, c, d, a, 0x00, MD5S44, 0x4e0811a1); /* 60 */
        MD5II(a, b, c, d, 0x00, MD5S41, 0xf7537e82); /* 61 */
        MD5II(d, a, b, c, 0x00, MD5S42, 0xbd3af235); /* 62 */
        MD5II(c, d, a, b, 0x00000080, MD5S43, 0x2ad7d2bb); /* 63 */
        MD5II(b, c, d, a, 0x00, MD5S44, 0xeb86d391); /* 64 */
    }
    
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

void MFNHashTypePlainCUDA_MD5::copyConstantDataToDevice() {
    trace_printf("MFNHashTypePlainCUDA_MD5::copyConstantDataToDevice()\n");

    cudaError_t err;

    // Begin copying constant data to the device.

    MFNHashTypePlainCUDA_MD5_CopyValueToConstant("deviceCharsetPlainMD5",
            &this->charsetForwardLookup[0], this->charsetForwardLookup.size());
    MFNHashTypePlainCUDA_MD5_CopyValueToConstant("deviceReverseCharsetPlainMD5",
            &this->charsetReverseLookup[0], this->charsetReverseLookup.size());
    MFNHashTypePlainCUDA_MD5_CopyValueToConstant("charsetLengthsPlainMD5",
            &this->charsetLengths[0], this->charsetLengths.size());
    MFNHashTypePlainCUDA_MD5_CopyValueToConstant("constantBitmapAPlainMD5",
            &this->sharedBitmap8kb_a[0], 8192);

    uint8_t localPasswordLength = (uint8_t) this->passwordLength;
    MFNHashTypePlainCUDA_MD5_CopyValueToConstant("passwordLengthPlainMD5",
            &localPasswordLength, sizeof(uint8_t));

    uint64_t localNumberHashes = (uint64_t) this->activeHashesProcessed.size();
    MFNHashTypePlainCUDA_MD5_CopyValueToConstant("numberOfHashesPlainMD5",
            &localNumberHashes, sizeof(uint64_t));

    MFNHashTypePlainCUDA_MD5_CopyValueToConstant("deviceGlobalHashlistAddressPlainMD5",
            &this->DeviceHashlistAddress, sizeof(uint8_t *));

    MFNHashTypePlainCUDA_MD5_CopyValueToConstant("deviceGlobalBitmapAPlainMD5",
            &this->DeviceBitmap128mb_a_Address, sizeof(uint8_t *));
    MFNHashTypePlainCUDA_MD5_CopyValueToConstant("deviceGlobalBitmapBPlainMD5",
            &this->DeviceBitmap128mb_b_Address, sizeof(uint8_t *));
    MFNHashTypePlainCUDA_MD5_CopyValueToConstant("deviceGlobalBitmapCPlainMD5",
            &this->DeviceBitmap128mb_c_Address, sizeof(uint8_t *));
    MFNHashTypePlainCUDA_MD5_CopyValueToConstant("deviceGlobalBitmapDPlainMD5",
            &this->DeviceBitmap128mb_d_Address, sizeof(uint8_t *));
    
    MFNHashTypePlainCUDA_MD5_CopyValueToConstant("deviceGlobalFoundPasswordsPlainMD5",
            &this->DeviceFoundPasswordsAddress, sizeof(uint8_t *));
    MFNHashTypePlainCUDA_MD5_CopyValueToConstant("deviceGlobalFoundPasswordFlagsPlainMD5",
            &this->DeviceSuccessAddress, sizeof(uint8_t *));

    MFNHashTypePlainCUDA_MD5_CopyValueToConstant("deviceGlobalStartPointsPlainMD5",
            &this->DeviceStartPointAddress, sizeof(uint8_t *));
    MFNHashTypePlainCUDA_MD5_CopyValueToConstant("deviceGlobalStartPasswords32PlainMD5",
            &this->DeviceStartPasswords32Address, sizeof(uint8_t *));

    uint64_t localNumberThreads = this->GPUBlocks * this->GPUThreads;
    MFNHashTypePlainCUDA_MD5_CopyValueToConstant("deviceNumberThreadsPlainMD5",
            &localNumberThreads, sizeof(uint64_t));

    MFNHashTypePlainCUDA_MD5_CopyValueToConstant("constantBitmapAPlainMD5", 
            &this->sharedBitmap8kb_a[0], this->sharedBitmap8kb_a.size());

    err = cudaGetLastError();
    if (err != cudaSuccess) {
        printf("Thread %d, dev %d: CUDA error 5: %s. Exiting.\n",
                this->threadId, this->gpuDeviceId, cudaGetErrorString( err));
        exit(1);
    }
}