#include "GRT_CUDA_host/GRTRegenerateChainsSHA1.h"



// Call the constructor of GRTRegenerateChains with len 20
GRTRegenerateChainsSHA1::GRTRegenerateChainsSHA1() : GRTRegenerateChains(20) {
    return;
}

void GRTRegenerateChainsSHA1::copyDataToConstant(GRTRegenerateThreadRunData *data) {
    char hostCharset[512]; // The 512 byte array copied to the GPU
    int i;
    char** hostCharset2D; // The 16x256 array of characters
    uint32_t charsetLength;
    char *CharsetLengths;
    uint32_t numberThreads;

    hostCharset2D = this->TableHeader->getCharset();
    CharsetLengths = this->TableHeader->getCharsetLengths();
    numberThreads = this->ThreadData[data->threadID].CUDABlocks *
            this->ThreadData[data->threadID].CUDAThreads;

    charsetLength = CharsetLengths[0];

    //printf("Charset length: %d\n", charsetLength);

    for (i = 0; i < 512; i++) {
        hostCharset[i] = hostCharset2D[0][i % charsetLength];
    }


    copySHA1RegenerateDataToConstant(hostCharset, charsetLength,
        this->TableHeader->getChainLength(), this->TableHeader->getTableIndex(),
        numberThreads, this->hostConstantBitmap, this->NumberOfHashes);
    return;

}

void GRTRegenerateChainsSHA1::setNumberOfChainsToRegen(uint32_t numberOfChainsToRegen) {
    setSHA1RegenerateNumberOfChains(numberOfChainsToRegen);
}


void GRTRegenerateChainsSHA1::Launch_CUDA_Kernel(unsigned char *InitialPasswordArray, unsigned char *FoundPasswordArray,
        unsigned char *DeviceHashArray, UINT4 PasswordSpaceOffset, UINT4 StartChainIndex,
        UINT4 StepsToRun, UINT4 charset_offset, unsigned char *successArray, GRTRegenerateThreadRunData *data) {

    // Launch the actual kernel function
    LaunchSHA1RegenerateKernel(this->PasswordLength, this->ThreadData[data->threadID].CUDABlocks,
            this->ThreadData[data->threadID].CUDAThreads, InitialPasswordArray, FoundPasswordArray,
        DeviceHashArray, PasswordSpaceOffset, StartChainIndex,
        StepsToRun, charset_offset, successArray, this->NumberOfHashes);
}
