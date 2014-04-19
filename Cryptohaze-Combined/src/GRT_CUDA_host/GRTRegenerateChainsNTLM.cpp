#include "GRT_CUDA_host/GRTRegenerateChainsNTLM.h"



// Call the constructor of GRTRegenerateChains with len 16
GRTRegenerateChainsNTLM::GRTRegenerateChainsNTLM() : GRTRegenerateChains(16) {
    return;
}

void GRTRegenerateChainsNTLM::copyDataToConstant(GRTRegenerateThreadRunData *data) {
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


    copyNTLMRegenerateDataToConstant(hostCharset, charsetLength,
        this->TableHeader->getChainLength(), this->TableHeader->getTableIndex(),
        numberThreads, this->hostConstantBitmap, this->NumberOfHashes);
    return;

}

void GRTRegenerateChainsNTLM::setNumberOfChainsToRegen(uint32_t numberOfChainsToRegen) {
    setNTLMRegenerateNumberOfChains(numberOfChainsToRegen);
}


void GRTRegenerateChainsNTLM::Launch_CUDA_Kernel(unsigned char *InitialPasswordArray, unsigned char *FoundPasswordArray,
        unsigned char *DeviceHashArray, UINT4 PasswordSpaceOffset, UINT4 StartChainIndex,
        UINT4 StepsToRun, UINT4 charset_offset, unsigned char *successArray, GRTRegenerateThreadRunData *data) {

    // Launch the actual kernel function
    LaunchNTLMRegenerateKernel(this->PasswordLength, this->ThreadData[data->threadID].CUDABlocks,
            this->ThreadData[data->threadID].CUDAThreads, InitialPasswordArray, FoundPasswordArray,
        DeviceHashArray, PasswordSpaceOffset, StartChainIndex,
        StepsToRun, charset_offset, successArray, this->NumberOfHashes);
}
