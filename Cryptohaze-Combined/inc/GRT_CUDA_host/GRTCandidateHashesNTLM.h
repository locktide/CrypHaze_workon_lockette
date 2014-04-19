


#include "GRT_CUDA_host/GRTCandidateHashes.h"

typedef uint32_t UINT4;

extern "C" void copyNTLMCandidateDataToConstant(char *hostCharset, UINT4 hostCharsetLength,
        UINT4 hostChainLength, UINT4 hostTableIndex, UINT4 hostNumberOfThreads);

extern "C" void copyNTLMHashDataToConstant(unsigned char *hash);

extern "C" void LaunchNTLMCandidateHashKernel(int PasswordLength, int CUDA_Blocks, int CUDA_Threads,
        unsigned char *DEVICE_End_Hashes, UINT4 ThreadSpaceOffset, UINT4 StartStep, UINT4 StepsToRun);


class GRTCandidateHashesNTLM : public GRTCandidateHashes {
public:
    GRTCandidateHashesNTLM();
    void copyDataToConstant(GRTThreadRunData *data);
    void runCandidateHashKernel(int PasswordLength, int CUDA_Blocks, int CUDA_Threads,
        unsigned char *DEVICE_End_Hashes, UINT4 ThreadSpaceOffset, UINT4 StartStep, UINT4 StepsToRun);
    void setHashInConstant(unsigned char *hash);
};