


#include "GRT_CUDA_host/GRTCandidateHashes.h"

typedef uint32_t UINT4;

extern "C" void copyMD5CandidateDataToConstant(char *hostCharset, UINT4 hostCharsetLength,
        UINT4 hostChainLength, UINT4 hostTableIndex, UINT4 hostNumberOfThreads);

extern "C" void copyMD5HashDataToConstant(unsigned char *hash);

extern "C" void LaunchMD5CandidateHashKernel(int PasswordLength, int CUDA_Blocks, int CUDA_Threads,
        unsigned char *DEVICE_End_Hashes, UINT4 ThreadSpaceOffset, UINT4 StartStep, UINT4 StepsToRun);


class GRTCandidateHashesMD5 : public GRTCandidateHashes {
public:
    GRTCandidateHashesMD5();
    void copyDataToConstant(GRTThreadRunData *data);
    void runCandidateHashKernel(int PasswordLength, int CUDA_Blocks, int CUDA_Threads,
        unsigned char *DEVICE_End_Hashes, UINT4 ThreadSpaceOffset, UINT4 StartStep, UINT4 StepsToRun);
    void setHashInConstant(unsigned char *hash);
};