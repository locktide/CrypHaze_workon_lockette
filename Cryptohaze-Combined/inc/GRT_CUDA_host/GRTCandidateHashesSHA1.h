


#include "GRT_CUDA_host/GRTCandidateHashes.h"

typedef uint32_t UINT4;

extern "C" void copySHA1CandidateDataToConstant(char *hostCharset, UINT4 hostCharsetLength,
        UINT4 hostChainLength, UINT4 hostTableIndex, UINT4 hostNumberOfThreads);

extern "C" void copySHA1HashDataToConstant(unsigned char *hash);

extern "C" void LaunchSHA1CandidateHashKernel(int PasswordLength, int CUDA_Blocks, int CUDA_Threads,
        unsigned char *DEVICE_End_Hashes, UINT4 ThreadSpaceOffset, UINT4 StartStep, UINT4 StepsToRun);


class GRTCandidateHashesSHA1 : public GRTCandidateHashes {
public:
    GRTCandidateHashesSHA1();
    void copyDataToConstant(GRTThreadRunData *data);
    void runCandidateHashKernel(int PasswordLength, int CUDA_Blocks, int CUDA_Threads,
        unsigned char *DEVICE_End_Hashes, UINT4 ThreadSpaceOffset, UINT4 StartStep, UINT4 StepsToRun);
    void setHashInConstant(unsigned char *hash);
};