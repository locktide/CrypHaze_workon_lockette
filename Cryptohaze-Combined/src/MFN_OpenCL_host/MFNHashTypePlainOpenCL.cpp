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


#include "MFN_OpenCL_host/MFNHashTypePlainOpenCL.h"
#include "MFN_Common/MFNCommandLineData.h"
#include "MFN_Common/MFNMultiforcerClassFactory.h"
#include "CH_HashFiles/CHHashFileVPlain.h"
#include "MFN_Common/MFNDisplay.h"
#include "OpenCL_Common/GRTOpenCL.h"
#include "GRT_OpenCL_host/GRTCLUtils.h"
#include "MFN_Common/MFNDebugging.h"
#include "MFN_Common/MFNDefines.h"


#define MFN_HASH_TYPE_PLAIN_CUDA_MD5_MAX_CHARSET_LENGTH 128

extern MFNClassFactory MultiforcerGlobalClassFactory;


MFNHashTypePlainOpenCL::MFNHashTypePlainOpenCL(int hashLengthBytes) :  MFNHashTypePlain(hashLengthBytes) {
    trace_printf("MFNHashTypePlainOpenCL::MFNHashTypePlainOpenCL(%d)\n", hashLengthBytes);

    this->MFNHashTypeMutex.lock();
    this->threadId = MultiforcerGlobalClassFactory.getDisplayClass()->getFreeThreadId(GPU_THREAD);
    this->numberThreads++;
    trace_printf("MFNHashType GPU/OpenCL Thread ID %d\n", this->threadId);
    this->MFNHashTypeMutex.unlock();

}

MFNHashTypePlainOpenCL::~MFNHashTypePlainOpenCL() {
    trace_printf("MFNHashTypePlainOpenCL::~MFNHashTypePlainOpenCL()\n");
    delete this->OpenCL;
}

void MFNHashTypePlainOpenCL::setupDevice() {
    trace_printf("CHHashTypeVPlainCUDA::setupDevice()\n");
    char buildOptions[1024];
    cl_int errorCode;

    // Set the OpenCL platform & device
    trace_printf("Thread %d setting OpenCL platform/device to %d, %d\n",
            this->threadId, this->openCLPlatformId, this->gpuDeviceId);
    this->OpenCL->selectPlatformById(this->openCLPlatformId);
    this->OpenCL->selectDeviceById(this->gpuDeviceId);
    
    /**
     * Handle generating the kernels.  This involves building with the specified
     * password length, vector width, and BFI_INT status.
     */

    if (MultiforcerGlobalClassFactory.getCommandlinedataClass()->GetUseBfiInt()) {
        // BFI_INT patching - pass BITALIGN to kernel
        sprintf(buildOptions, "-D PASSWORD_LENGTH=%d -D VECTOR_WIDTH=%d -D BITALIGN=1",
            this->passwordLength, this->VectorWidth);
    } else {
        // No BFI_INT patching.
        sprintf(buildOptions, "-D PASSWORD_LENGTH=%d -D VECTOR_WIDTH=%d",
                this->passwordLength, this->VectorWidth);
    }
    this->OpenCL->buildProgramFromManySourcesConcat(this->getHashFileNames(), buildOptions);

    // If the BFI_INT patching is being used, patch the generated binary.
    if (MultiforcerGlobalClassFactory.getCommandlinedataClass()->GetUseBfiInt()) {
        this->OpenCL->doAMDBFIPatch();
    }

    this->HashProgram = this->OpenCL->getProgram();
    this->HashKernel = clCreateKernel (this->HashProgram, this->getHashKernelName().c_str(), &errorCode);

    if (errorCode != CL_SUCCESS) {
        printf("Error: %s\n", print_cl_errstring(errorCode));
        exit(1);
    }

}


void MFNHashTypePlainOpenCL::teardownDevice() {
    trace_printf("MFNHashTypePlainOpenCL::teardownDevice()\n");
}

void MFNHashTypePlainOpenCL::allocateThreadAndDeviceMemory() {
    trace_printf("MFNHashTypePlainOpenCL::allocateThreadAndDeviceMemory()\n");

    /**
     * Error variable - stores the result of the various mallocs & such.
     */
    cl_int errorCode;
    /*
     * Malloc the device hashlist space.  This is the number of available hashes
     * times the hash length in bytes.  The data will be copied later.
     */
    memalloc_printf("Attempting to openclMalloc %d bytes for device hashlist for thread %d.\n",
            this->activeHashesProcessed.size() * this->hashLengthBytes, this->threadId);
    this->DeviceHashlistAddress =
            clCreateBuffer (this->OpenCL->getContext(),
            CL_MEM_READ_ONLY,
            this->activeHashesProcessed.size() * this->hashLengthBytes,
            NULL,
            &errorCode);
    if (errorCode != CL_SUCCESS) {
        printf("Unable to allocate %d bytes for device hashlist!  Exiting!\n",
                this->activeHashesProcessed.size() * this->hashLengthBytes);
        printf("Error: %s\n", print_cl_errstring(errorCode));
        exit(1);
    }

    /*
     * Allocate the host/device space for the success list (flags for found passwords).
     * This is a byte per password.  To avoid atomic write issues, each password
     * gets a full addressible byte, and the GPU handles the dependencies between
     * multiple threads trying to set a flag in the same segment of memory.
     *
     * On the host, it will be allocated as mapped memory if we are using zerocopy.
     *
     * As this region of memory is frequently copied back to the host, mapping it
     * improves performance.  In theory.
     */
    memalloc_printf("Attempting to cudaHostAlloc %d bytes for HostSuccess\n",
            this->activeHashesProcessed.size());
    this->HostSuccessAddress = new uint8_t [this->activeHashesProcessed.size()];
    memset(this->HostSuccessAddress, 0, this->activeHashesProcessed.size());

    // Allocate memory for the reported flags.
    this->HostSuccessReportedAddress = new uint8_t [this->activeHashesProcessed.size()];
    memset(this->HostSuccessReportedAddress, 0, this->activeHashesProcessed.size());

    // Allocate device memory for the "reported" flags, and copy in the zeroed 
    // host memory for this region.
    this->DeviceSuccessAddress =
            clCreateBuffer (this->OpenCL->getContext(),
            CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR,
            this->activeHashesProcessed.size(),
            this->HostSuccessAddress,
            &errorCode);
    
    if (errorCode != CL_SUCCESS) {
        printf("Unable to allocate %d bytes for device successlist!  Exiting!\n",
                this->activeHashesProcessed.size());
        printf("Error: %s\n", print_cl_errstring(errorCode));
        exit(1);
    }

    /*
     * Allocate memory for the found passwords.  As this is commonly copied
     * back and forth, it should be made zero copy if requested.
     *
     * This requires (number hashes * passwordLength) bytes of data.
     */

    this->HostFoundPasswordsAddress = new uint8_t [this->passwordLength * 
            this->activeHashesProcessed.size()];
    // Clear the host found password space.
    memset(this->HostFoundPasswordsAddress, 0,
            this->passwordLength * this->activeHashesProcessed.size());

    this->DeviceFoundPasswordsAddress =
            clCreateBuffer (this->OpenCL->getContext(),
            CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR,
            this->passwordLength * this->activeHashesProcessed.size(),
            this->HostFoundPasswordsAddress,
            &errorCode);
    
    if (errorCode != CL_SUCCESS) {
        printf("Unable to allocate %d bytes for device passwordlist!  Exiting!\n",
                this->passwordLength * this->activeHashesProcessed.size());
        printf("Error: %s\n", print_cl_errstring(errorCode));
        exit(1);
    }


    /**
     * Allocate space for host and device start positions.  To improve performance,
     * this space is now aligned for improved coalescing performance.  All the
     * position 0 elements are together, followed by all the position 1 elements,
     * etc.
     *
     * This memory can be allocated as write combined, as it is not read by
     * the host ever - only written.  Since it is regularly transferred to the
     * GPU, this should help improve performance.
     */

    this->HostStartPointAddress = new uint8_t [this->TotalKernelWidth * 
            this->passwordLength];

    this->DeviceStartPointAddress =
            clCreateBuffer (this->OpenCL->getContext(),
            CL_MEM_READ_ONLY,
            this->TotalKernelWidth * this->passwordLength,
            NULL,
            &errorCode);
    if (errorCode != CL_SUCCESS) {
        printf("Unable to allocate %d bytes for device start points!  Exiting!\n",
                this->TotalKernelWidth * this->passwordLength);
        printf("Error: %s\n", print_cl_errstring(errorCode));
        exit(1);
    }
    
    this->DeviceStartPasswords32Address =
            clCreateBuffer (this->OpenCL->getContext(),
            CL_MEM_READ_ONLY,
            this->TotalKernelWidth * this->passwordLengthWords,
            NULL,
            &errorCode);
    if (errorCode != CL_SUCCESS) {
        printf("Unable to allocate %d bytes for device start passwords!  Exiting!\n",
                this->TotalKernelWidth * this->passwordLengthWords);
        printf("Error: %s\n", print_cl_errstring(errorCode));
        exit(1);
    }

    /**
     * Allocate memory for the things that are considered constant in CUDA
     * and not stored in global memory.  For OpenCL, these are stored in a 
     * constant-tagged chunk of global memory (or something) and therefore
     * need to have space allocated in global memory.
     */
    
    this->DeviceBitmap8kb_a_Address =
            clCreateBuffer (this->OpenCL->getContext(),
            CL_MEM_READ_ONLY,
            8192,
            NULL,
            &errorCode);
    if (errorCode == CL_SUCCESS) {
        memalloc_printf("Successfully allocated 8kb Bitmap A\n");
    } else {
        printf("Unable to allocate 8kb bitmap A\n");
        printf("Error: %s\n", print_cl_errstring(errorCode));
        exit(1);
    }

    this->DeviceForwardCharsetAddress =
            clCreateBuffer (this->OpenCL->getContext(),
            CL_MEM_READ_ONLY,
            MFN_HASH_TYPE_PLAIN_CUDA_MD5_MAX_CHARSET_LENGTH * this->passwordLength,
            NULL,
            &errorCode);
    if (errorCode != CL_SUCCESS) {
        printf("Unable to allocate forward charset\n");
        printf("Error: %s\n", print_cl_errstring(errorCode));
        exit(1);
    }
    
    this->DeviceReverseCharsetAddress =
            clCreateBuffer (this->OpenCL->getContext(),
            CL_MEM_READ_ONLY,
            MFN_HASH_TYPE_PLAIN_CUDA_MD5_MAX_CHARSET_LENGTH * this->passwordLength,
            NULL,
            &errorCode);
    if (errorCode != CL_SUCCESS) {
        printf("Unable to allocate reverse charset\n");
        printf("Error: %s\n", print_cl_errstring(errorCode));
        exit(1);
    }
    
    this->DeviceCharsetLengthsAddress =
            clCreateBuffer (this->OpenCL->getContext(),
            CL_MEM_READ_ONLY,
            this->passwordLength,
            NULL,
            &errorCode);
    if (errorCode != CL_SUCCESS) {
        printf("Unable to allocate charset lengths\n");
        printf("Error: %s\n", print_cl_errstring(errorCode));
        exit(1);
    }
    
    
    
    /**
     * Finally, attempt to allocate space for the giant device bitmaps.  There
     * are 4x128MB bitmaps, and any number can be allocated.  If they are not
     * fully allocated, their address is set to null as a indicator to the device
     * that there is no data present.  Attempt to allocate as many as possible.
     *
     * This will be accessed regularly, so should probably not be zero copy.
     * Also, I'm not sure how mapping host memory into multiple threads would
     * work.  Typically, if the GPU doesn't have enough RAM for the full
     * set of bitmaps, it's a laptop, and therefore may be short on host RAM
     * for the pinned access.
     *
     */
    this->DeviceBitmap128mb_a_Address =
            clCreateBuffer (this->OpenCL->getContext(),
            CL_MEM_READ_ONLY,
            128 * 1024 * 1024,
            NULL,
            &errorCode);
    if (errorCode == CL_SUCCESS) {
        memalloc_printf("Successfully allocated Bitmap A\n");
    } else {
        memalloc_printf("Unable to allocate 128MB bitmap A\n");
        this->DeviceBitmap128mb_a_Address = 0;
    }
    
    this->DeviceBitmap128mb_b_Address =
            clCreateBuffer (this->OpenCL->getContext(),
            CL_MEM_READ_ONLY,
            128 * 1024 * 1024,
            NULL,
            &errorCode);
    if (errorCode == CL_SUCCESS) {
        memalloc_printf("Successfully allocated Bitmap B\n");
    } else {
        memalloc_printf("Unable to allocate 128MB bitmap B\n");
        this->DeviceBitmap128mb_b_Address = 0;
    }
    
    this->DeviceBitmap128mb_c_Address =
            clCreateBuffer (this->OpenCL->getContext(),
            CL_MEM_READ_ONLY,
            128 * 1024 * 1024,
            NULL,
            &errorCode);
    if (errorCode == CL_SUCCESS) {
        memalloc_printf("Successfully allocated Bitmap C\n");
    } else {
        memalloc_printf("Unable to allocate 128MB bitmap C\n");
        this->DeviceBitmap128mb_c_Address = 0;
    }
    
    this->DeviceBitmap128mb_d_Address =
            clCreateBuffer (this->OpenCL->getContext(),
            CL_MEM_READ_ONLY,
            128 * 1024 * 1024,
            NULL,
            &errorCode);
    if (errorCode == CL_SUCCESS) {
        memalloc_printf("Successfully allocated Bitmap D\n");
    } else {
        memalloc_printf("Unable to allocate 128MB bitmap D\n");
        this->DeviceBitmap128mb_d_Address = 0;
    }
    


    memalloc_printf("Thread %d memory allocated successfully\n", this->threadId);
}


void MFNHashTypePlainOpenCL::freeThreadAndDeviceMemory() {
    trace_printf("MFNHashTypePlainOpenCL::freeThreadAndDeviceMemory()\n");

    
    clReleaseMemObject(this->DeviceHashlistAddress);
    delete[] this->HostSuccessAddress;
    delete[] this->HostSuccessReportedAddress;
    clReleaseMemObject(this->DeviceSuccessAddress);
    delete[] this->HostFoundPasswordsAddress;
    clReleaseMemObject(this->DeviceFoundPasswordsAddress);
    delete[] this->HostStartPointAddress;
    clReleaseMemObject(this->DeviceStartPointAddress);
    clReleaseMemObject(this->DeviceStartPasswords32Address);
    
    clReleaseMemObject(this->DeviceBitmap8kb_a_Address);
    clReleaseMemObject(this->DeviceForwardCharsetAddress);
    clReleaseMemObject(this->DeviceReverseCharsetAddress);
    clReleaseMemObject(this->DeviceCharsetLengthsAddress);

    // Only free the bitmap memory if it has been allocated.
    if (this->DeviceBitmap128mb_a_Address) {
        clReleaseMemObject(this->DeviceBitmap128mb_a_Address);
        this->DeviceBitmap128mb_a_Address = 0;
    }
    if (this->DeviceBitmap128mb_b_Address) {
        clReleaseMemObject(this->DeviceBitmap128mb_b_Address);
        this->DeviceBitmap128mb_b_Address = 0;
    }
    if (this->DeviceBitmap128mb_c_Address) {
        clReleaseMemObject(this->DeviceBitmap128mb_c_Address);
        this->DeviceBitmap128mb_c_Address = 0;
    }
    if (this->DeviceBitmap128mb_d_Address) {
        clReleaseMemObject(this->DeviceBitmap128mb_d_Address);
        this->DeviceBitmap128mb_d_Address = 0;
    }
}


void MFNHashTypePlainOpenCL::copyDataToDevice() {
    trace_printf("MFNHashTypePlainOpenCL::copyDataToDevice()\n");
    
    cl_int errorCode;
    
    
    
    // Copy all the various elements of data to the device, forming them as needed.
    errorCode = clEnqueueWriteBuffer (this->OpenCL->getCommandQueue(),
            this->DeviceHashlistAddress,
            CL_TRUE /* blocking write */,
            0 /* offset */,
            this->activeHashesProcessedDeviceformat.size() /* bytes to copy */,
            (void *)&this->activeHashesProcessedDeviceformat[0],
            NULL, NULL, NULL /* event list stuff */);
    if (errorCode != CL_SUCCESS) {
        printf("Error: %s\n", print_cl_errstring(errorCode));
        exit(1);
    }
    
    // Device bitmaps: Copy all relevant bitmaps to the device.
    // Only copy bitmaps that are created.
    if (this->DeviceBitmap128mb_a_Address) {
        memalloc_printf("Thread %d: Copying bitmap A\n", this->threadId);
        errorCode = clEnqueueWriteBuffer (this->OpenCL->getCommandQueue(),
                this->DeviceBitmap128mb_a_Address,
                CL_TRUE /* blocking write */,
                0 /* offset */,
                this->globalBitmap128mb_a.size() /* bytes to copy */,
                (void *)&this->globalBitmap128mb_a[0],
                NULL, NULL, NULL /* event list stuff */);
        if (errorCode != CL_SUCCESS) {
            printf("Error: %s\n", print_cl_errstring(errorCode));
            exit(1);
        }
    }

    if (this->DeviceBitmap128mb_b_Address) {
        memalloc_printf("Thread %d: Copying bitmap B\n", this->threadId);
        errorCode = clEnqueueWriteBuffer (this->OpenCL->getCommandQueue(),
                this->DeviceBitmap128mb_b_Address,
                CL_TRUE /* blocking write */,
                0 /* offset */,
                this->globalBitmap128mb_b.size() /* bytes to copy */,
                (void *)&this->globalBitmap128mb_b[0],
                NULL, NULL, NULL /* event list stuff */);
        if (errorCode != CL_SUCCESS) {
            printf("Error: %s\n", print_cl_errstring(errorCode));
            exit(1);
        }
    }
    
    if (this->DeviceBitmap128mb_c_Address) {
        memalloc_printf("Thread %d: Copying bitmap C\n", this->threadId);
        errorCode = clEnqueueWriteBuffer (this->OpenCL->getCommandQueue(),
                this->DeviceBitmap128mb_c_Address,
                CL_TRUE /* blocking write */,
                0 /* offset */,
                this->globalBitmap128mb_c.size() /* bytes to copy */,
                (void *)&this->globalBitmap128mb_c[0],
                NULL, NULL, NULL /* event list stuff */);
        if (errorCode != CL_SUCCESS) {
            printf("Error: %s\n", print_cl_errstring(errorCode));
            exit(1);
        }
    }
    
    if (this->DeviceBitmap128mb_d_Address) {
        memalloc_printf("Thread %d: Copying bitmap D\n", this->threadId);
        errorCode = clEnqueueWriteBuffer (this->OpenCL->getCommandQueue(),
                this->DeviceBitmap128mb_d_Address,
                CL_TRUE /* blocking write */,
                0 /* offset */,
                this->globalBitmap128mb_d.size() /* bytes to copy */,
                (void *)&this->globalBitmap128mb_d[0],
                NULL, NULL, NULL /* event list stuff */);
        if (errorCode != CL_SUCCESS) {
            printf("Error: %s\n", print_cl_errstring(errorCode));
            exit(1);
        }
    }

    // Other data to the device - charset, etc.
}

void MFNHashTypePlainOpenCL::copyStartPointsToDevice() {
    trace_printf("MFNHashTypePlainOpenCL::copyStartPointsToDevice()\n");
    
    cl_int errorCode;
    
    errorCode = clEnqueueWriteBuffer (this->OpenCL->getCommandQueue(),
                this->DeviceStartPointAddress,
                CL_TRUE /* blocking write */,
                0 /* offset */,
                this->TotalKernelWidth * this->passwordLength /* bytes to copy */,
                (void *)this->HostStartPointAddress,
                NULL, NULL, NULL /* event list stuff */);

    errorCode = clEnqueueWriteBuffer (this->OpenCL->getCommandQueue(),
                this->DeviceStartPasswords32Address,
                CL_TRUE /* blocking write */,
                0 /* offset */,
                this->TotalKernelWidth * this->passwordLengthWords /* bytes to copy */,
                (void *)&this->HostStartPasswords32[0],
                NULL, NULL, NULL /* event list stuff */);
}


int MFNHashTypePlainOpenCL::setOpenCLDeviceID(int newOpenCLPlatformId, int newOpenCLDeviceId) {
    trace_printf("MFNHashTypePlainOpenCL::setOpenCLDeviceID(%d, %d)\n", newOpenCLPlatformId, newOpenCLDeviceId);
    
    MFNCommandLineData *CommandLineData = MultiforcerGlobalClassFactory.getCommandlinedataClass();
    
    this->OpenCL = new CryptohazeOpenCL();

    if (newOpenCLPlatformId > this->OpenCL->getNumberOfPlatforms()) {
        printf("Error: OpenCL Platform ID %d not valid!\n", newOpenCLPlatformId);
        exit(1);
    }

    this->OpenCL->selectPlatformById(newOpenCLPlatformId);

    if (newOpenCLDeviceId > this->OpenCL->getNumberOfDevices()) {
        printf("Error: OpenCL Device ID %d not valid!\n", newOpenCLDeviceId);
        exit(1);
    }

    this->OpenCL->selectDeviceById(newOpenCLDeviceId);

    this->openCLPlatformId = newOpenCLPlatformId;
    this->gpuDeviceId = newOpenCLDeviceId;
    
 
    // If the blocks or threads are set, use them, else use the default.
    if (CommandLineData->GetGpuBlocks()) {
        this->GPUBlocks = CommandLineData->GetGpuBlocks();
    } else {
        this->GPUBlocks = this->OpenCL->getDefaultBlockCount();
    }

    if (CommandLineData->GetGpuThreads()) {
        this->GPUThreads = CommandLineData->GetGpuThreads();
    } else {
        this->GPUThreads = this->OpenCL->getDefaultThreadCount();
    }

    // If target time is 0, use defaults.
    if (CommandLineData->GetTargetExecutionTimeMs()) {
        this->kernelTimeMs = CommandLineData->GetTargetExecutionTimeMs();
    } else {
        this->kernelTimeMs = 100;
    }

    this->OpenCL->createContext();
    this->OpenCL->createCommandQueue();
 
    // For now - set by CLI later.
    this->VectorWidth = 4;

    this->TotalKernelWidth = this->GPUBlocks * this->GPUThreads * this->VectorWidth;

    trace_printf("Thread %d added OpenCL Device (%d, %d)\n", this->threadId,
            newOpenCLPlatformId, newOpenCLDeviceId);;

    return 1;
}

void MFNHashTypePlainOpenCL::setupClassForMultithreadedEntry() {
    trace_printf("MFNHashTypePlainOpenCL::setupClassForMultithreadedEntry()\n");
}

void MFNHashTypePlainOpenCL::synchronizeThreads() {
    trace_printf("MFNHashTypePlainOpenCL::synchronizeThreads()\n");
    clEnqueueBarrier(this->OpenCL->getCommandQueue());
}


void MFNHashTypePlainOpenCL::setStartPoints(uint64_t perThread, uint64_t startPoint) {
    trace_printf("MFNHashTypePlain::setStartPoints()\n");

    uint32_t numberThreads = this->TotalKernelWidth;
    uint64_t threadId, threadStartPoint;
    uint32_t characterPosition;

    uint8_t *threadStartCharacters = this->HostStartPointAddress;

    if (this->isSingleCharset) {
        klaunch_printf("Calculating start points for a single charset.\n");
        // Copy the current charset length into a local variable for speed.
        uint8_t currentCharsetLength = this->currentCharset.at(0).size();

        for (threadId = 0; threadId < numberThreads; threadId++) {
            threadStartPoint = threadId * perThread + startPoint;
            //printf("Thread %u, startpoint %lu, perThread %d\n", threadId, threadStartPoint, perThread);

            // Loop through all the character positions.  This is easier than a case statement.
            for (characterPosition = 0; characterPosition < this->passwordLength; characterPosition++) {
                threadStartCharacters[characterPosition * numberThreads + threadId] =
                        this->currentCharset[0][(uint8_t)(threadStartPoint % currentCharsetLength)];
                threadStartPoint /= currentCharsetLength;
                /*printf("Set thread %d to startpoint %c at pos %d\n",
                        threadId, threadStartCharacters[characterPosition * numberThreads + threadId],
                        characterPosition * numberThreads + threadId);*/
            }
        }

    } else{
        klaunch_printf("Calculating start points for a multiple charset.\n");
        if (this->passwordLength > this->currentCharset.size()) {
            printf("Error: Password length > charset length!\n");
            printf("Terminating!\n");
            exit(1);
        }
        for (threadId = 0; threadId < numberThreads; threadId++) {
            threadStartPoint = threadId * perThread + startPoint;
            //printf("Thread %u, startpoint %lu\n", threadId, threadStartPoint);

            // Loop through all the character positions.  This is easier than a case statement.
            for (characterPosition = 0; characterPosition < this->passwordLength; characterPosition++) {
                threadStartCharacters[characterPosition * numberThreads + threadId] =
                        this->currentCharset[characterPosition][(uint8_t)(threadStartPoint % this->currentCharset[characterPosition].size())];
                threadStartPoint /= this->currentCharset[characterPosition].size();
                /*printf("Set thread %d to startpoint %d at pos %d\n",
                        threadId, threadStartPosition[characterPosition * numberThreads + threadId],
                        characterPosition * numberThreads + threadId);*/
            }
        }
    }
}


void MFNHashTypePlainOpenCL::copyDeviceFoundPasswordsToHost() {
    trace_printf("MFNHashTypePlainOpenCL::copyDeviceFoundPasswordsToHost()\n");

    cl_int errorCode;
    
    errorCode = clEnqueueReadBuffer (this->OpenCL->getCommandQueue(),
        this->DeviceSuccessAddress,
        CL_TRUE /* blocking write */,
        0 /* offset */,
        this->activeHashesProcessed.size() /* bytes to copy */,
        (void *)this->HostSuccessAddress,
        NULL, NULL, NULL /* event list stuff */);
    if (errorCode != CL_SUCCESS) {
        printf("Error: %s\n", print_cl_errstring(errorCode));
        exit(1);
    }

    errorCode = clEnqueueReadBuffer (this->OpenCL->getCommandQueue(),
        this->DeviceFoundPasswordsAddress,
        CL_TRUE /* blocking write */,
        0 /* offset */,
        this->passwordLength * this->activeHashesProcessed.size() /* bytes to copy */,
        (void *)this->HostFoundPasswordsAddress,
        NULL, NULL, NULL /* event list stuff */);
    if (errorCode != CL_SUCCESS) {
        printf("Error: %s\n", print_cl_errstring(errorCode));
        exit(1);
    }
}

void MFNHashTypePlainOpenCL::outputFoundHashes() {
    trace_printf("MFNHashTypePlainOpenCL::outputFoundHashes()\n");
    uint32_t i, j;

    /**
     * A vector containing the hash, processed back into the raw format.
     */
    std::vector<uint8_t> rawHash;
    std::vector<uint8_t> foundPassword;

    uint8_t *hostSuccessArray = this->HostSuccessAddress;
    uint8_t *hostSuccessReportedArray = this->HostSuccessReportedAddress;
    uint8_t *hostPasswords = this->HostFoundPasswordsAddress;

    for (i = 0; i < this->activeHashesProcessed.size(); i++) {
        if (hostSuccessArray[i] && !hostSuccessReportedArray[i]) {
            rawHash = this->postProcessHash(this->activeHashesProcessed[i]);
            foundPassword.resize(this->passwordLength + 1, 0);
            for (j = 0; j < this->passwordLength; j++) {
                foundPassword[j] = hostPasswords[this->passwordLength * i + j];
            }
            this->HashFile->ReportFoundPassword(rawHash, foundPassword);
            this->Display->addCrackedPassword(foundPassword);
            hostSuccessReportedArray[i] = 1;

        }
    }

    // Check to see if we should exit (as all hashes are found).
    if (this->HashFile->GetUncrackedHashCount() == 0) {
      //global_interface.exit = 1;
    }
}
