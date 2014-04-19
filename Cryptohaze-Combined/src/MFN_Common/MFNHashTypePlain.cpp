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


#include <vector>

#include "MFN_Common/MFNHashTypePlain.h"
#include "Multiforcer_Common/CHDisplay.h"
#include "CH_HashFiles/CHHashFileV.h"
#include "CH_Common/CHCharsetNew.h"
#include "MFN_Common/MFNCommandLineData.h"
#include "CH_Common/CHWorkunitBase.h"
#include "CH_Common/CHHiresTimer.h"
#include "MFN_Common/MFNDefines.h"
#include "MFN_Common/MFNDebugging.h"
#include "MFN_Common/MFNDisplay.h"


extern struct global_commands global_interface;

// static data members
uint8_t MFNHashTypePlain::staticDataInitialized = 0;
uint16_t MFNHashTypePlain::hashLengthBytes = 0;
uint16_t MFNHashTypePlain::passwordLength = 0;
uint16_t MFNHashTypePlain::passwordLengthWords = 0;

boost::mutex MFNHashTypePlain::MFNHashTypePlainMutex;


std::vector<std::vector<uint8_t> > MFNHashTypePlain::activeHashesRaw;
std::vector<std::vector<uint8_t> > MFNHashTypePlain::activeHashesProcessed;
std::vector<uint8_t> MFNHashTypePlain::activeHashesProcessedDeviceformat;
std::vector<std::vector<uint8_t> > MFNHashTypePlain::currentCharset;

std::vector<uint8_t> MFNHashTypePlain::sharedBitmap8kb_a;
std::vector<uint8_t> MFNHashTypePlain::sharedBitmap8kb_b;
std::vector<uint8_t> MFNHashTypePlain::sharedBitmap8kb_c;
std::vector<uint8_t> MFNHashTypePlain::sharedBitmap8kb_d;

std::vector<uint8_t> MFNHashTypePlain::globalBitmap128mb_a;
std::vector<uint8_t> MFNHashTypePlain::globalBitmap128mb_b;
std::vector<uint8_t> MFNHashTypePlain::globalBitmap128mb_c;
std::vector<uint8_t> MFNHashTypePlain::globalBitmap128mb_d;

std::vector<uint8_t> MFNHashTypePlain::charsetForwardLookup;
std::vector<uint8_t> MFNHashTypePlain::charsetReverseLookup;
std::vector<uint8_t> MFNHashTypePlain::charsetLengths;


uint8_t MFNHashTypePlain::isSingleCharset;



// Snagged from here:
// http://www.exploringbinary.com/ten-ways-to-check-if-an-integer-is-a-power-of-two-in-c/
// Feb 23 2012
static char isPowerOfTwo (uint32_t x)
{
 uint32_t numberOfOneBits = 0;

 while(x && numberOfOneBits <=1)
   {
    if ((x & 1) == 1) /* Is the least significant bit a 1? */
      numberOfOneBits++;
    x >>= 1;          /* Shift number one bit to the right */
   }

 return (numberOfOneBits == 1); /* 'True' if only one 1 bit */
}

// Table search predicates.

/**
 * Table search predicate for big endian hashes.
 *
 * This function sorts a big endian hash (where the value, in the registers,
 * corresponds to the hash interpreted as big endian).  This is for SHA type hashes.
 *
 * Returns true if h1 less than h2
 */
static bool hashBigEndianSortPredicate(const std::vector<uint8_t> &h1, const std::vector<uint8_t> &h2) {
    uint32_t i;
    for (i = 0; i < h1.size(); i++) {
        if (h1[i] == h2[i]) {
            continue;
        } else if (h1[i] > h2[i]) {
            return 0;
        } else if (h1[i] < h2[i]) {
            return 1;
        }
    }
    // Exactly equal = return 0.
    return 0;
}

// Deal with hashes that are little endian 32-bits.
static bool hashLittleEndianSortPredicate(const std::vector<uint8_t> &h1, const std::vector<uint8_t> &h2) {
    long int i, j;
    
    for (i = 0; i < (h1.size() / 4); i++) {
        for (j = 3; j >= 0; j--) {
            if (h1[(i * 4) + j] == h2[(i * 4) + j]) {
                continue;
            } else if (h1[(i * 4) + j] > h2[(i * 4) + j]) {
                return 0;
            } else if (h1[(i * 4) + j] < h2[(i * 4) + j]) {
                return 1;
            }
        }
    }
    // Exactly equal = return 0.
    return 0;
}


bool hashUniquePredicate(const std::vector<uint8_t> &h1, const std::vector<uint8_t> &h2) {
    int i;
    for (i = 0; i < h1.size(); i++) {
        if (h1[i] != h2[i]) {
            return 0;
        }
    }
    // Exactly equal = return 1.
    return 1;
}


MFNHashTypePlain::MFNHashTypePlain(uint16_t newHashLengthBytes) : MFNHashType() {
    trace_printf("MFNHashTypePlain::MFNHashTypePlain(%d)\n", newHashLengthBytes);
    this->hashLengthBytes = newHashLengthBytes;
    
    // Clear the data on thread initalization.
    this->staticDataInitialized = 0;
    this->passwordLength = 0;

    this->activeHashesRaw.clear();
    this->activeHashesProcessed.clear();
    this->activeHashesProcessedDeviceformat.clear();
    this->currentCharset.clear();
    
    this->sharedBitmap8kb_a.clear();
    this->sharedBitmap8kb_b.clear();
    this->sharedBitmap8kb_c.clear();
    this->sharedBitmap8kb_d.clear();

    this->globalBitmap128mb_a.clear();
    this->globalBitmap128mb_b.clear();
    this->globalBitmap128mb_c.clear();
    this->globalBitmap128mb_d.clear();
    
    this->charsetForwardLookup.clear();
    this->charsetReverseLookup.clear();
    this->charsetLengths.clear();

    this->isSingleCharset = 0;

    this->threadRendezvous = 0;
    
    this->GPUBlocks = 0;
    this->GPUThreads = 0;
    this->VectorWidth = 1;
    this->TotalKernelWidth = 0;
}


void MFNHashTypePlain::crackPasswordLength(int passwordLength) {
    trace_printf("MFNHashTypePlain::crackPasswordLength(%d)\n", passwordLength);

    uint64_t i;
    char statusBuffer[1000];
    struct CHWorkunitRobustElement WU;


    // New cracking - do NOT need to rendezvous threads.
    this->threadRendezvous = 0;

    // Acquire a setup mutex if we're the first thread.
    this->MFNHashTypePlainMutex.lock();

    // If static data is not set up, do so.
    // This data is shared across all instances.
    if (!this->staticDataInitialized) {
        this->threadRendezvous = 0;

        mt_printf("Thread %d doing MFNHashTypePlain setup.\n", this->threadId);

        this->Display->setPasswordLen(passwordLength);
        this->passwordLength = passwordLength;

        // Determine the password length in words.  If not a multiple of 4, round up.
        // Include the end padding bit in this calculation.
        this->passwordLengthWords = (this->passwordLength + 1);
        if (passwordLengthWords % 4) {
            passwordLengthWords = (passwordLengthWords + 4) & 0xfffc;
        }

        
        // Get the raw list of hashes.
        this->activeHashesRaw = this->HashFile->ExportUncrackedHashList();
        // Get the active charset.
        this->currentCharset = this->Charset->getCharset();
        
        mt_printf("Thread %d Charset length: %d\n", this->threadId, this->currentCharset.size());

        // If the charset length is 1, it is a single charset.  Tag as such.
        if (this->currentCharset.size() == 1) {
            this->isSingleCharset = 1;
        } else {
            this->isSingleCharset = 0;
        }
        
        this->setupCharsetArrays();

        this->Display->Refresh();

        // Preprocess all the hashes for the current password length.
        for (i = 0; i < this->activeHashesRaw.size(); i++) {
            this->activeHashesProcessed.push_back(this->preProcessHash(this->activeHashesRaw[i]));
        }

        // Sort and unique the hashes.
        this->sortHashes();

        // Set up the device-format hash list
        this->copyHashesIntoDeviceFormat();

        // If this is *not* a server-only instance, create bitmaps
        if (!this->CommandLineData->GetIsServerOnly()) {
            this->createLookupBitmaps();
        }
        this->staticDataInitialized = 1;
    }
    
    this->MFNHashTypePlainMutex.unlock();

    // Retrieve our client ID.
    this->ClientId = this->Workunit->GetClientId();
    sprintf(statusBuffer, "Td %d: CID %d.", this->threadId, this->ClientId);
    this->Display->addStatusLine(statusBuffer);

    // If the device ID is 0, the device is the fastest in the system.
    // This is true for CUDA, and possibly OpenCL.  If this thread is for
    // a non-zero device, wait a second.  This allows the fastest GPU to
    // take the work.  Otherwise, we don't care what order they enter.
    if (this->gpuDeviceId) {
        CHSleep(1);
    }

    // Do all the device-specific setup.
    this->setupDevice();

    // Reset the per-step data for the new password length.
    this->perStep = 0;

    // Allocate the thread and GPU memory.
    this->allocateThreadAndDeviceMemory();

    // Copy all the run data to the device.
    this->copyDataToDevice();

    // Copy the kernel-specific constant data to the device.
    this->copyConstantDataToDevice();

    // I... *think* we're ready to rock!
    // As long as we aren't supposed to exit, keep running.
    while(!global_interface.exit && !this->threadRendezvous) {
        WU = this->Workunit->GetNextWorkunit(ClientId);
        if (!WU.IsValid) {
            // If a null workunit came in, rendezvous the threads.
            this->threadRendezvous = 1;
            // Workunit came back null -
            sprintf(statusBuffer, "Td %d: out of WU.", this->threadId);
            this->Display->addStatusLine(statusBuffer);
            break;
        }
        if (this->CommandLineData->GetDevDebug()) {
            printf("Thread %d has workunit ID %d\n", this->threadId, WU.WorkUnitID);
        }
        this->RunGPUWorkunit(&WU);

        // If we are NOT aborting, submit the unit.
        // If we are force-exiting, do not submit the workunit!
        if (!global_interface.exit) {
            this->Workunit->SubmitWorkunit(WU);
        }
        this->Display->Refresh();
        //sprintf(this->statusBuffer, "WU rate: %0.1f", this->Workunit->GetAverageRate());
        //this->Display->addStatusLine(this->statusBuffer);
    }

    // Done with cracking - out of workunits.  Clean up & wait.

    // Free memory.
    this->freeThreadAndDeviceMemory();
    // Do final device teardown.
    this->teardownDevice();
    // Report speed of 0.
    this->Display->setThreadCrackSpeed(this->threadId, 0);


    // Wait until all workunits are back from remote systems.
    if (this->Workunit->GetNumberOfCompletedWorkunits() < this->Workunit->GetNumberOfWorkunits()) {
        sprintf(statusBuffer, "Waiting for workunits...");
        this->Display->addStatusLine(statusBuffer);
    }

    while (this->Workunit->GetNumberOfCompletedWorkunits() < this->Workunit->GetNumberOfWorkunits()) {
        CHSleep(1);
        //printf("Completed WU: %d\n", this->Workunit->GetNumberOfCompletedWorkunits());
        //printf("Total WU: %d\n", this->Workunit->GetNumberOfWorkunits());
        this->Display->Refresh();
        // Make termination work properly for the server
        if (global_interface.exit) {
            break;
        }
    }
    this->staticDataInitialized = 0;
}


// This is the GPU thread where we do the per-GPU tasks.
void MFNHashTypePlain::GPU_Thread() {
    trace_printf("MFNHashTypePlain::GPU_Thread()\n");
}

void MFNHashTypePlain::RunGPUWorkunit(CHWorkunitRobustElement* WU) {
    trace_printf("MFNHashTypePlain::RunGPUWorkunit()\n");

    /**
     * High-res timer - this should work properly on both Windows & Posix.
     */
    CHHiresTimer Timer, WorkunitTimer;

    uint64_t perThread, start_point = 0;
    uint64_t step_count = 0;
    uint64_t tempPerStep = 0;

    WorkunitTimer.start();
    
    // Kernel run time: seconds
    float ref_time = 0.0f;
    // Kernel run time: Milliseconds
    float ref_time_ms = 0.0f;
    
    float ref_time_total = 0.0f;

    // Default number per steps.  As this is updated quickly, this just needs to be in the ballpark.
    if (this->perStep == 0) {
        this->perStep = 50;
    }

    klaunch_printf("Thread %d total kernel width: %d\n", this->threadId, this->TotalKernelWidth);
    klaunch_printf("Thread %d blocks/threads/vec: %d/%d/%d\n", this->threadId, this->GPUBlocks, this->GPUThreads, this->VectorWidth);
    
    // Calculate how many iterations per thread - divide total by the number of
    // total threads, then add one to deal with truncation.
    perThread = WU->EndPoint - WU->StartPoint;
    perThread /= (this->TotalKernelWidth);
    perThread++;
    
    klaunch_printf("Total kernel width: %d\n", this->TotalKernelWidth);
    klaunch_printf("perThread: %d\n", perThread);

    // Set up the password start points for loading as blocks.
    this->setStartPasswords32(perThread, start_point + WU->StartPoint);
    // Copy them to the GPU.
    this->copyStartPointsToDevice();

    // Start the timer.
    Timer.start();

    while (start_point <= perThread) {
        step_count++;

        //this->setStartPoints(perThread, start_point + WU->StartPoint);

        if ((start_point + this->perStep) > perThread) {
            klaunch_printf("start_point: %lu\n", start_point);
            klaunch_printf("per_thread: %lu\n", perThread);
            klaunch_printf("Will overrun by %lu\n", (start_point + this->perStep) - perThread);
            tempPerStep = this->perStep;
            this->perStep = (perThread - start_point) + 1;
            klaunch_printf("Final per_step: %lu\n", this->perStep);
        }
        
        // We sync here and wait for the GPU to finish.
        this->synchronizeThreads();

        ref_time = Timer.getElapsedTime();
        ref_time_ms = Timer.getElapsedTimeInMilliSec();
        klaunch_printf("ref_time: %f s\n", ref_time);
        ref_time_total += ref_time;
        
        // Run this roughly every second, or every step if target_ms is >500
        if ((step_count < 5) || (this->kernelTimeMs > 500) || (step_count % (1000 / this->kernelTimeMs) == 0)) {

            this->copyDeviceFoundPasswordsToHost();
            this->outputFoundHashes();
            
            // Only set the crack speed if we have set one...
            if (step_count > 5) {
                this->Display->setThreadCrackSpeed(this->threadId,
                        (float) (this->TotalKernelWidth *
                        this->perStep) / (ref_time));
            }
            // If the current execution time is not correct, adjust.
            if ((ref_time_ms > 0) && (step_count > 2) &&
                    ((ref_time_ms < (this->kernelTimeMs * 0.9)) ||
                    (ref_time_ms > (this->kernelTimeMs * 1.1)))) {
                this->perStep = (uint64_t) ((float) this->perStep *
                        ((float) this->kernelTimeMs / ref_time_ms));
                if (0) {
                    printf("\nThread %d Adjusting passwords per step to %d\n",
                            this->gpuDeviceId, (unsigned int) this->perStep);
                }
            }
        }
        
        
        // If we are to pause, hang here.
        if (global_interface.pause) {
            while (global_interface.pause) {
                // Just hang out until the pause is broken...
                CHSleep(1);
            }
        }
        // Exit option
        if (global_interface.exit) {
            return;
        }


        //this->copyStartPointsToDevice();
        //this->synchronizeThreads();
        Timer.start();

        klaunch_printf("Launching kernel: \n");
        klaunch_printf("  start_point: %lu\n", start_point);
        klaunch_printf("  perStep: %lu\n", this->perStep);

        this->launchKernel();

        // Increment start point by however many we did
        start_point += this->perStep;
        

    }
    this->synchronizeThreads();
    
    // Perform a final rate calculation.
    // In some cases, the device is too fast for the normal speed reporting
    // to get triggered.
    Timer.stop();
    ref_time = Timer.getElapsedTime();
    this->Display->setThreadCrackSpeed(this->threadId,
        (float) (this->TotalKernelWidth *
        this->perStep) / (ref_time));

    this->copyDeviceFoundPasswordsToHost();
    this->outputFoundHashes();
    
    WorkunitTimer.stop();
    
    klaunch_printf("Workunit rate: %f\n", (WU->EndPoint - WU->StartPoint) / WorkunitTimer.getElapsedTime());
    klaunch_printf("Workunit timer: %f\n", WorkunitTimer.getElapsedTime());
    klaunch_printf("ref_time_total: %f\n", ref_time_total);
    
    if (tempPerStep) {
        klaunch_printf("Correcting perStep from current %lu to perm %lu\n", this->perStep, tempPerStep);
        this->perStep = tempPerStep;
    }
    
    return;
}

void MFNHashTypePlain::createLookupBitmaps() {
    trace_printf("MFNHashTypePlain::createLookupBitmaps()\n");
    
    // This involves creating bitmaps based on the provided hashes.
    // If the hash is big endian, they will be reversed compared to the hash.
    
    // Create bitmaps a (8kb and 128mb)
    if (this->hashLengthBytes >= 4) {
        static_printf("Creating bitmaps for word 0/a\n");
        this->create8kbBitmap(0, this->activeHashesProcessed, this->sharedBitmap8kb_a);
        this->create128mbBitmap(0, this->activeHashesProcessed, this->globalBitmap128mb_a);
    }
    if (this->hashLengthBytes >= 8) {
        static_printf("Creating bitmaps for word 1/b\n");
        this->create8kbBitmap(1, this->activeHashesProcessed, this->sharedBitmap8kb_b);
        this->create128mbBitmap(1, this->activeHashesProcessed, this->globalBitmap128mb_b);
    }
    if (this->hashLengthBytes >= 12) {
        static_printf("Creating bitmaps for word 2/c\n");
        this->create8kbBitmap(2, this->activeHashesProcessed, this->sharedBitmap8kb_c);
        this->create128mbBitmap(2, this->activeHashesProcessed, this->globalBitmap128mb_c);
    }
    if (this->hashLengthBytes >= 16) {
        static_printf("Creating bitmaps for word 3/d\n");
        this->create8kbBitmap(3, this->activeHashesProcessed, this->sharedBitmap8kb_d);
        this->create128mbBitmap(3, this->activeHashesProcessed, this->globalBitmap128mb_d);
    }
    
}


void MFNHashTypePlain::create8kbBitmap(uint8_t startWord, 
            std::vector<std::vector<uint8_t> > &hashList, std::vector<uint8_t> &bitmap8kb) {
    
    uint32_t bitmapIndex;
    uint8_t  bitmapByte;
    uint64_t passwordIndex;
    
    // Step 1: Set the vector to 8kb.
    bitmap8kb.resize(8192);
    // Step 2: Clear the vector
    memset(&bitmap8kb[0], 0, 8192);
    
    for (passwordIndex = 0; passwordIndex < hashList.size(); passwordIndex++) {
        /*
        printf("Hash word: %02x%02x%02x%02x\n", 
                hashList.at(passwordIndex).at((startWord * 4) + 0),
                hashList.at(passwordIndex).at((startWord * 4) + 1),
                hashList.at(passwordIndex).at((startWord * 4) + 2),
                hashList.at(passwordIndex).at((startWord * 4) + 3));
        */
        if (this->HashIsBigEndian) {
            // Big endian hash - take bytes 2 & 3 in the word as the low value.
            bitmapIndex = ((uint16_t)hashList.at(passwordIndex).at((startWord * 4) + 2) << 8) + 
                (uint16_t)hashList.at(passwordIndex).at((startWord * 4) + 3);
        } else {
            // Little endian hash - take bytes 0 & 1 in the word as the low value (swapped).
            bitmapIndex = ((uint16_t)hashList.at(passwordIndex).at((startWord * 4) + 1) << 8) + 
                (uint16_t)hashList.at(passwordIndex).at((startWord * 4));
        }
        //printf("bitmapIndex: %04x\n", bitmapIndex);
        
        // Set the byte by shifting left by the lower 3 bits in the index
        bitmapByte = 0x01 << (bitmapIndex & 0x0007);
        // Determine the byte offset by shifting right 3 bits.
        bitmapIndex = bitmapIndex >> 3;
        
        //printf("bitmapByte: %02x\n", bitmapByte);
        //printf("bitmapIndex: %04x\n", bitmapIndex);

        if (bitmapIndex >= 8192) {
            printf("FATAL ERROR: Bitmap index beyond bound of bitmap!\n");
            exit(1);
        }
        // Add the bit into the bitmap
        bitmap8kb[bitmapIndex] |= bitmapByte;
    }
}

void MFNHashTypePlain::create128mbBitmap(uint8_t startWord, 
        std::vector<std::vector<uint8_t> > &hashList, std::vector<uint8_t> &bitmap128mb) {
    
    uint32_t bitmapIndex;
    uint8_t  bitmapByte;
    uint64_t passwordIndex;
    
    // Step 1: Set the vector to 128mb.
    bitmap128mb.resize(128*1024*1024);
    // Step 2: Clear the vector
    memset(&bitmap128mb[0], 0, 128*1024*1024);
    
    for (passwordIndex = 0; passwordIndex < hashList.size(); passwordIndex++) {
        
        /*
         printf("Hash word: %02x%02x%02x%02x\n", 
                hashList.at(passwordIndex).at((startWord * 4) + 0),
                hashList.at(passwordIndex).at((startWord * 4) + 1),
                hashList.at(passwordIndex).at((startWord * 4) + 2),
                hashList.at(passwordIndex).at((startWord * 4) + 3));
        */
        
        if (this->HashIsBigEndian) {
            // Big endian hash - read in as a big endian value
            bitmapIndex = 
                    ((uint32_t)hashList.at(passwordIndex).at((startWord * 4) + 0) << 24) + 
                    ((uint32_t)hashList.at(passwordIndex).at((startWord * 4) + 1) << 16) + 
                    ((uint32_t)hashList.at(passwordIndex).at((startWord * 4) + 2) <<  8) + 
                    ((uint32_t)hashList.at(passwordIndex).at((startWord * 4) + 3) <<  0);
        } else {
            // Little endian hash - take bytes 0 & 1 in the word as the low value (swapped).
            bitmapIndex = 
                    ((uint32_t)hashList.at(passwordIndex).at((startWord * 4) + 0) <<  0) + 
                    ((uint32_t)hashList.at(passwordIndex).at((startWord * 4) + 1) <<  8) + 
                    ((uint32_t)hashList.at(passwordIndex).at((startWord * 4) + 2) << 16) + 
                    ((uint32_t)hashList.at(passwordIndex).at((startWord * 4) + 3) << 24);
        }
        //printf("bitmapIndex: %08x\n", bitmapIndex);
        
        // Set the byte by shifting left by the lower 3 bits in the index
        bitmapByte = 0x01 << (bitmapIndex & 0x0007);
        // Determine the byte offset by shifting right 3 bits.
        bitmapIndex = bitmapIndex >> 3;
        // Mask off the lower 27 bits 
        bitmapIndex &= 0x07FFFFFF;
        
        //printf("bitmapByte: %02x\n", bitmapByte);
        //printf("bitmapIndex: %08x\n", bitmapIndex);

        if (bitmapIndex >= 128*1024*1024) {
            printf("FATAL ERROR: Bitmap index beyond bound of bitmap!\n");
            exit(1);
        }

        // Add the bit into the bitmap
        bitmap128mb[bitmapIndex] |= bitmapByte;
    }
}

void MFNHashTypePlain::createArbitraryBitmap(uint8_t startWord,
        std::vector<std::vector<uint8_t> > &hashList, std::vector<uint8_t> &bitmap,
        uint32_t bitmapSizeBytes) {

    uint32_t bitmapIndex;
    uint8_t  bitmapByte;
    uint64_t passwordIndex;
    uint32_t bitmapMask;

    if (!isPowerOfTwo(bitmapSizeBytes)) {
        printf("Error!  Bitmap size not a power of 2!\n");
        exit(1);
    }

    // Set the bitmap mask - size - 1 for and masking.
    bitmapMask = (bitmapSizeBytes - 1);

    // Step 1: Set the vector to whatever is specified.
    bitmap.resize(bitmapSizeBytes);
    // Step 2: Clear the vector
    memset(&bitmap[0], 0, bitmapSizeBytes);


    for (passwordIndex = 0; passwordIndex < hashList.size(); passwordIndex++) {
        if (this->HashIsBigEndian) {
            // Big endian hash - read in as a big endian value
            bitmapIndex =
                    ((uint32_t)hashList.at(passwordIndex).at((startWord * 4) + 0) << 24) +
                    ((uint32_t)hashList.at(passwordIndex).at((startWord * 4) + 1) << 16) +
                    ((uint32_t)hashList.at(passwordIndex).at((startWord * 4) + 2) <<  8) +
                    ((uint32_t)hashList.at(passwordIndex).at((startWord * 4) + 3) <<  0);
        } else {
            // Little endian hash - take bytes 0 & 1 in the word as the low value (swapped).
            bitmapIndex =
                    ((uint32_t)hashList.at(passwordIndex).at((startWord * 4) + 0) <<  0) +
                    ((uint32_t)hashList.at(passwordIndex).at((startWord * 4) + 1) <<  8) +
                    ((uint32_t)hashList.at(passwordIndex).at((startWord * 4) + 2) << 16) +
                    ((uint32_t)hashList.at(passwordIndex).at((startWord * 4) + 3) << 24);
        }
        //printf("bitmapIndex: %08x\n", bitmapIndex);

        // Set the byte by shifting left by the lower 3 bits in the index
        bitmapByte = 0x01 << (bitmapIndex & 0x0007);
        // Determine the byte offset by shifting right 3 bits.
        bitmapIndex = bitmapIndex >> 3;
        // Mask off the lower 27 bits
        bitmapIndex &= bitmapMask;

        //printf("bitmapByte: %02x\n", bitmapByte);
        //printf("bitmapIndex: %08x\n", bitmapIndex);

        if (bitmapIndex >= bitmapSizeBytes) {
            printf("FATAL ERROR: Bitmap index beyond bound of bitmap!\n");
            exit(1);
        }

        // Add the bit into the bitmap
        bitmap[bitmapIndex] |= bitmapByte;
    }
}


void MFNHashTypePlain::sortHashes() {
    trace_printf("MFNHashTypePlain::sortHashes()\n");
    if (this->HashIsBigEndian) {
        // Big endian sort
        // Sort hashes with the big endian sort predicate.  This will interpret
        // them as 00112233 < 11111111
        std::sort(this->activeHashesProcessed.begin(),
                this->activeHashesProcessed.end(), hashBigEndianSortPredicate);
    } else {
        // Little endian sort
        // Sort hashes with the little endian sort predicate.  This will interpret
        // them as 00112233 > 11111111
        std::sort(this->activeHashesProcessed.begin(),
                this->activeHashesProcessed.end(), hashLittleEndianSortPredicate);
   }
    this->activeHashesProcessed.erase(
        std::unique(this->activeHashesProcessed.begin(), this->activeHashesProcessed.end(), hashUniquePredicate),
        this->activeHashesProcessed.end());

    // Debug print hashes
    /*
    printf("sortHashes() printout\n");
    uint32_t i, j;
    for (i = 0; i < this->activeHashesProcessed.size(); i++) {
        for (j = 0; j < this->activeHashesProcessed[i].size(); j++) {
            printf("%02x", this->activeHashesProcessed[i][j]);
        }
        printf("\n");
    }
    */
    
}


void MFNHashTypePlain::copyHashesIntoDeviceFormat() {
    trace_printf("MFNHashTypePlain::copyHashesIntoDeviceFormat()\n");

    uint64_t hashIndex;

    /** Convert the processed hashlist into a single vector suited to copying
     * to the GPUs.  This will be the same for CUDA and OpenCL (and can be
     * used by the CPU as well.
     */

    // Reserve the right amount of space in the main vector - number of elements * hashlength
    this->activeHashesProcessedDeviceformat.resize(
            this->activeHashesProcessed.size() * this->hashLengthBytes);

    for (hashIndex = 0; hashIndex < this->activeHashesProcessed.size(); hashIndex++) {
        memcpy(&this->activeHashesProcessedDeviceformat[hashIndex * this->hashLengthBytes],
                &this->activeHashesProcessed[hashIndex][0], this->hashLengthBytes);
    }

    static_printf("Created common hash array of %d bytes.\n", this->activeHashesProcessedDeviceformat.size());

    if (0) {
        for (hashIndex = 0; hashIndex < this->activeHashesProcessed.size(); hashIndex++) {
            for (int j = 0; j < this->hashLengthBytes; j++) {
                printf("%02x", this->activeHashesProcessedDeviceformat[hashIndex * this->hashLengthBytes + j]);
            }
            printf("\n");
        }
    }
    
}

void MFNHashTypePlain::setupCharsetArrays() {
    trace_printf("MFNHashTypePlain::setupCharsetArrays()\n");

    uint32_t charsetItemsToCopy, i, j;


    // Ensure that we zero unused elements.
    this->charsetLengths.resize(this->passwordLength, 0);

    // Step 1: Set up the charset array - CHARSET_LENGTH elements per length.
    if (this->currentCharset.size() == 1) {
        charsetItemsToCopy = 1;

        // If the charset is single (length 1), then only allocate CHARSET_LENGTH bytes for it.
        this->charsetForwardLookup.resize(MFN_HASH_TYPE_PLAIN_MAX_CHARSET_LENGTH, 0);
        this->charsetReverseLookup.resize(MFN_HASH_TYPE_PLAIN_MAX_CHARSET_LENGTH, 0);

        this->charsetLengths[0] = this->currentCharset[0].size();
        
        for (i = 0; i < this->currentCharset[0].size(); i++) {
            this->charsetForwardLookup[i] = this->currentCharset[0][i];
            this->charsetReverseLookup[this->currentCharset[0][i]] = i;
        }

    } else {
        // Vector is multiple - ensure it is long enough, then copy it.
        if (this->currentCharset.size() < this->passwordLength) {
            printf("Error!  Multiposition charset is shorter than password!\n");
            exit(1);
        }
        charsetItemsToCopy = this->passwordLength;

        // Make room!  PassLength * CHARSET_LENGTH
        this->charsetForwardLookup.resize(this->passwordLength * 
                MFN_HASH_TYPE_PLAIN_MAX_CHARSET_LENGTH, 0);
        this->charsetReverseLookup.resize(this->passwordLength * 
                MFN_HASH_TYPE_PLAIN_MAX_CHARSET_LENGTH, 0);

        for (i = 0; i < charsetItemsToCopy; i++) {
            this->charsetLengths[i] = this->currentCharset[i].size();
            for (j = 0; j < this->currentCharset[i].size(); j++) {
                this->charsetForwardLookup[(i * MFN_HASH_TYPE_PLAIN_MAX_CHARSET_LENGTH) + j] = 
                        this->currentCharset[i][j];
                this->charsetReverseLookup[(i * MFN_HASH_TYPE_PLAIN_MAX_CHARSET_LENGTH) + 
                        this->currentCharset[i][j]] = j;
            }
        }
    }
}

void MFNHashTypePlain::setStartPasswords32(uint64_t perThread, uint64_t startPoint) {
    trace_printf("MFNHashTypePlain::setStartPasswords32()\n");

    uint64_t threadId, threadStartPoint;
    uint32_t characterPosition;


    // Resize the vector to the needed number of bytes.  This will possibly
    // have waste space at the end, but will be loaded as words, so needs
    // to be a multiple of 4 length.  Init to 0, so the unused bytes are
    // null.
    this->HostStartPasswords32.resize(this->TotalKernelWidth * this->passwordLengthWords, 0);

    
    if (this->isSingleCharset) {
        klaunch_printf("Calculating start points for a single charset.\n");
        // Copy the current charset length into a local variable for speed.
        uint8_t currentCharsetLength = this->currentCharset.at(0).size();

        for (threadId = 0; threadId < this->TotalKernelWidth; threadId++) {

            threadStartPoint = threadId * perThread + startPoint;
            //printf("Thread %u, startpoint %lu, perThread %d\n", threadId, threadStartPoint, perThread);

            // Loop through all the character positions.  This is easier than a case statement.
            for (characterPosition = 0; characterPosition < this->passwordLength; characterPosition++) {
                // Base offset: b0 starts at (kernelWidth * 0), b1 starts at (kernelWidth * 4), etc.
                uint32_t baseOffset = ((characterPosition / 4) * this->TotalKernelWidth * 4);
                // Character offset: baseOffset + (threadId * 4) + (characterPos % 4)
                this->HostStartPasswords32[baseOffset + (threadId * 4) + (characterPosition % 4)] =
                        this->currentCharset[0][(uint8_t)(threadStartPoint % currentCharsetLength)];
                threadStartPoint /= currentCharsetLength;
            }
            // Set the padding bit.
            this->HostStartPasswords32[((this->passwordLength / 4) * this->TotalKernelWidth * 4)
                    + (threadId * 4) + (this->passwordLength % 4)] = 0x80;
        }
    } else {
        klaunch_printf("Calculating start points for a multiple charset.\n");
        // Copy the current charset length into a local variable for speed.
        uint8_t currentCharsetLength = this->currentCharset.at(0).size();

        for (threadId = 0; threadId < this->TotalKernelWidth; threadId++) {

            threadStartPoint = threadId * perThread + startPoint;
            //printf("Thread %u, startpoint %lu, perThread %d\n", threadId, threadStartPoint, perThread);

            // Loop through all the character positions.  This is easier than a case statement.
            for (characterPosition = 0; characterPosition < this->passwordLength; characterPosition++) {
                // Base offset: b0 starts at (kernelWidth * 0), b1 starts at (kernelWidth * 4), etc.
                uint32_t baseOffset = ((characterPosition / 4) * this->TotalKernelWidth * 4);
                // Character offset: baseOffset + (threadId * 4) + (characterPos % 4)
                this->HostStartPasswords32[baseOffset + (threadId * 4) + (characterPosition % 4)] =
                        this->currentCharset[characterPosition][(uint8_t)(threadStartPoint % currentCharsetLength)];
                threadStartPoint /= currentCharsetLength;
            }
            // Set the padding bit.
            this->HostStartPasswords32[((this->passwordLength / 4) * this->TotalKernelWidth * 4)
                    + (threadId * 4) + (this->passwordLength % 4)] = 0x80;
        }
    }
}
