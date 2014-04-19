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

#ifndef _MFNCOMMANDLINEDATA_H
#define _MFNCOMMANDLINEDATA_H

#include "Multiforcer_Common/CHCommon.h"

#include <string>
#include <vector>

#define MAX_FILENAME_LENGTH 1024
#define MAX_HOSTNAME_LENGTH 1024


// Current version of the structure - we refuse to restore from different versions.
// This should be incremented any time the structure changes!
#define SAVE_RESTORE_DATA_VERSION 1

/* A structure type containing data for saving and restoring state to the
 * MFNCommandLineData class - this is used for the save/restore files.
 *
 * The "Use" variables are set based on the presence or absence of the
 * related string - they are not stored individually.
 *
 * The current password length is set by the calling code.
 *
 * Things like network server are set on invocation, not by the
 * restore state - this allows easy changing to add the server if not originally
 * enabled in the execution, or changing the server port.
 */
#pragma pack(push, 1)
typedef struct MFNSaveRestoreData{
    uint8_t  MFNSaveRestoreDataVersion;
    uint8_t  AddHexOutput;
    uint8_t  CurrentPasswordLength;
    uint8_t  UseCharsetMulti;
    int      HashType;
    char     HashListFileName[MAX_FILENAME_LENGTH];
    char     CharsetFileName[MAX_FILENAME_LENGTH];
    char     OutputFileName[MAX_FILENAME_LENGTH];
    char     UnfoundOutputFileName[MAX_FILENAME_LENGTH];
} MFNSaveRestoreData;
#pragma pack(pop)

/**
 * A structure containing device information.  This is used to allow for specifying
 * multiple devices to be added to the execution context.  This structure works
 * for CUDA, OpenCL, and CPU threads.  Unused fields are ignored.
 * 
 * If Block or Thread count is zero, the default for the device is used.
 * 
 * OpenCLPlatformId: The OpenCL Platform ID, if OpenCL is being used.
 * GPUDeviceId: The OpenCL Device ID, or the CUDA Device ID.
 * DeviceBlocks: Number of blocks (CUDA form)
 * DeviceThreads: Number of threads (CUDA form), or number CPU SSE threads.
 * IsCUDADevice: True if this is a CUDA device identifier.
 * IsOpenCLDevice: True if this is an OpenCL device identifier.
 * IsCPUDevice: True if this is a CPU device identifier.
 */
typedef struct MFNDeviceInformation {
    uint32_t OpenCLPlatformId;
    uint32_t GPUDeviceId;
    uint32_t DeviceBlocks;
    uint32_t DeviceThreads;
    uint8_t  IsCUDADevice;
    uint8_t  IsOpenCLDevice;
    uint8_t  IsCPUDevice;
    uint8_t  Reserved1;
} MFNDeviceInformation;

class MFNCommandLineData {
private:
    uint32_t HashType;
    std::string HashTypeString;
    
    std::string HashListFileName;

    std::string CharsetFileName;
    char UseCharsetMulti;

    std::string OutputFileName;

    std::string UnfoundOutputFileName;

    char AddHexOutput;

    // Server mode enabled
    char IsNetworkServer;
    // Server mode - do NOT use GPU/CPU threads - serve only.
    char IsServerOnly;
    // Is a network client
    char IsNetworkClient;

    std::string NetworkRemoteHost;
    uint16_t NetworkPort;


    std::string RestoreFileName;

    // Vector of active devices to use.
    std::vector<MFNDeviceInformation> DevicesToUse;

    uint32_t TargetExecutionTimeMs;

    int DefaultCUDABlocks;
    int DefaultCUDAThreads;

    char UseLookupTable;

    char Verbose;

    char Silent;
    char Daemon;

    char Debug;
    char DevDebug;

    int MinPasswordLength;
    int MaxPasswordLength;

    int WorkunitBits;

    char UseZeroCopy; // Force zero copy memory for integrated GPUs.

    // Force BFI_INT patching on ATI
    char UseBFIIntPatching;
    
public:
    MFNCommandLineData();
    ~MFNCommandLineData();

    // Parses the command line.  Returns 0 for failure, 1 for success.
    int ParseCommandLine(int argc, char *argv[]);


    // Getters, all the setting is done in ParseCommandLine
    uint32_t GetHashType() {
        return this->HashType;
    }
    std::string GetHashTypeString() {
        return this->HashTypeString;
    }

    std::string GetHashListFileName() {
        return this->HashListFileName;
    }

    std::string GetCharsetFileName() {
        return this->CharsetFileName;
    }
    char GetUseCharsetMulti() {
        return this->UseCharsetMulti;
    }

    std::string GetOutputFileName() {
        return this->OutputFileName;
    }

    std::string GetUnfoundOutputFileName() {
        return this->UnfoundOutputFileName;
    }

    std::string GetRestoreFileName() {
        return this->RestoreFileName;
    }

    char GetAddHexOutput() {
        return this->AddHexOutput;
    }

    int GetTargetExecutionTimeMs() {
        return this->TargetExecutionTimeMs;
    }
    
    int GetGpuBlocks() {
        return this->DefaultCUDABlocks;
    }
    
    int GetGpuThreads() {
        return this->DefaultCUDAThreads;
    }

    std::vector<MFNDeviceInformation> GetDevicesToUse() {
        return this->DevicesToUse;
    }

    char GetUseLookupTable() {
        return this->UseLookupTable;
    }

    char GetVerbose() {
        return this->Verbose;
    }
    char GetSilent() {
        return this->Silent;
    }
    char GetDaemon() {
        return this->Daemon;
    }
    char GetDebug() {
        return this->Debug;
    }
    char GetDevDebug() {
        return this->DevDebug;
    }
    int GetMinPasswordLength() {
        return this->MinPasswordLength;
    }
    int GetMaxPasswordLength() {
        return this->MaxPasswordLength;
    }

    char GetUseZeroCopy() {
        return this->UseZeroCopy;
    }
    char GetUseBfiInt() {
        return this->UseBFIIntPatching;
    }

    // Returns zero if not set
    int GetWorkunitBits() {
        return this->WorkunitBits;
    }

    char GetIsNetworkServer() {
        return this->IsNetworkServer;
    }
    char GetIsNetworkClient() {
        return this->IsNetworkClient;
    }
    char GetIsServerOnly() {
        return this->IsServerOnly;
    }
    std::string GetNetworkRemoteHostname() {
        return this->NetworkRemoteHost;
    }
    uint16_t GetNetworkPort() {
        return this->NetworkPort;
    }

    std::vector<uint8_t> GetRestoreData(int passLength);
    void SetDataFromRestore(std::vector<uint8_t>);
};


#endif
