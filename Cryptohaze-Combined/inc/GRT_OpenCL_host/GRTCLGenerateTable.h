/*
Cryptohaze GPU Rainbow Tables
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

#ifndef _GRTCLGENERATETABLE_H
#define _GRTCLGENERATETABLE_H

#include "GRT_OpenCL_host/GRTCLGenCommandLineData.h"
#include "GRT_Common/GRTCharsetSingle.h"
#include "OpenCL_Common/GRTOpenCL.h"
#include "CH_Common/CHRandom.h"


#ifdef __APPLE_CC__
#include <OpenCL/cl.h>
#else
#include <CL/cl.h>
#endif

#include <string>
#include <vector>

// Password types: NORMAL is a normally packed password,
// NTLM is the utf16le encoding
#define PASSWORD_TYPE_NORMAL 0
#define PASSWORD_TYPE_NTLM 1

typedef uint32_t UINT4;

// This is a generic class for all hash types.  Tweak as needed.
class GRTCLGenerateTable {
protected:
    // The length of the hash output block.  Should be a multiple of 4.
    int HashOutputBlockLengthBytes;
    // The length of the password input block.  Should be a multiple of 4.
    int PasswordInputBlockLengthBytes;

    unsigned char *HOST_Initial_Passwords;
    unsigned char *HOST_End_Hashes;

    cl_mem DEVICE_Initial_Passwords;
    cl_mem DEVICE_End_Hashes;
    cl_mem DEVICE_Charset;

    GRTCLGenCommandLineData *TableParameters;
    GRTCharsetSingle *Charset;
    CryptohazeOpenCL *OpenCL;
    CHRandom *RandomGenerator;

    //===== Functions that are mostly the same ===
    // These functions are basically the same for all hash types.

    // Generates the initial passwords.
    // Specify the type to generate: NORMAL or NTLM
    virtual void generateInitialPasswords(int passwordType);

    // Allocates space for the host and device hashes.
    // Also sets the device being used.
    virtual void mallocDeviceAndHostSpace();
    // And undo it.
    virtual void freeDeviceAndHostSpace();

    //===== Per Hash Functions ====
    // These need to be implemented by the specific hash type being used.

    virtual std::vector<std::string> getHashFileName() = 0;
    virtual std::string getHashKernelName() = 0;

public:
    GRTCLGenerateTable(int hashLengthBytes, int passwordLengthBytes);
    ~GRTCLGenerateTable();
    // Actually create the tables.
    virtual void createTables();
    //  Set the table parameter structure to the created one.
    virtual void setGRTCLGenCommandLineData(GRTCLGenCommandLineData *NewTableParameters);
    virtual void setGRTCLCharsetSingle(GRTCharsetSingle *NewCharset);
    virtual void setOpenCL(CryptohazeOpenCL *newOpenCL);

    virtual void setRandomGenerator(CHRandom *newRandomGenerator) {
        this->RandomGenerator = newRandomGenerator;
    }
};

#endif
