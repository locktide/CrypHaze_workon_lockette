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

#ifndef __MFNCLASSFACTORY_H__
#define __MFNCLASSFACTORY_H__

/**
 * @section DESCRIPTION
 *
 * This file implements a basic hash factory for the new Cryptohaze Multiforcer.
 *
 * The factory will be a global class, and will be accessed by all classes,
 * removing the need for the setClass type functions.  This should clean
 * code and ensure that everyone gets what they need.
 *
 * This class will return the default type of class unless another type has been
 * specified before the class is returned.  Classes will have a unique ID
 * assigned to them.  Or something.  Still working on details.
 */

#include <stdlib.h>
#include <stdint.h>


// Forward declare classes
class CHCharsetNew;
class CHWorkunitBase;
class MFNDisplay;
class CHHashFileV;
class MFNCommandLineData;
class CHCUDAUtils;
class MFNHashIdentifiers;

// Defines for class types
#include "MFN_Common/MFNDefines.h"


class MFNClassFactory {
public:
    MFNClassFactory();

    /**
     * Set the Charset class type.  Returns true on success, false on failure.
     */
    void setCharsetClassType(uint32_t newCharsetClassId) {
        this->CharsetClassId = newCharsetClassId;
    }
    CHCharsetNew *getCharsetClass() {
        if (!this->CharsetClass) {
            this->createCharsetClass();
        }
        return this->CharsetClass;
    }

    void setWorkunitClassType(uint32_t newWorkunitClassId) {
        this->WorkunitClassId = newWorkunitClassId;
    }

    CHWorkunitBase *getWorkunitClass() {
        if (!this->WorkunitClass) {
            this->createWorkunitClass();
        }
        return this->WorkunitClass;
    }
    
    void setDisplayClassType(uint32_t newDisplayClassId) {
        this->DisplayClassId = newDisplayClassId;
    }
    
    MFNDisplay *getDisplayClass() {
        if (!this->DisplayClass) {
            this->createDisplayClass();
        }
        return this->DisplayClass;
    }

    void setHashfileClassType(uint32_t newHashfileClassId) {
        this->HashfileClassId = newHashfileClassId;
    }

    CHHashFileV *getHashfileClass() {
        if (!this->HashfileClass) {
            this->createHashfileClass();
        }
        return this->HashfileClass;
    }

    void setCommandlinedataClassType(uint32_t newCommandlinedataClassId) {
        this->CommandlinedataClassId = newCommandlinedataClassId;
    }

    MFNCommandLineData *getCommandlinedataClass() {
        if (!this->CommandlinedataClass) {
            this->createCommandlinedataClass();
        }
        return this->CommandlinedataClass;
    }

    void setCudaUtilsClassType(uint32_t newCudaUtilsClassId) {
        this->CudaUtilsClassId = newCudaUtilsClassId;
    }
    
    CHCUDAUtils *getCudaUtilsClass() {
        if (!this->CudaUtilsClass) {
            this->createCudaUtilsClass();
        }
        return this->CudaUtilsClass;
    }

    void setHashIdentifiersClassType(uint32_t newHashIdentifiersClassId) {
        this->HashIdentifiersClassId = newHashIdentifiersClassId;
    }
    
    MFNHashIdentifiers *getHashIdentifiersClass() {
        if (!this->HashIdentifiersClass) {
            this->createHashIdentifiersClass();
        }
        return this->HashIdentifiersClass;
    }
protected:
    // Charset class variables
    void createCharsetClass();
    uint32_t CharsetClassId;
    CHCharsetNew *CharsetClass;

    // Workunit variables
    void createWorkunitClass();
    uint32_t WorkunitClassId;
    CHWorkunitBase *WorkunitClass;
    
    // Display classes
    void createDisplayClass();
    uint32_t DisplayClassId;
    MFNDisplay *DisplayClass;

    // Hashfile classes
    void createHashfileClass();
    uint32_t HashfileClassId;
    CHHashFileV *HashfileClass;

    // Command line data
    void createCommandlinedataClass();
    uint32_t CommandlinedataClassId;
    MFNCommandLineData *CommandlinedataClass;
    
    //CHCUDAUtils data
    void createCudaUtilsClass();
    uint32_t CudaUtilsClassId;
    CHCUDAUtils *CudaUtilsClass;

    //CHCUDAUtils data
    void createHashIdentifiersClass();
    uint32_t HashIdentifiersClassId;
    MFNHashIdentifiers *HashIdentifiersClass;
};


#endif

