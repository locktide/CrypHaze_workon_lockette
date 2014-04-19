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


#include "MFN_Common/MFNMultiforcerClassFactory.h"

#include "CH_Common/CHCharsetNew.h"

#include "CH_Common/CHWorkunitRobust.h"
#include "CH_Common/CHWorkunitNetwork.h"

#include "MFN_Common/MFNDisplayDaemon.h"
#include "MFN_Common/MFNDisplayDebug.h"
#include "MFN_Common/MFNDisplayCurses.h"

#include "CH_HashFiles/CHHashFileVPlain.h"
#include "CH_HashFiles/CHHashFileVLM.h"

#include "MFN_CUDA_host/MFNHashTypePlainCUDA_MD5.h"

#include "MFN_OpenCL_host/MFNHashTypePlainOpenCL_MD5.h"

#include "MFN_Common/MFNCommandLineData.h"
#include "MFN_Common/MFNHashIdentifiers.h"

#include "CUDA_Common/CHCudaUtils.h"

MFNClassFactory::MFNClassFactory() {
        // Charset class: Default CHCharsetNew
        this->CharsetClass = NULL;
        this->CharsetClassId = CH_CHARSET_NEW_CLASS_ID;

        // Workunit class: Default CHWorkunitRobust
        this->WorkunitClass = NULL;
        this->WorkunitClassId = CH_WORKUNIT_ROBUST_CLASS_ID;
        
        this->DisplayClass = NULL;
        this->DisplayClassId = MFN_DISPLAY_CLASS_NCURSES;

        this->HashfileClass = NULL;
        this->HashfileClassId = NULL;

        this->CommandlinedataClass = NULL;
        this->CommandlinedataClassId = CH_COMMANDLINEDATA;
        
        this->CudaUtilsClass = NULL;
        this->CudaUtilsClassId = CH_CUDAUTILS;

        this->HashIdentifiersClass = NULL;
        this->HashIdentifiersClassId = MFN_HASHIDENTIFIERS;
    }

/**
 * Creates the charset class.  If an invalid ID is present, leaves it null.
 */
void MFNClassFactory::createCharsetClass() {
   switch(this->CharsetClassId) {
       case CH_CHARSET_NEW_CLASS_ID:
           this->CharsetClass = new CHCharsetNew();
           break;
       default:
           this->CharsetClass = NULL;
           break;
   }
}

/**
 * Creates the workunit class.
 */
void MFNClassFactory::createWorkunitClass() {
    switch(this->WorkunitClassId) {
        case CH_WORKUNIT_ROBUST_CLASS_ID:
            this->WorkunitClass = new CHWorkunitRobust();
            break;
        case CH_WORKUNIT_NETWORK_CLASS_ID:
            this->WorkunitClass = new CHWorkunitNetworkClient();
            break;
        default:
            this->WorkunitClass = NULL;
            break;
    }
}


void MFNClassFactory::createDisplayClass() {
    switch(this->DisplayClassId) {
        case MFN_DISPLAY_CLASS_NCURSES:
            this->DisplayClass = NULL; //new MFNDisplayCurses();
            break;
        case MFN_DISPLAY_CLASS_DEBUG:
            this->DisplayClass = new MFNDisplayDebug();
            break;
        case MFN_DISPLAY_CLASS_DAEMON:
            this->DisplayClass = NULL; //new MFNDisplayDaemon();
            break;
        default:
            this->DisplayClass = NULL;
            break;
    }
}

void MFNClassFactory::createHashfileClass() {
    switch (this->HashfileClassId) {
        case CH_HASHFILE_PLAIN_16:
            this->HashfileClass = new CHHashFileVPlain(16);
            break;
        case CH_HASHFILE_LM:
            this->HashfileClass = new CHHashFileVPlainLM();
            break;
        default:
            this->HashfileClass = NULL;
            break;
    }
}

void MFNClassFactory::createCommandlinedataClass() {
    switch (this->CommandlinedataClassId) {
        case CH_COMMANDLINEDATA:
            this->CommandlinedataClass = new MFNCommandLineData();
            break;
        default:
            this->CommandlinedataClass = NULL;
            break;
    }
}


void MFNClassFactory::createCudaUtilsClass() {
    switch(this->CudaUtilsClassId) {
        case CH_CUDAUTILS:
            this->CudaUtilsClass = new CHCUDAUtils();
            break;
        default:
            this->CudaUtilsClass = NULL;
            break;
    }
}

void MFNClassFactory::createHashIdentifiersClass() {
    switch(this->HashIdentifiersClassId) {
        case MFN_HASHIDENTIFIERS:
            this->HashIdentifiersClass = new MFNHashIdentifiers();
            break;
        default:
            this->HashIdentifiersClass = NULL;
            break;
    }
}
