// New Multiforcer main file.



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


// Main code for the Cryptohaze Multiforcer.



#include "MFN_Common/MFNCommandLineData.h"
#include "CUDA_Common/CHCudaUtils.h"
#include "CH_Common/CHWorkunitRobust.h"
#include "CH_Common/CHWorkunitNetwork.h"

#include "MFN_Common/MFNDisplayDebug.h"

#include "CH_Common/CHCharsetNew.h"
#include "MFN_Common/MFNHashType.h"
#include "MFN_Common/MFNHashTypePlain.h"
#include "MFN_CUDA_host/MFNHashTypePlainCUDA_MD5.h"
#include "MFN_OpenCL_host/MFNHashTypePlainOpenCL_MD5.h"
#include "CH_HashFiles/CHHashFileVPlain.h"

#include "MFN_Common/MFNMultiforcerClassFactory.h"
#include "MFN_Common/MFNHashClassLauncher.h"

#if USE_NETWORK
#include "Multiforcer_Common/CHNetworkServer.h"
#include "Multiforcer_Common/CHNetworkClient.h"
#endif

#include "CUDA_Common/CHCudaUtils.h"

// global_commands is a way of communicating across all threads.
// It handles exit requests and error handling.
struct global_commands global_interface;

/**
 * Global class factory.
 */
MFNClassFactory MultiforcerGlobalClassFactory;

// Ctrl-C handler.  Terminate cleanly.
void terminate_process(int sig) {
    // Set the exit value to 1 to force all threads to exit.
    global_interface.exit = 1;
    global_interface.user_exit = 1;
}

// Runs the multiforcer in standalone or network server mode.
void runStandaloneOrServerMode(MFNCommandLineData *CommandLineData) {
    int i;

    CHCharsetNew *Charset;
    CHWorkunitBase *Workunit;
    CHHashFileV *HashFile;
    MFNDisplay *Display;
    //MFNHashType *HashDeviceClass;
    //char printBuffer[1000];
    //CHHashes HashTypes;
    MFNHashClassLauncher HashClassLauncher;
    MFNHashIdentifiers *HashIdentifiers;
    
    uint32_t hashId;

    int maxPasswordLength = 0;

    // Default size.  May be overridden.
    int WorkunitSize = 32;
    std::vector<uint8_t> RestoreData;
    std::string ResumeFilename;

    {
        char ResumeTimestampBuffer[1024];
        struct timeval resume_time;
        time_t resume_time_t;
        // Get the resume filename with timestamp.
        gettimeofday(&resume_time, NULL);
        resume_time_t=resume_time.tv_sec;
        memset(ResumeTimestampBuffer, 0, sizeof(ResumeTimestampBuffer));
        strftime(ResumeTimestampBuffer, 128, "%Y-%m-%d-%H-%M-%S", localtime(&resume_time_t));
        ResumeFilename = "CM-Resume-";
        ResumeFilename += ResumeTimestampBuffer;
        ResumeFilename += ".mfr";
    }

    // Determine the hash type
    HashIdentifiers = MultiforcerGlobalClassFactory.getHashIdentifiersClass();
    if (!HashIdentifiers) {
        printf("Cannot get hash identifiers class!\n");
        exit(1);
    }
    hashId = HashIdentifiers->GetHashIdFromString(CommandLineData->GetHashTypeString());
    if (hashId == MFN_HASHTYPE_UNDEFINED) {
        printf("Invalid hash type %s!\n", CommandLineData->GetHashTypeString().c_str());
        HashIdentifiers->PrintAllHashTypes();
        exit(1);
    }

    

    // Get our classes
    MultiforcerGlobalClassFactory.setCharsetClassType(CH_CHARSET_NEW_CLASS_ID);
    MultiforcerGlobalClassFactory.setDisplayClassType(MFN_DISPLAY_CLASS_DEBUG);
    MultiforcerGlobalClassFactory.setWorkunitClassType(CH_WORKUNIT_ROBUST_CLASS_ID);

    // Set up the hash specific stuff.
    MultiforcerGlobalClassFactory.setHashfileClassType(HashIdentifiers->GetHashData().HashFileIdentifier);
    HashClassLauncher.setHashType(HashIdentifiers->GetHashData().HashTypeIdentifier);

    
    Charset = MultiforcerGlobalClassFactory.getCharsetClass();
    if (!Charset) {
        printf("Cannot get charset class!\n");
        exit(1);
    }

    Workunit = MultiforcerGlobalClassFactory.getWorkunitClass();
    if (!Workunit) {
        printf("Cannot get workunit class!\n");
        exit(1);
    }
    HashFile = MultiforcerGlobalClassFactory.getHashfileClass();
    if (!HashFile) {
        printf("Cannot get hashfile class!\n");
        exit(1);
    }

    Display = MultiforcerGlobalClassFactory.getDisplayClass();
    if (!Display) {
        printf("Cannot get display class!\n");
        exit(1);
    }
    

    if (CommandLineData->GetDevDebug()) {
        Workunit->EnableDebugOutput();
    }
    
    

/*
    if (CommandLineData->GetUseRestoreFile()) {
        if (!RobustWorkunit->LoadStateFromFile(CommandLineData->GetRestoreFileName())) {
            printf("Loading state from file failed.\n");
            exit(1);
        }
        RestoreData = RobustWorkunit->GetResumeMetadata();
        CommandLineData->SetDataFromRestore(RestoreData);
        // Overwrite the existing one as we progress.
        RobustWorkunit->SetResumeFile(ResumeFilename);
    } else {
        RobustWorkunit->SetResumeFile(ResumeFilename);
    }
*/

    // Set the hash type being used.
    //HashTypes.SetHashId(CommandLineData->GetHashType());

    // Get the HashType class and HashFile class

    /*


*/

    // If an output file is to be used, set it here.
    if (CommandLineData->GetOutputFileName().length()) {
        HashFile->SetFoundHashesOutputFilename(CommandLineData->GetOutputFileName());
    }
    // If the workunit size was set on the command line, use it here.
    if (CommandLineData->GetWorkunitBits()) {
        WorkunitSize = CommandLineData->GetWorkunitBits();
    }

    if (!Charset->readCharsetFromFile(CommandLineData->GetCharsetFileName())) {
        printf("Cannot open charset!\n");
        exit(1);
    }
    //printf("Charset opened properly.\n");
    
    if (!HashFile->OpenHashFile(CommandLineData->GetHashListFileName())) {
        printf("Cannot open hash file!\n");
        exit(1);
    }
    //printf("Hashfile opened properly.\n");
    

    // Add hex output option if desired.
    HashFile->SetAddHexOutput(CommandLineData->GetAddHexOutput());


    /*
    HashType->setCharset(Charset);
    HashType->setCommandLineData(CommandLineData);
    HashType->setHashFile(HashFile);
    HashType->setWorkunit(RobustWorkunit);

    // If we are using debug, set the display to that mode.
    if (CommandLineData->GetDebug()) {
        Display = new CHMultiforcerDisplayDebug();
    } else {
        // Normal curses output
        Display = new CHMultiforcerDisplay();
    }

#if USE_NETWORK
    Network = NULL;
    // If requested bring the network online and assign types to it
    if (CommandLineData->GetIsNetworkServer()) {
        Network = new CHNetworkServer(CommandLineData->GetNetworkPort());

        Network->setCharset(Charset);
        Network->setCommandLineData(CommandLineData);
        Network->setHashFile(HashFile);
        Network->setWorkunit(RobustWorkunit);
        Network->setDisplay(Display);
        Network->setHashTypeId(CommandLineData->GetHashType());

        Network->startNetwork();

        // Update the display with the server info.
        char portBuffer[16];
        sprintf(portBuffer, "%d", CommandLineData->GetNetworkPort());
        Display->setSystemMode(SYSTEM_MODE_SERVER, portBuffer);
    }
#endif
*/
    //HashDeviceClass->setDisplay(Display);

    Display->setHashName(HashIdentifiers->GetHashData().HashDescriptor);
    
    if (!HashClassLauncher.addAllDevices(CommandLineData->GetDevicesToUse())) {
        printf("Cannot add devices!\n");
        exit(1);
    }



/*
    // Add a few GPU threads
    if (CommandLineData->GetDebug()) {
        // If debug is in use, use the CUDA device ID.  Default 0.
        HashType->addGPUDeviceID(CommandLineData->GetCUDADevice());
    } else {
        for (i = 0; i < CommandLineData->GetCUDANumberDevices(); i++) {
            HashType->addGPUDeviceID(i);
            Display->setThreadCrackSpeed(i, GPU_THREAD, 0.00);
        }
    }

    // Catch Ctrl-C and handle it gracefully
    signal(SIGINT, terminate_process);

    // If a max length has been set, use it.
    // Otherwise just set to the max supported length.
    if (CommandLineData->GetMaxPasswordLength()) {
        maxPasswordLength = CommandLineData->GetMaxPasswordLength();
    } else {
        maxPasswordLength = HashTypes.GetMaxSupportedLength();
    }
*/
    maxPasswordLength = CommandLineData->GetMaxPasswordLength();
    for (i = CommandLineData->GetMinPasswordLength(); i <= maxPasswordLength; i++) {
        uint64_t NumberOfPasswords;
        
        Display->setPasswordLen(i);
        /*
        // Set the status line to indicate where we are.
        sprintf(printBuffer, "Starting pw len %d", i);
        Display->addStatusLine(printBuffer);

        // If no hashes are left, exit.
        if (HashFile->GetUncrackedHashCount() == 0) {
            global_interface.exit = 1;
            strcpy(global_interface.exit_message, "All hashes found!  Exiting!\n");
            break;
        }

#if USE_NETWORK
        // Set the network support for the password length
        if (CommandLineData->GetIsNetworkServer()) {
            Network->setPasswordLength(i);
        }
#endif
        */
        NumberOfPasswords = Charset->getPasswordSpaceSize(i);
        if (global_interface.exit) {
            break;
        }
/*
        // Provide the correct metadata to the workunit class
        RestoreData = CommandLineData->GetRestoreData(i);
        RobustWorkunit->SetResumeMetadata(RestoreData);

        // If we are NOT restoring, create new workunits.
        if (!CommandLineData->GetUseRestoreFile()) {
            RobustWorkunit->CreateWorkunits(NumberOfPasswords, WorkunitSize, i);
        }

        if (global_interface.exit) {
            break;
        }
*/
        Workunit->CreateWorkunits(NumberOfPasswords, WorkunitSize, i);
        //Display->setWorkunitsTotal(Workunit->GetNumberOfWorkunits());
        //Display->setWorkunitsCompleted(Workunit->GetNumberOfCompletedWorkunits());

        HashClassLauncher.launchThreads(i);
        //HashClassLauncher.getClassById(0)->crackPasswordLength(i);
        //HashDeviceClass->crackPasswordLength(i);

        if (global_interface.exit) {
            break;
        }
    }

    delete Workunit;
    delete Display;

    HashFile->PrintAllFoundHashes();
    /*
    // If we are outputting unfound hashes, do it now.
    if (CommandLineData->GetUseUnfoundOutputFile()) {
        HashFile->OutputUnfoundHashesToFile(CommandLineData->GetUnfoundOutputFileName());
    }
*/
}



int main(int argc, char *argv[]) {

    MFNCommandLineData *CommandLineData;

    // Init the global stuff
    global_interface.exit = 0;
    global_interface.user_exit = 0;
    global_interface.pause = 0;
    memset(global_interface.exit_message, 0, sizeof(global_interface.exit_message));

    CommandLineData = MultiforcerGlobalClassFactory.getCommandlinedataClass();

    // Get the command line data.  If not success, fail.
    if (!CommandLineData->ParseCommandLine(argc, argv)) {
        exit(1);
    }

    // Catch Ctrl-C and handle it gracefully
    signal(SIGINT, terminate_process);

    runStandaloneOrServerMode(CommandLineData);
  
    // If there is a message to print, terminate.
    if (strlen(global_interface.exit_message)) {
        printf("\n\nTerminating due to error: %s\n", global_interface.exit_message);
    }
}
