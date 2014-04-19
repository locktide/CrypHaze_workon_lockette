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

#include "GRT_CUDA_host/GRTCrackCommandLineData.h"
#include <stdio.h>
#include <stdlib.h>
#include "GRT_Common/GRTCommon.h"
#include <string.h>
#include <cuda.h>
#include <cutil.h>
#include <cutil_inline.h>
#include <cuda_runtime_api.h>
#include <valarray>
#include <vector>
#include <string>


#ifdef _WIN32
#include "argtable2-13/src/argtable2.h"
#else
#include <argtable2.h>
#endif



GRTCrackCommandLineData::GRTCrackCommandLineData() {
    this->HashType = NULL;
    memset(this->Hash, 0, sizeof(this->Hash));
    this->KernelTimeMs = 0;
    this->CUDABlocks = 0;
    this->CUDAThreads = 0;
    this->CUDAUseZeroCopy = 0;
    this->Autotune = 0;
    this->CommandLineValid = 0;
    this->Table_File_Count = 0;
    this->Current_Table_File = 0;
    this->Table_Filenames = NULL;

    this->Verbose = 0;
    this->Silent = 0;
    
    this->useHashFile = 0;

    this->useOutputHashFile = 0;

    this->AddHexOutput = 0;

    this->Debug = 0;
    this->DeveloperDebug = 0;

    this->DebugDump = 0;

    this->NumberPrefetchThreads = 1;
    this->useWebTable = 0;

    this->GRTHashTypes = new GRTHashes();
    this->TableHeader = NULL;
    this->CandidateHashesToSkip = 0;
}
GRTCrackCommandLineData::~GRTCrackCommandLineData() {

}

int GRTCrackCommandLineData::ParseCommandLine(int argc, char *argv[]) {
    int deviceCount, i;
    std::vector<std::string> webTableFilenames;

    // Check for a supported CUDA device
    cudaGetDeviceCount(&deviceCount);
    if (deviceCount == 0) {
      printf("This program requires a CUDA-capable video card.\nNo cards found.  Sorry.  Exiting.\n");
      printf("This is currently built against CUDA 3.2 and requires at least\n");
      printf("the version 260 drivers to work.  Try updating if you have a CUDA card.\n");
      exit(1);
    }
    this->CUDANumberDevices = deviceCount;


    // Command line argument parsing with argtable
    struct arg_lit *verbose = arg_lit0("v", "verbose", "verbose output");
    struct arg_lit *silent = arg_lit0(NULL, "silent", "silence all output");

    // Table related options
    struct arg_file *table_file = arg_filen(NULL,NULL,"<file>", 0, 10000, "GRT Tables to use");

    struct arg_file *hash_file = arg_file0("f","hashfile","<file>", "Hashfile to use");

    struct arg_str *hash_value = arg_str0("s", "hashstring", "hashstring", "The hash string");
    struct arg_str *hash_type = arg_str1("h", "hashtype", "{NTLM, MD4, MD5, SHA1}", "hash type to crack");

    // CUDA related params
    struct arg_int *device = arg_int0("d", "device", "<n>", "CUDA device to use");
    struct arg_int *m = arg_int0("m", "ms", "<n>", "target step time in ms");
    struct arg_int *blocks = arg_int0("b", "blocks", "<n>", "number of thread blocks to run");
    struct arg_int *threads = arg_int0("t", "threads", "<n>", "number of threads per block");
    //struct arg_lit *autotune = arg_lit0(NULL, "autotune", "autotune for maximum performance");
    struct arg_lit *zerocopy = arg_lit0("z", "zerocopy", "use zerocopy memory");
    struct arg_file *o = arg_file0("o", "outputfile", "outputfile", "output file for results");
    // hexoutput: Adds hex output to all password outputs.
    struct arg_lit *hex_output = arg_lit0(NULL, "hexoutput", "Adds hex output to all hash outputs");

    struct arg_lit *debug = arg_lit0(NULL, "debug", "Use debug display class");
    struct arg_lit *devdebug = arg_lit0(NULL, "devdebug", "Developer debugging output");
    struct arg_str *debugfiles = arg_str0(NULL, "debugdumpfiles", "<filename>", "Filename base to dump candidates and chains to");

    struct arg_int *prefetch_count = arg_int0(NULL, "prefetch", "<n>", "number of prefetch threads");
    struct arg_int *candidates_to_skip = arg_int0(NULL, "skip", "<n>", "number of candidate hashes to skip");

    struct arg_str *table_url = arg_str0(NULL, "tableurl", "<URL>", "URL of the web table script");
    struct arg_str *table_username = arg_str0(NULL, "tableusername", "<username>", "Username, if required, for the web table script");
    struct arg_str *table_password = arg_str0(NULL, "tablepassword", "<password>", "Password, if required, for the web table script");

    struct arg_end *end = arg_end(20);
    void *argtable[] = {verbose,silent,table_file,hash_value,hash_file,hash_type,device,
        m,blocks,threads,zerocopy,o,hex_output,debug,devdebug,prefetch_count,
        table_url,table_username,table_password,candidates_to_skip,debugfiles,end};

    // Get arguments, collect data, check for basic errors.
    if (arg_nullcheck(argtable) != 0) {
      printf("error: insufficient memory\n");
    }
    // Look for errors
    int nerrors = arg_parse(argc,argv,argtable);
    if (nerrors > 0) {
      // Print errors, exit.
      arg_print_errors(stdout,end,argv[0]);
      //arg_print_syntax(stdout,argtable,"\n\n");
      printf("\n\nOptions: \n");
      arg_print_glossary(stdout,argtable,"  %-20s %s\n");
      exit(1);
    }

    // Verbose & silent
    if (verbose->count) {
        this->Verbose = 1;
    }
    if (silent->count) {
        this->Silent = 1;
    }
    if (zerocopy->count) {
        this->CUDAUseZeroCopy = 1;
    }
    if (debug->count) {
        this->Debug = 1;
    }
    if (devdebug->count) {
        this->Debug = 1;
        this->DeveloperDebug = 1;
    }
    if (debugfiles->count) {
        this->DebugDump = 1;
        this->DebugDumpFilenameBase = *debugfiles->sval;
    }
    if (prefetch_count->count) {
        this->NumberPrefetchThreads = *prefetch_count->ival;
    }
    if (candidates_to_skip->count) {
            this->CandidateHashesToSkip = *candidates_to_skip->ival;
    }

    // Web table stuff
    if (table_url->count) {
        this->useWebTable = 1;
        this->tableURL = *table_url->sval;
        // If someone has NOT specified the candidates to skip, set to default.
        if (!candidates_to_skip->count) {
                this->CandidateHashesToSkip = DEFAULT_CANDIDATES_TO_SKIP;
        }
    }
    if (table_username->count) {
        this->tableUsername = *table_username->sval;
    }
    if (table_password->count) {
        this->tablePassword = *table_password->sval;
    }


    this->HashType = this->GRTHashTypes->GetHashIdFromString(*hash_type->sval);
    if (this->HashType == -1) {
        printf("Unknown hash type %s: Exiting.\n\n", *hash_type->sval);
        exit(1);
    }
    
    if ((hash_value->count) && (strlen(*hash_value->sval) != 32)) {
        printf("Hash string is not 32 hex characters. Exiting.\n\n");
        exit(1);
    }

    if (hash_value->count) {
        convertAsciiToBinary(*hash_value->sval, this->Hash, 16);
    } else if (hash_file->count) {
        this->hashFileName = hash_file->filename[0];
        this->useHashFile = 1;
    } else {
        printf("Must provide a hash value or a hash file!\n");
        exit(1);
    }

    if (o->count) {
        this->outputHashFileName = o->filename[0];
        this->useOutputHashFile = 1;
    }

    // Desired kernel time
    if (m->count) {
        this->KernelTimeMs = *m->ival;
    }

    // Blocks
    if (blocks->count) {
        this->CUDABlocks = *blocks->ival;
    }

    // Threads
    if (threads->count) {
        this->CUDAThreads = *threads->ival;
    }

    if (hex_output->count) {
        this->AddHexOutput = 1;
    }


    // Allocate space for the list of pointers
    this->Table_File_Count = table_file->count;
    this->Table_Filenames = (char **)malloc(this->Table_File_Count * sizeof(char *));

    // Create the table header type
    if (this->useWebTable) {
        this->TableHeader = new GRTTableHeaderVWeb();
        this->TableHeader->setWebURL(this->tableURL);
        this->TableHeader->setWebUsername(this->tableUsername);
        this->TableHeader->setWebPassword(this->tablePassword);

        GRTTableHeaderVWeb *WebTableHeader =
                (GRTTableHeaderVWeb *)this->TableHeader;
        webTableFilenames = WebTableHeader->getHashesFromServerByType(this->HashType);
    } else {
        // V1 will work for both V1 & V2 types
        this->TableHeader = new GRTTableHeaderV1();
    }

    // If we don't have any table filenames, get the ones from the web.
    // Note: The script ONLY reutrns valid tables.
    if ((table_file->count == 0) && this->useWebTable) {
        this->Table_File_Count = webTableFilenames.size();
        this->Table_Filenames = (char **)malloc(this->Table_File_Count * sizeof(char *));
        for (i = 0; i < this->Table_File_Count; i++) {
            // Increment size by 1 for null termination
            this->Table_Filenames[i] = (char *)malloc((webTableFilenames.at(i).size() + 1) * sizeof(char));
            strcpy(this->Table_Filenames[i], webTableFilenames.at(i).c_str());
        }
    } else {
        this->Table_File_Count = table_file->count;
        this->Table_Filenames = (char **)malloc(this->Table_File_Count * sizeof(char *));
        // Handle the file list sanely
        for (i = 0; i < table_file->count; i++) {
            // Check to ensure the file is valid
            if (!this->TableHeader->isValidTable(table_file->filename[i], -1)) {
                printf("%s is not a valid GRT table!  Exiting.\n", table_file->filename[i]);
                exit(1);
            }
            // Check to ensure the file is of the right type
            if (!this->TableHeader->isValidTable(table_file->filename[i], this->HashType)) {
                printf("%s is not a valid %s GRT table!\n", table_file->filename[i],
                        this->GRTHashTypes->GetHashStringFromId(this->HashType));
                exit(1);
            }

            // Increment size by 1 for null termination
            this->Table_Filenames[i] = (char *)malloc((strlen(table_file->filename[i]) + 1) * sizeof(char));
            strcpy(this->Table_Filenames[i], table_file->filename[i]);
        }
    }
}

int GRTCrackCommandLineData::getHashType() {
    return this->HashType;
}
unsigned int GRTCrackCommandLineData::getKernelTimeMs() {
    return this->KernelTimeMs;
}
unsigned int GRTCrackCommandLineData::getCUDABlocks() {
    return this->CUDABlocks;
}
unsigned int GRTCrackCommandLineData::getCUDAThreads() {
    return this->CUDAThreads;
}
const char *GRTCrackCommandLineData::getNextTableFile() {
    char *returnValue;
    const char *returnConstValue;

    returnValue = new char[strlen(this->Table_Filenames[this->Current_Table_File]) + 1];

    strcpy(returnValue, this->Table_Filenames[this->Current_Table_File]);

    this->Current_Table_File++;

    returnConstValue = (const char *)returnValue;

    return returnConstValue;
}
unsigned char *GRTCrackCommandLineData::getHash() {
    unsigned char *hashToReturn;
    int i;

    hashToReturn = new unsigned char[16];

    for (i = 0; i < 16; i++) {
        hashToReturn[i] = this->Hash[i];
    }
    return hashToReturn;
}
int GRTCrackCommandLineData::getNumberOfTableFiles() {
    return this->Table_File_Count;
}
char GRTCrackCommandLineData::getIsSilent() {
    return this->Silent;
}

int GRTCrackCommandLineData::getCudaNumberDevices() {
    return this->CUDANumberDevices;
}

char GRTCrackCommandLineData::GetUseZeroCopy() {
    return this->CUDAUseZeroCopy;
}

char GRTCrackCommandLineData::getUseHashFile() {
    return this->useHashFile;
}

string GRTCrackCommandLineData::getHashFileName() {
    return this->hashFileName;
}

char GRTCrackCommandLineData::getUseOutputHashFile() {
    return this->useOutputHashFile;
}
string GRTCrackCommandLineData::getOutputHashFile() {
    return this->outputHashFileName;
}
char GRTCrackCommandLineData::getAddHexOutput() {
    return this->AddHexOutput;
}