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

// Main CUDA generate code.

#include "GRT_CUDA_host/GRTGenCommandLineData.h"
#include "GRT_Common/GRTHashes.h"
#include "GRT_Common/GRTTableHeaderV1.h"
#include "GRT_Common/GRTCharsetSingle.h"
#include "GRT_CUDA_host/GRTGenerateTableMD5.h"
#include "GRT_CUDA_host/GRTGenerateTableNTLM.h"
#include "GRT_CUDA_host/GRTGenerateTableSHA1.h"
#include "CH_Common/CHRandom.h"
#include <stdlib.h>
#include <stdio.h>
#include <cuda_runtime_api.h>



// Silence output if true.
char silent = 0;

const char programTitle[] = "Cryptohaze GRTGen 1.00";


int main(int argc, char *argv[]) {
    int deviceCount;

    GRTGenCommandLineData GenerateParams;
    GRTCharsetSingle Charset;
    GRTGenerateTable *GenTable;
    CHRandom RandomGenerator;

    printf("\n%s\n\n", programTitle);


    // Check to see if this is even a CUDA capable system.
    cudaGetDeviceCount(&deviceCount);
    if (deviceCount == 0) {
      printf("This program requires a CUDA-capable video card.\nNo cards found.  Sorry.  Exiting.\n");
      exit(1);
    }

    //GenTable = new GRTGenerateTableMD5();

    // Parse the command line.  If this returns, things went well.
    GenerateParams.setRandomGenerator(&RandomGenerator);
    GenerateParams.ParseCommandLine(argc, argv);

    if (!GenerateParams.getUseWebGenerate()) {
        Charset.getCharsetFromFile(GenerateParams.GetCharsetFileName());
    }

    switch(GenerateParams.getHashType()) {
        case 0:
            GenTable = new GRTGenerateTableNTLM();
            break;
        case 1:
            GenTable = new GRTGenerateTableMD5();
            break;
        case 3:
            GenTable = new GRTGenerateTableSHA1();
            break;
        default:
            printf("This hash type is not supported yet!\n");
            exit(1);
            break;
    }

    GenerateParams.PrintTableData();
    
    GenTable->setRandomGenerator(&RandomGenerator);
    GenTable->setGRTGenCommandLineData(&GenerateParams);
    GenTable->setGRTCharsetSingle(&Charset);
    GenTable->createTables();

    delete GenTable;
}
