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

#include "GRT_OpenCL_host/GRTCLGenCommandLineData.h"
#include "OpenCL_Common/GRTOpenCL.h"
#include "GRT_Common/GRTHashes.h"
//#include "GRT_Common/GRTTableHeaderV1.h"
#include "GRT_Common/GRTCharsetSingle.h"
#include "GRT_OpenCL_host/GRTCLGenerateTableMD5.h"
#include "GRT_OpenCL_host/GRTCLGenerateTableNTLM.h"
#include "GRT_OpenCL_host/GRTCLGenerateTableSHA1.h"
#include "CH_Common/CHRandom.h"
#include <stdlib.h>
#include <stdio.h>


// Silence output if true.
char silent = 0;


int main(int argc, char *argv[]) {
    GRTCLGenCommandLineData GenerateParams;
    CryptohazeOpenCL *OpenCL;

    OpenCL = new CryptohazeOpenCL();

    GRTCharsetSingle Charset;
    GRTCLGenerateTable *GenTable;
    CHRandom RandomGenerator;

    // Parse the command line.  If this returns, things went well.
    GenerateParams.setRandomGenerator(&RandomGenerator);
    GenerateParams.ParseCommandLine(argc, argv);


    //OpenCL->printAvailablePlatforms();
    //printf("Using platform %d\n", GenerateParams.getOpenCLPlatform());
    OpenCL->selectPlatformById(GenerateParams.getOpenCLPlatform());

    

    //OpenCL->printAvailableDevices();
    //printf("Using device %d\n", GenerateParams.getOpenCLDevice());
    OpenCL->selectDeviceById(GenerateParams.getOpenCLDevice());

    OpenCL->createContext();



    Charset.getCharsetFromFile(GenerateParams.GetCharsetFileName());

    switch(GenerateParams.getHashType()) {
        case 0:
            GenTable = new GRTCLGenerateTableNTLM();
            break;
        case 1:
            GenTable = new GRTCLGenerateTableMD5();
            break;
        case 3:
            GenTable = new GRTCLGenerateTableSHA1();
            break;
        default:
            printf("This hash type is not supported yet!\n");
            exit(1);
            break;
    }

    GenerateParams.PrintTableData();

    GenTable->setRandomGenerator(&RandomGenerator);
    GenTable->setGRTCLGenCommandLineData(&GenerateParams);
    GenTable->setGRTCLCharsetSingle(&Charset);
    GenTable->setOpenCL(OpenCL);
    GenTable->createTables();

    delete GenTable;
}
