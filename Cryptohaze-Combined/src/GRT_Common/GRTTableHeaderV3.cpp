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

#include "GRT_Common/GRTTableHeaderV3.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include "GRT_Common/GRTCharsetSingle.h"
#include <math.h>

#define UNIT_TEST 0

GRTTableHeaderV3::GRTTableHeaderV3() {
    // Clear the table header and set the magic
    memset(&this->Table_Header, 0, sizeof(this->Table_Header));
    this->Table_Header.Magic0 = this->MAGIC_0;
    this->Table_Header.Magic1 = this->MAGIC_1;
    this->Table_Header.Magic2 = this->MAGIC_2;
    this->Table_Header.TableVersion = this->TABLE_VERSION;
}

char GRTTableHeaderV3::isValidTable(const char *filename, int hashVersion) {

    if (!this->readTableHeader(filename)) {
        printf("Unable to read the table header.\n");
        return 0;
    }

    // Check the magic.
    if ((this->Table_Header.Magic0 != this->MAGIC_0) ||
        (this->Table_Header.Magic1 != this->MAGIC_1) ||
        (this->Table_Header.Magic2 != this->MAGIC_2)) {
        printf("Table magic is bad.\n");
        return 0;
    }

    if (this->Table_Header.TableVersion != this->TABLE_VERSION) {
        printf("Table version is incorrect.\n");
        return 0;
    }

    // If the hash version is set, check for it.
    if (hashVersion >= 0) {
        if (hashVersion != this->Table_Header.HashVersion) {
            printf("Table hash ID mismatch.\n");
            return 0;
        }
    }

    // Passes basic sanity checks, free and return.
    return 1;
}

char GRTTableHeaderV3::readTableHeader(const char *filename){
    FILE *Table;

    // Open as a large file
    Table = fopen(filename, "rb");

    // If the table file can't be opened, return false.
    if (Table == NULL) {
        printf("Cannot open table %s: fopen failed.\n", filename);
        printf( "Error opening file: %s\n", strerror( errno ) );
        return 0;
    }

    memset(&this->Table_Header, 0, sizeof(this->Table_Header));

    // If the read fails, clean up and return false.
    if (fread(&this->Table_Header, sizeof(this->Table_Header), 1, Table) != 1) {
        fclose(Table);
        return 0;
    }

    fclose(Table);
    return 1;
};

char GRTTableHeaderV3::writeTableHeader(FILE *file){
    // Perform sanity checks to ensure everything important has been written
    if (!this->Table_Header.TableVersion || !this->Table_Header.PasswordLength ||
        !this->Table_Header.NumberChains || !this->Table_Header.ChainLength) {
            printf("ERROR: Not all table header data set!\n");
            exit(1);
    }

    // Seek to the beginning of the file.
    fseek (file, 0 , SEEK_SET );

    if (fwrite(&this->Table_Header, sizeof(this->Table_Header), 1, file) != sizeof(this->Table_Header)) {
        return 0;
    } else {
        return 1;
    }
};

void GRTTableHeaderV3::printTableHeader(){
    // Print out the table metainfo.
    printf("\n");
    printf("Table version:   %d\n", this->Table_Header.TableVersion);
    printf("Hash:            %s\n", this->Table_Header.HashName);
    printf("Password length: %d\n", this->Table_Header.PasswordLength);
    printf("Table index:     %d\n", this->Table_Header.TableIndex);
    printf("Chain length:    %d\n", this->Table_Header.ChainLength);
    printf("Num chains:      %ld\n", this->Table_Header.NumberChains);
    printf("Perfect table:   ");
    if (this->Table_Header.IsPerfect) {
        printf("Yes\n");
    } else {
        printf("No\n");
    }
    printf("Charset length:  %d\n", this->Table_Header.CharsetLength[0]);
    printf("Charset:         ");
    for (int i = 0; i < this->Table_Header.CharsetLength[0]; i++) {
        printf("%c", this->Table_Header.Charset[0][i]);
        // Add a newline at sane points.
        if ((i % 50 == 0) && (i)) {
            printf("\n                 ");
        }
    }
    printf("\nBits of hash:    %d\n", this->Table_Header.BitsInHash);
    printf("Bits of pass:    %d\n", this->Table_Header.BitsInPassword);
    printf("Generate seed: %lu\n", this->Table_Header.randomSeedValue);
    printf("Chain start offset: %lu\n", this->Table_Header.chainStartOffset);
    printf("\n\n");
};

char GRTTableHeaderV3::isCompatibleWithTable(GRTTableHeader* Table2){
    // Basically, match a bunch of important stuff together, and if it doesn't match,
    // return false.
    int i, j;
/*
    // Must be the same table version
    if (this->Table_Header.TableVersion != Table2->getTableVersion()) {
        return 0;
    }
*/
    // Must be the same hash.
    if (this->Table_Header.HashVersion != Table2->getHashVersion()) {
        return 0;
    }

    // Must be the same table index.
    if (this->Table_Header.TableIndex != Table2->getTableIndex()) {
        return 0;
    }

    // Must have the same chain length
    if (this->Table_Header.ChainLength != Table2->getChainLength()) {
        return 0;
    }

    // Password length must be the same
    if (this->Table_Header.PasswordLength != Table2->getPasswordLength()) {
        return 0;
    }

    // We need the same charset setup.
    if (this->Table_Header.CharsetCount != Table2->getCharsetCount()) {
        return 0;
    }


    // Verify that the number of characters in each charset is the same
    char *Table2CharsetLength = Table2->getCharsetLengths();

    for (i = 0; i < this->Table_Header.CharsetCount; i++) {
        if (this->Table_Header.CharsetLength[i] != Table2CharsetLength[i]) {
            delete[] Table2CharsetLength;
            return 0;
        }
    }

    char **Table2Charset = Table2->getCharset();

    // If we are here, the charset metadata is OK - check the charset
    for (i = 0; i < this->Table_Header.CharsetCount; i++) {
        for (j = 0; j < this->Table_Header.CharsetLength[i]; j++) {
            if (this->Table_Header.Charset[i][j] != Table2Charset[i][j]) {
                for (i = 0; i < 16; i++)
                    delete[] Table2Charset[i];
                delete[] Table2Charset;
                return 0;
            }
        }
    }

    // Clean up the charset
    delete[] Table2CharsetLength;

    for (i = 0; i < 16; i++)
        delete[] Table2Charset[i];
    delete[] Table2Charset;

/*
    if (this->Table_Header.BitsInHash != Table2->getBitsInHash()) {
        return 0;
    }
*/
    // If we haven't failed out so far, the tables are compatible for merging!
    return 1;

};


char GRTTableHeaderV3::getTableVersion(){return this->Table_Header.TableVersion;};
void GRTTableHeaderV3::setTableVersion(char NewTableVersion){this->Table_Header.TableVersion = NewTableVersion; };

char GRTTableHeaderV3::getHashVersion(){return this->Table_Header.HashVersion;};
void GRTTableHeaderV3::setHashVersion(char NewHashVersion){this->Table_Header.HashVersion = NewHashVersion; };

char* GRTTableHeaderV3::getHashName(){
    char *HashNameReturn;

    HashNameReturn = new char[16];
    strcpy(HashNameReturn, (const char *)&this->Table_Header.HashName);
    return HashNameReturn;
};
void GRTTableHeaderV3::setHashName(char* NewHashName){
    strcpy(this->Table_Header.HashName, NewHashName);
};

uint32_t GRTTableHeaderV3::getTableIndex(){return this->Table_Header.TableIndex; };
void GRTTableHeaderV3::setTableIndex(uint32_t NewTableIndex){this->Table_Header.TableIndex = NewTableIndex; };

uint32_t GRTTableHeaderV3::getChainLength(){return this->Table_Header.ChainLength; };
void GRTTableHeaderV3::setChainLength(uint32_t NewChainLength){this->Table_Header.ChainLength = NewChainLength; };

uint64_t GRTTableHeaderV3::getNumberChains(){return this->Table_Header.NumberChains; };
void GRTTableHeaderV3::setNumberChains(uint64_t NewNumberChains){this->Table_Header.NumberChains = NewNumberChains; };

char GRTTableHeaderV3::getIsPerfect(){return this->Table_Header.IsPerfect; };
void GRTTableHeaderV3::setIsPerfect(char NewIsPerfect){this->Table_Header.IsPerfect = NewIsPerfect; };

char GRTTableHeaderV3::getPasswordLength(){return this->Table_Header.PasswordLength; };
void GRTTableHeaderV3::setPasswordLength(char NewPasswordLength){
    this->Table_Header.PasswordLength = NewPasswordLength;
};

char GRTTableHeaderV3::getCharsetCount(){return this->Table_Header.CharsetCount; };
void GRTTableHeaderV3::setCharsetCount(char NewCharsetCount){this->Table_Header.CharsetCount = NewCharsetCount; };

char* GRTTableHeaderV3::getCharsetLengths(){
    char *ReturnCharsetLengths;
    int i;

    ReturnCharsetLengths = new char[16];

    for (i = 0; i < 16; i++) {
        ReturnCharsetLengths[i] = this->Table_Header.CharsetLength[i];
    }
    return ReturnCharsetLengths;
};
void GRTTableHeaderV3::setCharsetLengths(char* NewCharsetLengths){
    int i;

    for (i = 0; i < 16; i++) {
        this->Table_Header.CharsetLength[i] = NewCharsetLengths[i];
    }
    // Regenerate the value after the charset lengths change
};

char** GRTTableHeaderV3::getCharset(){
    int i, j;

    char **ReturnCharsetArray = new char*[16];
    for (i = 0; i < 16; i++)
        ReturnCharsetArray[i] = new char[256];

    for (i = 0; i < 16; i++) {
        for (j = 0; j < 256; j++) {
            ReturnCharsetArray[i][j] = this->Table_Header.Charset[i][j];
        }
    }

    return ReturnCharsetArray;
};

void GRTTableHeaderV3::setCharset(char** NewCharsetArray){
    int i, j;

    for (i = 0; i < this->Table_Header.CharsetCount; i++) {
        for (j = 0; j < this->Table_Header.CharsetLength[i]; j++) {
            this->Table_Header.Charset[i][j] = NewCharsetArray[i][j];
        }
    }
};

char* GRTTableHeaderV3::getComments(){return NULL;};
void GRTTableHeaderV3::setComments(char*){ };

int GRTTableHeaderV3::getBitsInPassword() {
    return this->Table_Header.BitsInPassword;
}
int GRTTableHeaderV3::getBitsInHash() {
    return this->Table_Header.BitsInHash;
}

void GRTTableHeaderV3::setBitsInHash(int newHashBits) {
    this->Table_Header.BitsInHash = newHashBits;
}
void GRTTableHeaderV3::setBitsInPassword(int newPasswordBits) {
    this->Table_Header.BitsInPassword = newPasswordBits;
}

void GRTTableHeaderV3::setRandomSeedValue(uint32_t newRandomSeedValue) {
    this->Table_Header.randomSeedValue = newRandomSeedValue;
}

uint32_t GRTTableHeaderV3::getRandomSeedValue() {
    return this->Table_Header.randomSeedValue;
}

void GRTTableHeaderV3::setChainStartOffset(uint64_t newChainStartOffset) {
    this->Table_Header.chainStartOffset = newChainStartOffset;
}

uint64_t GRTTableHeaderV3::getChainStartOffset() {
    return this->Table_Header.chainStartOffset;
}

int GRTTableHeaderV3::setHeaderString(std::vector<uint8_t> headerVector) {
    if (headerVector.size() != 8192) {
        printf("ERROR!  Header size incorrect!  Need 8192 bytes, got %d!\n", headerVector.size());
        return 0;
    }
    memcpy(&this->Table_Header, &headerVector[0], 8192);

    // Check the magic.
    if ((this->Table_Header.Magic0 != this->MAGIC_0) ||
        (this->Table_Header.Magic1 != this->MAGIC_1) ||
        (this->Table_Header.Magic2 != this->MAGIC_2)) {
        printf("Table magic is bad.\n");
        return 0;
    }

    if (this->Table_Header.TableVersion != this->TABLE_VERSION) {
        printf("Table version is incorrect.\n");
        return 0;
    }
    return 1;
}

#if UNIT_TEST

#include <string.h>
int main() {
    GRTTableHeaderV3 TableHeader;
    char charsetLengths[16];

    memset(charsetLengths, 0, 16);

    charsetLengths[0] = 95;

    TableHeader.setCharsetLengths(charsetLengths);

    TableHeader.setHashVersion(0);
    TableHeader.setPasswordLength(9);


    printf("Bits in pw: %d\n", TableHeader.getBitsInPassword());

}
#endif



