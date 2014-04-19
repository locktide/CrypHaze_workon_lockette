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

#include "CH_HashFiles/CHHashFileVSalted.h"

// For supa-verbose printouts.
#define CHHASHFILEVSALTED_DEBUG 0

CHHashFileVSalted::CHHashFileVSalted(int newHashLengthBytes, 
        int newMaxSaltLengthBytes, char newSaltIsFirst, char newSaltIsLiteral, 
        char newSeperatorSymbol = ':') : CHHashFileV() {
    
    // Ensure the structures are clear.
    this->Hashes.clear();
    this->UniqueSalts.clear();

    this->TotalHashes = 0;
    this->TotalHashesFound = 0;
    this->TotalHashesRemaining = 0;
    
    // Copy parameters into the internal state
    this->HashLengthBytes = newHashLengthBytes;
    this->MaxSaltLengthBytes = newMaxSaltLengthBytes;
    this->SaltIsFirst = newSaltIsFirst;
    this->SaltIsLiteral = newSaltIsLiteral;
    this->SeperatorSymbol = newSeperatorSymbol;
    
}


int CHHashFileVSalted::OpenHashFile(std::string filename) {
    std::ifstream hashFile;
    std::string fileLine;
    std::string hashValue;
    std::string saltValue;
    HashSalted HashVectorEntry;
    size_t separatorPos;
    uint64_t fileLineCount = 0;
    
    std::string whitespaces (" \t\f\v\n\r");
    size_t found;
    
    HashVectorEntry.passwordFound = 0;
    HashVectorEntry.passwordOutputToFile = 0;
    HashVectorEntry.passwordPrinted = 0;
    
    hashFile.open(filename.c_str(), std::ios_base::in);
    if (!hashFile.good())
    {
        
        std::cout << "ERROR: Cannot open hashfile " << filename <<"\n";
        exit(1);
    }
    
    while (std::getline(hashFile, fileLine)) {
        HashVectorEntry.hash.clear();
        HashVectorEntry.salt.clear();
        
        found=fileLine.find_last_not_of(whitespaces);
        if (found!=std::string::npos)
            fileLine.erase(found+1);
        else
            fileLine.clear();  
#if CHHASHFILEVSALTED_DEBUG
        printf("Hash length: %d\n", (int)fileLine.length());
#endif
        
        // If the line length is 0, continue - blank line that we can ignore.
        if (fileLine.length() == 0) {
            continue;
        }

        // Determine the location of the separator symbol in the line.
        separatorPos = fileLine.find_first_of(this->SeperatorSymbol, 0);
        if (separatorPos == std::string::npos) {
            // Separator not found - abort!
            printf("Separator character '%c' not found on line %lu!\n", this->SeperatorSymbol, fileLineCount);
            exit(1);
        } else {
#if CHHASHFILEVSALTED_DEBUG
            printf("Found split at %d\n", (int)separatorPos);
#endif
        }

        if (this->SaltIsFirst) {
            // Salt is the first part of the line.
            
            // Check hash length - don't forget the length of the separator.
            if ((fileLine.length() - (separatorPos + 1)) != (this->HashLengthBytes * 2)) {
                printf("Error: Hash on line %lu is not correct length!\n", fileLineCount);
                exit(1);
            }
            
            // Copy the salt into the salt string.
            saltValue = fileLine.substr(0, separatorPos);
            // Copy the hash into the hash string - from the separator to the end of the line.
            hashValue = fileLine.substr(separatorPos + 1, std::string::npos);
#if CHHASHFILEVSALTED_DEBUG
            printf("Salt:Hash format\n");
            printf("Salt: %s\n", saltValue.c_str());
            printf("Hash: %s\n", hashValue.c_str());
#endif
        } else {
            // Hash is the first part of the line.
            
            // Check the hash length to ensure it is correct.
            if (separatorPos != (this->HashLengthBytes * 2)) {
                printf("Error: Hash on line %lu is not correct length!\n", fileLineCount);
                exit(1);
            }
            // Copy the hash into the hash string.
            hashValue = fileLine.substr(0, separatorPos);
            // Copy the salt into the salt string - from the separator to the end of the line.
            saltValue = fileLine.substr(separatorPos + 1, std::string::npos);
#if CHHASHFILEVSALTED_DEBUG
            printf("Hash:Salt format\n");
            printf("Hash: %s\n", hashValue.c_str());
            printf("Salt: %s\n", saltValue.c_str());
#endif
        }
        
        // Deal with the hash: It should be ASCII-hex, so convert it.
        HashVectorEntry.hash = this->convertAsciiToBinary(hashValue);
        
        // Deal with the salt properly.
        if (this->SaltIsLiteral) {
            // Salt is literal - copy it into the salt vector with a std::copy operation.
            HashVectorEntry.salt.reserve(saltValue.length());
            std::copy(saltValue.begin(), saltValue.end(), std::back_inserter(HashVectorEntry.salt));
        } else {
            // Salt is ascii-hex - convert it from a string to a vector.
            HashVectorEntry.salt = this->convertAsciiToBinary(saltValue);
        }
#if CHHASHFILEVSALTED_DEBUG
        printf("Loaded hash value: 0x");
        for (int i = 0; i < HashVectorEntry.hash.size(); i++) {
            printf("%02x", HashVectorEntry.hash[i]);
        }
        printf("\n");
        printf("Loaded salt value: 0x");
        for (int i = 0; i < HashVectorEntry.salt.size(); i++) {
            printf("%02x", HashVectorEntry.salt[i]);
        }
        printf("\n");
#endif
        this->Hashes.push_back(HashVectorEntry);

        fileLineCount++;
    }
    
    this->SortHashes();
    
    // Set total hashes and hashes remaining to size of hash vector.
    this->TotalHashes = this->Hashes.size();
    this->TotalHashesRemaining = this->TotalHashes;
    
    hashFile.close();
    
    this->ExtractUncrackedSalts();
    
    return 1;
}


int CHHashFileVSalted::OutputFoundHashesToFile() {
    
}
void CHHashFileVSalted::SortHashes() {
    // Sort hashes and remove duplicates.
    std::sort(this->Hashes.begin(), this->Hashes.end(), CHHashFileVSalted::SaltedHashSortPredicate);
    this->Hashes.erase(
        std::unique(this->Hashes.begin(), this->Hashes.end(), CHHashFileVSalted::SaltedHashUniquePredicate),
        this->Hashes.end());
    
}

void CHHashFileVSalted::ExtractUncrackedSalts() {
    // Grab a mutex.  This will likely happen during execution.
    this->HashFileMutex.lock();
    
    // Clear out the old salts.
    this->UniqueSalts.clear();
    
    // Loop through the hashes, copying unfound salts into the new structure.
    std::vector<HashSalted>::iterator HashesIt;
    
    for (HashesIt = this->Hashes.begin(); HashesIt < this->Hashes.end(); 
            HashesIt++) {
        
        if (!HashesIt->passwordFound) {
            this->UniqueSalts.push_back(HashesIt->salt);
        }
    }
    
    // Sort the hashes.
    this->SortHashes();
    
    // Sort and unique the salts.
    std::sort(this->UniqueSalts.begin(), this->UniqueSalts.end());
    this->UniqueSalts.erase(
        std::unique(this->UniqueSalts.begin(), this->UniqueSalts.end()),
        this->UniqueSalts.end());
    
    this->HashFileMutex.unlock();
}

std::vector<std::vector<uint8_t> > CHHashFileVSalted::ExportUncrackedSaltList() {
    // Update the list of uncracked salts.  This function handles locking on its own.
    this->ExtractUncrackedSalts();
    
    // Return a copy of the internal buffer.
    return this->UniqueSalts;
}

bool CHHashFileVSalted::SaltedHashSortPredicate(const HashSalted &d1, const HashSalted &d2) {
    int i;
    for (i = 0; i < d1.hash.size(); i++) {
        if (d1.hash[i] == d2.hash[i]) {
            continue;
        } else if (d1.hash[i] > d2.hash[i]) {
            return 0;
        } else if (d1.hash[i] < d2.hash[i]) {
            return 1;
        }
    }
    // Exactly equal = return 0.
    return 0;
}

bool CHHashFileVSalted::SaltedHashUniquePredicate(const HashSalted &d1, const HashSalted &d2) {
    if (memcmp(&d1.hash[0], &d2.hash[0], d1.hash.size()) == 0) {
        return 1;
    }
    return 0;
}

std::vector<std::vector<uint8_t> > CHHashFileVSalted::ExportUncrackedHashList() {
    std::vector<std::vector<uint8_t> > ReturnHashes;
    
    this->HashFileMutex.lock();
    
    // Loop through the hashes, copying unfound hashes into the new structure.
    std::vector<HashSalted>::iterator HashesIt;
    
    for (HashesIt = this->Hashes.begin(); HashesIt < this->Hashes.end(); 
            HashesIt++) {
        
        if (!HashesIt->passwordFound) {
            ReturnHashes.push_back(HashesIt->hash);
        }
    }

    this->HashFileMutex.unlock();
    return ReturnHashes;
}
int CHHashFileVSalted::ReportFoundPassword(std::vector<uint8_t> hash, std::vector<uint8_t> password) {
    
}
void CHHashFileVSalted::PrintAllFoundHashes() {
    
}
void CHHashFileVSalted::PrintNewFoundHashes() {
    
}
int CHHashFileVSalted::OutputUnfoundHashesToFile(std::string filename) {
    
}
void CHHashFileVSalted::ImportHashListFromRemoteSystem(::google::protobuf::Message & remoteData)  {
    
}
void CHHashFileVSalted::ExportHashListToRemoteSystem(::google::protobuf:: Message &exportData) {
    
}


#define UNIT_TEST 0

#if UNIT_TEST

#include <stdlib.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
    
    std::cout<<"foo"<<std::endl;
    
    //CHHashFileVSalted HashFile(16, 0, CHHASHFILESALTED_SALT_IS_FIRST, CHHASHFILESALTED_HEX_SALT);
    CHHashFileVSalted HashFile(16, 0, CHHASHFILESALTED_HASH_IS_FIRST, CHHASHFILESALTED_LITERAL_SALT);
    
    if (argc != 2) {
        printf("Call it with the file name!\n");
        exit(1);
    }
    
    
    HashFile.OpenHashFile(argv[1]);
    
    std::cout<<(int)HashFile.GetTotalHashCount();
}

#endif
