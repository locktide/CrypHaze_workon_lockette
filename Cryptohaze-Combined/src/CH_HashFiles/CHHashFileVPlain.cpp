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

#include "CH_HashFiles/CHHashFileVPlain.h"


#include <iostream>
#include <ostream>
#include <iomanip>

#define HEX( x ) std::setw(2) << std::setfill('0') << std::hex << (int)( x )


CHHashFileVPlain::CHHashFileVPlain(int newHashLengthBytes) : CHHashFileV() {
    this->HashLengthBytes = newHashLengthBytes;
}


int CHHashFileVPlain::OutputFoundHashesToFile() {
    return 0;
}


int CHHashFileVPlain::OpenHashFile(std::string filename) {
    std::ifstream hashFile;
    std::string fileLine;
    HashPlain HashVectorEntry;
    
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
        found=fileLine.find_last_not_of(whitespaces);
        if (found!=std::string::npos)
            fileLine.erase(found+1);
        else
            fileLine.clear();  
        //printf("Hash length: %d\n", (int)fileLine.length());
        // If the line is not empty and is not the right length, throw error.
        if ((fileLine.length() > 0) && (fileLine.length() != (this->HashLengthBytes * 2)))
        {
            std::cout << "Hash in line "<< this->Hashes.size() <<" incorrect length!\n";
            exit(1);
        }
        
        // If it's a valid line, do the work.
        if (fileLine.length() > 0) {
            // Convert the hash to binary.
            HashVectorEntry.hash = this->convertAsciiToBinary(fileLine);
            if (HashVectorEntry.hash.size() == 0) {
                std::cout << "Hash in line "<< this->Hashes.size() <<" invalid hash!\n";
                exit(1);
            }
            this->Hashes.push_back(HashVectorEntry);
        }
    }
    
    this->SortHashes();
    
    // Set total hashes and hashes remaining to size of hash vector.
    this->TotalHashes = this->Hashes.size();
    this->TotalHashesRemaining = this->TotalHashes;
    
    hashFile.close();
    return 1;
}

std::vector<std::vector<uint8_t> > CHHashFileVPlain::ExportUncrackedHashList() {
    std::vector<std::vector<uint8_t> > returnVector;
    std::vector<HashPlain>::iterator currentHash;
    
    this->HashFileMutex.lock();
    
    // Loop through all current hashes.
    for (currentHash = this->Hashes.begin(); currentHash < this->Hashes.end(); currentHash++) {
        // If it's already found, continue.
        if (currentHash->passwordFound) {
            continue;
        }
        // If not, add it to the current return vector.
        returnVector.push_back(currentHash->hash);
    }
    
    this->HashFileMutex.unlock();
    return returnVector;
}

int CHHashFileVPlain::ReportFoundPassword(std::vector<uint8_t> foundHash, std::vector<uint8_t> foundPassword) {
    std::vector<HashPlain>::iterator currentHash;
    char hashesAdded = 0;

    this->HashFileMutex.lock();
    // Loop through all hashes.
    for (currentHash = this->Hashes.begin(); currentHash < this->Hashes.end(); currentHash++) {
        // Skip if already found.
        if (currentHash->passwordFound) {
            continue;
        }
        // If lengths do not match, wtf?
        if (currentHash->hash.size() != foundHash.size()) {
            continue;
        }
        // Compare hashes.  If there's a match, add the password.
        if (memcmp(&currentHash->hash[0], &foundHash[0], currentHash->hash.size()) == 0) {
            if (!currentHash->passwordFound) {
                currentHash->password = foundPassword;
                currentHash->passwordFound = 1;
                hashesAdded++;
                this->TotalHashesFound++;
            }
        }
    }
    this->HashFileMutex.unlock();
    return hashesAdded;
}

void CHHashFileVPlain::PrintAllFoundHashes() {
    std::vector<HashPlain>::iterator currentHash;
    int position;
    
    this->HashFileMutex.lock();
    
    // Loop through all hashes.
    for (currentHash = this->Hashes.begin(); currentHash < this->Hashes.end(); currentHash++) {
        // Skip if already found.
        if (currentHash->passwordFound) {
            //This could use a friend function that would allow us to use 
            //std::cout less clumsily
            for (position = 0; position < currentHash->hash.size(); position++) {
                std::cout<<HEX(currentHash->hash[position]);
            }
            std::cout<<":";
            for (position = 0; position < currentHash->password.size(); position++) {
                    std::cout<<(char)currentHash->password[position];
            }
            if (this->AddHexOutput) {
                std::cout<<":0x"<<std::endl;
                for (position = 0; position < currentHash->password.size(); position++) {
                        std::cout<<HEX(currentHash->password[position]);
                
                }
            }
            std::cout<<std::endl;
        }
    }
    
    this->HashFileMutex.unlock();
}


void CHHashFileVPlain::PrintNewFoundHashes() {
    std::vector<HashPlain>::iterator currentHash;
    int position;
    
    this->HashFileMutex.lock();
    
    // Loop through all hashes.
    for (currentHash = this->Hashes.begin(); currentHash < this->Hashes.end(); currentHash++) {
        // Skip if already found.
        if (currentHash->passwordFound && !currentHash->passwordPrinted) {
            for (position = 0; position < currentHash->hash.size(); position++) {
                std::cout<<currentHash->hash[position];
            }
            printf(":");
            for (position = 0; position < currentHash->password.size(); position++) {
                    std::cout<<(char)currentHash->password[position];
            }
            if (this->AddHexOutput) {
                std::cout<<":0x";
                for (position = 0; position < currentHash->password.size(); position++) {
                        std::cout<<currentHash->password[position];
                }
            }
            std::cout<<std::endl;
            currentHash->passwordPrinted = 1;
        }
    }
    
    this->HashFileMutex.unlock();
}


int CHHashFileVPlain::OutputUnfoundHashesToFile(std::string filename) {
 
    int j;
    
    std::ofstream hashFile;
    std::vector<HashPlain>::iterator it;
    
    hashFile.open(filename.c_str(), std::ios_base::out);
    //Hope you didn't need the previous contents of this file for anything.
    
    this->HashFileMutex.lock();
    
    if (hashFile.good()) {
        for (it = this->Hashes.begin(); it < this->Hashes.end(); it++) {
            
            if (it->passwordFound && (!(it->passwordOutputToFile)))
            {
                for (j=0; j < this->HashLengthBytes; j++)
                {
                    hashFile<<it->hash[j];
                   
                }
                
                hashFile<<":";
                
                for (j=0; j < it->password.size(); j++)
                {
                    hashFile<<it->password[j];
                }
                
                hashFile<<std::endl;
                it->passwordPrinted = 1;
                it->passwordOutputToFile = 1;
            } 
        }            
    }
    this->HashFileMutex.unlock();
    if (hashFile.good())
        return 1;
    else
        return 0;
}

void CHHashFileVPlain::ImportHashListFromRemoteSystem(::google::protobuf::Message& remoteData) {
    // I hope your CHHashFileVPlain was empty.
    // For cleanliness, I will clean this now.
    this->Hashes.clear();
    this->HashLengthBytes = 0;
    
    //Cast Message object to MFNHashFileVPlainProtobuf and set up objects needed to retrieve
    //protobuf 
    
    ::MFNHashFilePlainProtobuf& protobuf = dynamic_cast< ::MFNHashFilePlainProtobuf& >(remoteData);
    
    //Need to finish this.
    

}

void CHHashFileVPlain::ExportHashListToRemoteSystem(::google::protobuf::Message& exportData) {

    std::vector<HashPlain>::iterator i,j;
    //Later: try, except around this.
    ::MFNHashFilePlainProtobuf & protobuf = dynamic_cast< ::MFNHashFilePlainProtobuf & >(exportData);
    
    protobuf.set_hash_length_bytes(this->HashLengthBytes);
    this->HashFileMutex.lock();
    for (i = this->Hashes.begin(); i < this->Hashes.end(); i++)
    {
        std::string hashString = std::string(i->hash.begin(), i->hash.end());
        protobuf.add_hash_value(hashString); 
    }
    this->HashFileMutex.unlock(); 
}



bool CHHashFileVPlain::PlainHashSortPredicate(const HashPlain &d1, const HashPlain &d2) {
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


bool CHHashFileVPlain::PlainHashUniquePredicate(const HashPlain &d1, const HashPlain &d2) {
    if (memcmp(&d1.hash[0], &d2.hash[0], d1.hash.size()) == 0) {
        return 1;
    }
    return 0;
}

void CHHashFileVPlain::SortHashes() {
    // Sort hashes and remove duplicates.
    std::sort(this->Hashes.begin(), this->Hashes.end(), CHHashFileVPlain::PlainHashSortPredicate);
    this->Hashes.erase(
        std::unique(this->Hashes.begin(), this->Hashes.end(), CHHashFileVPlain::PlainHashUniquePredicate ),
        this->Hashes.end() );
}

//#define UNIT_TEST 1

#if UNIT_TEST

int main() {
    
    std::cout<<"foo"<<std::endl;
    
    CHHashFileVPlain HashFile(16);
    
    HashFile.OpenHashFile("foobar");
    std::cout<<(int)HashFile.GetTotalHashCount();
}

#endif
