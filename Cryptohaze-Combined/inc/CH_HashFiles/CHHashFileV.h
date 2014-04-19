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

/**
 * @section DESCRIPTION
 * CHHashFileV is a base class for the vector hash file types.
 *
 * These are a replacement set of classes for the old CHHashType classes
 * that use vectors for passing data around instead of arrays of data.
 *
 * This should improve reliability and stability by reducing memory leaks.
 *
 * Also, this hash file type handles passing arbitrary data to the hash
 * functions - this will support cracking odd things such as file types,
 * WPA/WPA2 hashes, IKE hashes, etc.
 * 
 * Also, this no longer uses the network class.  Submitting hashes to the
 * network is handled by the upstream code if needed... I think.  This may
 * get revisited later if needed.
 */

#ifndef _CHHASHFILEV_H
#define _CHHASHFILEV_H

//#include "Multiforcer_Common/CHCommon.h"

// We need to include the mutex defines.
#include <boost/thread.hpp>
#include <boost/thread/mutex.hpp>
#include "CH_HashFiles/CHHashFileVPlain.pb.h"
#include "CH_HashFiles/CHHashFileVSalted.pb.h"
#include <vector>
#include <string>
#include <stdlib.h>
#include <stdio.h>


class CHHashFileV {
protected:
    /**
     * Mutex for hash file operations
     * 
     * This is a mutex used to protect all standard template operations.
     * As the STL is not threadsafe, this is used to enforce only one thread
     * at a time modifying things.  This should be locked before doing anything
     * with the STL types, and unlocked on exit.  In general, lock this at the
     * beginning of a function and unlock on all exit paths.
     */
    boost::mutex HashFileMutex;
    
    /**
     * Set if hex output is to be added to the output file.
     * 
     * If this is not set, the output file will have a standard "hash:password" 
     * output format (as relevant for the hash file).  If this is set, the 
     * output will be "hash:password:0x[password in hex]" - this is useful
     * for people who put spaces or other weird characters at the end of the 
     * password, as well as for non-ASCII hash output such as SL3.
     */
    char AddHexOutput;
    
    /**
     * Path to the output filename for found hashes.
     * 
     * This contains the relative path for the file containing found hashes.
     * If it is null, the output file is not being used.
     */
    std::string OutputFilePath;
    
    /**
     * File for the hash output file.
     * 
     * This is the opened file for hash output.  If the file is not being used,
     * this is set to NULL.
     */
    FILE *OutputFile;

    /**
     * Total number of hashes currently loaded.
     */
    uint64_t TotalHashes;
    
    /**
     * Total number of hashes that have been found in the current set.
     */
    uint64_t TotalHashesFound;
    
    /**
     * Total number of hashes remaining to be found.
     */
    uint64_t TotalHashesRemaining;

    
    /**
     * Appends the found hashes to the specified output file.
     * 
     * This function adds new found hashes to the open output file.  It appends
     * to the end of the file, and syncs the file if possible on the OS.  If the
     * output file is not being used, this function returns 0.
     * 
     * @return True if the hashes were successfully written, else false.
     */
    virtual int OutputFoundHashesToFile() = 0;

    /**
     * Converts a string of ascii-hex into a vector of uint8_t values matching.
     *
     * Takes a std::string type and converts it into the ascii representation.
     * Will return this vector, or a null vector if there is an error.
     * If any non-[0-9,a-f] characters are present or the number of characters
     * is odd, it will error out.
     *
     * @param asciiHex The ascii string to convert
     * @return A vector consisting of the binary value of the string.
     */
    virtual std::vector<uint8_t> convertAsciiToBinary(std::string asciiHex);
    /**
     * Overloaded convertAsciiToBinary with a vector of char input vs string.
     * @param asciiHex Vector of chars to convert.
     * @return A vector consisting of the binary value of the string.
     */
    virtual std::vector<uint8_t> convertAsciiToBinary(std::vector<char> asciiHex);

    
    
public:

    /**
     * Default constructor for CHHashFileV.
     * 
     * Clears variables as needed.  All non-stl variables should be cleared.
     */
    CHHashFileV() {
        this->AddHexOutput = 0;
        this->TotalHashes = 0;
        this->TotalHashesFound = 0;
        this->TotalHashesRemaining = 0;
        this->OutputFile = NULL;
    }

    /**
     * Attempts to open a hash file with the given filename.
     * 
     * This function will attempt to open and parse the given filename.  After
     * completion, the HashFile class will be fully set up and ready to go.
     * Returns true on success, false on failure.  If an error occurs, this 
     * function will printf details of it before returning, and therefore should
     * be called before any curses GUIs are brought online.
     * 
     * @param filename The hashfile path to open.
     * @return True on success, False on failure.
     */
    virtual int OpenHashFile(std::string filename) = 0;

    
    /**
     * Exports the currently uncracked hashes in a vector of vectors.
     * 
     * This function exports a vector of vectors containing the currently
     * uncracked hashes (those without passwords).  The outer vector contains
     * a number of inner vectors equal to the number of uncracked hashes, and 
     * each inner vector contains a single hash.  The return may or may not be
     * in sorted order.  Calling code should sort if required.
     * 
     * @return The vector of vectors of currently uncracked hashes.
     */
    virtual std::vector<std::vector<uint8_t> > ExportUncrackedHashList() = 0;


    /**
     * Reports a found password.
     * 
     * This function is used to report a found password.  The hash and found 
     * password are reported.  If they are successfully imported as a new 
     * password/hash combination, the function returns number of successful
     * additions, else 0.  0 may mean that the hash is not present in the list,
     * or may mean that the password has already been reported.
     * 
     * @param foundHash A vector containing the hash corresponding to the found password.
     * @param foundPassword The found password for the hash.
     * @return Number of times password added to hash list.
     */
    virtual int ReportFoundPassword(std::vector<uint8_t> foundHash, std::vector<uint8_t> foundPassword) = 0;


    /**
     * Prints a list of all found hashes.
     * 
     * This function prints out a list of all found hashes and their passwords,
     * along with the hex of the password if requested.  It uses printf, so
     * call it after any curses display has been torn down.
     */
    virtual void PrintAllFoundHashes() = 0;


    /**
     * Prints out newly found hashes - ones that haven't been printed yet.
     * 
     * This function prints out found hashes that have not been printed yet.
     * It is used for display hashes as we find them in the daemon mode.  This
     * function uses printf, so must not be called during curses display.
     */
    virtual void PrintNewFoundHashes() = 0;

    /**
     * Sets the filename for output of found hashes.
     * 
     * This function sets the filename for output hashes and attempts to open
     * the file.  If it is successful, it returns true, else returns false.
     * Failures are silent - it is up to the calling code to detect that this 
     * function failed and report properly.
     * 
     * @param filename Output filename for hashes to be appended to.
     * @return True if file is opened successfully, else false.
     */
    virtual int SetFoundHashesOutputFilename(std::string filename) {
        this->OutputFilePath = filename;
        // Attempt to open the file and return the path.
        this->OutputFile = fopen(filename.c_str(), "a");
        if (this->OutputFile) {
            return 1;
        } else {
            return 0;
        }
    }

    /**
     * Outputs hashes that were not found to the specified filename.
     * 
     * This function outputs all the hashes that have not been found to the
     * specified filename.  They will be written in the same format that the
     * file was read in - typically just "hash", one per line.  Returns true
     * if the file was written successfully, else false.
     * 
     * @param filename The filename to write the unfound hashes to.
     * @return True if successfully written, else false.
     */
    virtual int OutputUnfoundHashesToFile(std::string filename) = 0;

    /**
     * Returns the total number of hashes loaded by the file.
     * 
     * @return The total number of hashes present in the hashfile.
     */
    virtual uint64_t GetTotalHashCount() {
        return this->TotalHashes;
    }

    /**
     * Returns the number of cracked hashes.
     * 
     * @return The number of cracked hashes in the current instance.
     */
    virtual uint64_t GetCrackedHashCount() {
        return this->TotalHashesFound;
    }
    
    /**
     * Returns the number of uncracked hashes remaining.
     * 
     * @return The number of uncracked hashes in the hash file.
     */
    virtual uint64_t GetUncrackedHashCount() {
        return this->TotalHashesRemaining;
    }

    /**
     * Returns the current hash length in bytes.
     * 
     * @return Hash length in bytes.
     */
    virtual uint32_t GetHashLengthBytes() {
        return 0;
    }
    
    /**
     * Enables hex output in the password output file.
     * 
     * This function allows enabling or disabling hex output in the password
     * file.  If the value passed in is true, an additional column of hex output
     * will be added to the output file.  If false, no hex will be added.
     * 
     * @param newAddHexOutput True to add hex output, false to disable.
     */
    virtual void SetAddHexOutput(char newAddHexOutput) {
        this->AddHexOutput = newAddHexOutput;
    }

    /**
     * Imports a hash list from a remote system by passing a reference to a Google
     *  Protocol Buffer Message object.
     * 
     * This function is related to the network operation, and is used to import
     * a list of hashes/salts/etc from the remote system in a hashfile specific
     * format.  The only requirement is that this properly read the data
     * exported by the corresponding ExportHashListToRemoteSystem function in 
     * each class.  Other details are totally up to the implementation.  This
     * function overwrites any existing data in the class with the new received
     * data.
     */
    virtual void ImportHashListFromRemoteSystem(::google::protobuf::Message & remoteData) = 0;
    
    /**
     * Exports a list of hashes to a remote system by passing a reference to a
     * Google Protocol Buffer Message object.
     * 
     * This function is related to network operation, and is used to export a 
     * list of hashes or other data to the remote system.  This can be in a 
     * hashfile specific format, and the only requirement is that the
     * corresponding ImportHashListFromRemoteSystem can read the output format.
     * This function may export the entire hash list, or it may only export
     * the uncracked hashes.  If it exports the entire hash list, it should
     * also export data as to whether the hash has been cracked or not.
     * 
     * 
     */
    virtual void ExportHashListToRemoteSystem(::google::protobuf:: Message &exportData) = 0;
    
    /**
     * Returns the number of "Other Data" fields.
     * 
     * "Other Data" fields are other blobs of data on a per-hash basis that are
     * related to each target hash.  This is present to support things like
     * WPA key cracking with SSIDs, or IKE cracking with SKEY and HASH_R data.
     * This function returns the number of unique other data IDs that this 
     * hash file class will return.  The data is obtained with the 
     * GetOtherDataByIndex function.
     * 
     * @return The number of "other data" fields present.
     */
    virtual int GetOtherDataCount() {
        return 0;
    }
    
    /**
     * Returns the specified "Other Data" by dataId
     * 
     * This returns a vector of other data as needed by the hash file.  This
     * data is returned as a vector of vectors, and is identified by the dataId,
     * which is defined by each hash file.  The data should be in the same order
     * as the returned hash list - item 0 should correspond to hash 0, etc.
     * Otherwise, there are no restrictions on the returned data, as this is 
     * up to each hash class. 
     * 
     * @param dataId The unique data ID to return from the class.
     * @return The requested data, or null if there is no data or an invalid ID.
     */
    virtual std::vector<std::vector<uint8_t> > GetOtherDataByIndex(int dataId) {
        std::vector<std::vector<uint8_t> > returnVector;
        return returnVector;
    }
    
    /**
     * Exports a vector of vectors of the unique salts to use.
     * 
     * This function exports all the unique salts that need to be tried on the
     * GPU for cracking.  This merges duplicate salts before exporting, as
     * duplicate salts are just wasting time on the GPU.  There are no
     * restrictions on salt length with the returned data - it is up to the 
     * calling code to throw an error on a length exceeded condition.
     * 
     * @return A vector of vectors of unique salts to use for cracking.
     */
    virtual std::vector<std::vector<uint8_t> > ExportUniqueSalts() {
        std::vector<std::vector<uint8_t> > returnVector;
        return returnVector;
    }

};


#endif
