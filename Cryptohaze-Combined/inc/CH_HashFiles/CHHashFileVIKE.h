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
 * CHHashFileVIKE is an implementation of the CHHashFileV class for 
 * IKE types in VPN initial exchanges.  It reads the exchange dump files in the
 * ike-scan format and stores the data as needed.
 * 
 * http://www.nta-monitor.com/tools/ike-scan/ for algorithm and sample code.
 * 
 */



#ifndef _CHHASHFILEVIKE_H
#define _CHHASHFILEVIKE_H

#include "CH_HashFiles/CHHashFileV.h"
#include <iostream>
#include <fstream>

/**
 * This is a struct containing all the needed data about the IKE hash to crack
 * it.  This will be requested and passed to the GPU in the needed format.
 */
typedef struct CHHashFileVIKE_IKEHashData {
    std::vector<uint8_t> skeyid_data;
    std::vector<uint8_t> hash_r_data;
    std::vector<uint8_t> hash_r;
} CHHashFileVIKE_IKEHashData;

class CHHashFileVIKE : public CHHashFileV {
protected:

    /**
     * A structure to contain data on each hash found.
     * 
     * This structure contains the various fields related to each hash.
     * These fields correspond to the fields used for the hashes, and are
     * built on the fly when reading the file in.  This prevents us from having
     * to join stuff again when building the data to crack.
     */
    typedef struct SaltedHashIKE {
        // Parameters we will pull in from the file.
        std::vector<uint8_t> skeyid_data;
        std::vector<uint8_t> hash_r_data;
        // Target hash we are looking for.
        std::vector<uint8_t> hash_r;
        // The found password if discovered
        std::vector<uint8_t> password;
        char passwordReported;
        char passwordFound;
        char passwordOutputToFile;
    } SaltedHashIKE;

    
    /**
     * A vector of all loaded hashes.
     * 
     * This is the main store of hashes.  It contains an entry for each line of
     * the hashfile loaded.
     */
    std::vector<SaltedHashIKE> IKEHashes;
    
    /**
     * The current hash length in bytes.  This is determined when the file is
     * loaded, and will either be 16 (MD5) or 20 (SHA1).  This is the length
     * of the hash_r field.
     * 
     * This is set on the first line read, and the read will abort if the hash
     * length changes mid-file.
     */
    uint32_t HashLengthBytes;
    
    /**
     * Appends the found hashes to the specified output file.
     * 
     * This function adds new found hashes to the open output file.  It appends
     * to the end of the file, and syncs the file if possible on the OS.  If the
     * output file is not being used, this function returns 0.
     * 
     * @return True if the hashes were successfully written, else false.
     */
    virtual int OutputFoundHashesToFile();
    
    
    
    /**
     * Sorts and unique the hash list by hash value.
     * 
     * This function sorts the currently loaded hashes based on the value of
     * the hash.  It also removes duplicate hashes to reduce the workload.
     */
    virtual void SortHashes();
    
    /**
     * Sort predicate: returns true if d1 < d2.
     * 
     * @param d1 First SaltedHashIKE struct
     * @param d2 Second SaltedHashIKE struct
     * @return true if d1.hash_r < d2.hash_r, else false.
     */
    static bool IKEHashSortPredicate(const SaltedHashIKE &d1, const SaltedHashIKE &d2);
    
    /**
     * Unique predicate: returns true if d1 == d2.
     * 
     * @param d1 First SaltedHashIKE struct
     * @param d2 Second SaltedHashIKE struct
     * @return true if d1.hash_r == d2.hash_r, else false.
     */
    
    static bool IKEHashUniquePredicate(const SaltedHashIKE &d1, const SaltedHashIKE &d2);
    
public:

    /**
     * Default constructor for CHHashFileVIKE.
     * 
     * Clears variables as needed.  All non-stl variables should be cleared.
     */
    CHHashFileVIKE();

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
    virtual int OpenHashFile(std::string filename);

    
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
    virtual std::vector<std::vector<uint8_t> > ExportUncrackedHashList();


    /**
     * Reports a found password.
     * 
     * This function is used to report a found password.  The hash and found 
     * password are reported.  If they are successfully imported as a new 
     * password/hash combination, the function returns 1, else 0.  0 may mean
     * that the hash is not present in the list, or may mean that the password
     * has already been reported.
     * 
     * @param hash A vector containing the hash corresponding to the found password.
     * @param password The found password for the hash.
     * @return 1 if the password is newly found, else 0.
     */
    virtual int ReportFoundPassword(std::vector<uint8_t> hash, std::vector<uint8_t> password);


    /**
     * Prints a list of all found hashes.
     * 
     * This function prints out a list of all found hashes and their passwords,
     * along with the hex of the password if requested.  It uses printf, so
     * call it after any curses display has been torn down.
     */
    virtual void PrintAllFoundHashes();


    /**
     * Prints out newly found hashes - ones that haven't been printed yet.
     * 
     * This function prints out found hashes that have not been printed yet.
     * It is used for display hashes as we find them in the daemon mode.  This
     * function uses printf, so must not be called during curses display.
     */
    virtual void PrintNewFoundHashes();

    
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
    virtual int OutputUnfoundHashesToFile(std::string filename);


    /**
     * Imports a hash list from a remote system.
     * 
     * This function is related to the network operation, and is used to import
     * a list of hashes/salts/etc from the remote system in a hashfile specific
     * format.  The only requirement is that this properly read the data
     * exported by the corresponding ExportHashListToRemoteSystem function in 
     * each class.  Other details are totally up to the implementation.  This
     * function overwrites any existing data in the class with the new received
     * data.
     * 
     * @param remoteData A vector of bytes from the remote system.
     */
    virtual void ImportHashListFromRemoteSystem(std::vector<uint8_t> remoteData);
    
    /**
     * Exports a list of hashes to a remote system.
     * 
     * This function is related to network operation, and is used to export a 
     * list of hashes or other data to the remote system.  This can be in a 
     * hashfile specific format, and the only requirement is that the
     * corresponding ImportHashListFromRemoteSystem can read the output format.
     * This function may export the entire hash list, or it may only export
     * the uncracked hashes.  If it exports the entire hash list, it should
     * also export data as to whether the hash has been cracked or not.
     * 
     * @return A vector of bytes to send to the remote system.
     */
    virtual std::vector<uint8_t> ExportHashListToRemoteSystem();

    /**
     * Returns the current hash length in bytes.
     * 
     * @return Hash length in bytes.
     */
    virtual uint32_t GetHashLengthBytes() {
        return this->HashLengthBytes;
    }
    
    /**
     * Exports all the data needed for the cracking of the IKE hashes.
     * @return 
     */
    std::vector<CHHashFileVIKE_IKEHashData> ExportUncrackedIKEHashes();
    
};


#endif
