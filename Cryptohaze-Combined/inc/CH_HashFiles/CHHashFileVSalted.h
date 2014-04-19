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
 * CHHashFileVSalted is an implementation of the CHHashFileV class for 
 * salted hash types with a simple salt separation.  It requires a separating
 * character that can be specified if not the default.
 * 
 * This class will separate out the salts, and sort/unique them to avoid doing
 * more work than needed - if a salt is present twice, this can be tried once
 * for the actual hash algorithm.  Also, the salts will be selected from the
 * passwords that are not cracked, because there's no point in trying a salt
 * that has already been cracked!  That just wastes time...
 * 
 * As a result of this, this hash class should also be able to export just the
 * unique salt list.  Remote hosts will use this to improve performance if
 * hashes have been cracked.
 * 
 */



#ifndef _CHHASHFILEVSALTED_H
#define _CHHASHFILEVSALTED_H

#include "CH_HashFiles/CHHashFileV.h"
#include <iostream>
#include <fstream>

// Some useful defines to make things easier to read.

// For newSaltIsLiteral value to the constructor
#define CHHASHFILESALTED_HEX_SALT 0
#define CHHASHFILESALTED_LITERAL_SALT 1

// For newSaltIsFirst value to the constructor
#define CHHASHFILESALTED_HASH_IS_FIRST 0
#define CHHASHFILESALTED_SALT_IS_FIRST 1




class CHHashFileVSalted : public CHHashFileV {
protected:

    /**
     * A structure to contain data for each hash.
     * 
     * This structure contains the various fields related to each hash.
     */    
    typedef struct HashSalted {
        std::vector<uint8_t> hash; /**< Hash in file order - as binary representation. */
        std::vector<uint8_t> salt; /**< Salt in file order - as binary representation. */
        std::vector<uint8_t> password; /**< Password related to the hash, or null */
        char passwordPrinted; /**< True if the password has been printed to screen */
        char passwordFound; /**< True if the password is found. */
        char passwordOutputToFile; /**< True if the password has been placed in the output file. */
    } HashSalted;

    
    /**
     * A vector of all loaded hashes.
     * 
     * This is the main store of hashes.  It contains an entry for each line of
     * the hashfile loaded.
     */
    std::vector<HashSalted> Hashes;
    
    /**
     * A vector containing all the unique salts.  This will be updated at intervals
     * based on updates to hashes.  This should only contain the salts for
     * uncracked hashes.
     */
    std::vector<std::vector<uint8_t> > UniqueSalts;
    
    /**
     * The current hash length in bytes.  Set by the constructor, and hashes
     * will be ignored if they do not match exactly.
     */
    uint32_t HashLengthBytes;
    
    /**
     * The max allowed salt length in bytes.  If 0, salt length is unlimited.
     * 
     * This may be set by the constructor.  If it is set and a salt of 
     * excessive length is found, it will be skipped.  It's probably a good
     * idea to leave this set to 0.
     */
    uint32_t MaxSaltLengthBytes;
    
    /**
     * Set if the salt value comes first in the password file.  Default is hash:salt
     */
    char SaltIsFirst;
    
    /**
     * Set if the salt should be read as a literal character string, not hex values.
     * 
     * If this is not set, the salt string is interpreted as a series of hex
     * values - a4b5c6 is a 3 byte salt.  If this is set, that sequence is 
     * read as a 6 byte salt.
     */
    char SaltIsLiteral;
    
    /**
     * The character separating hash and salt in the hash file.
     */
    char SeperatorSymbol;
    
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
     * Extract the unique salts from uncracked hashes.
     * 
     * This function will read the Hashes vector and copy all the uncracked
     * hashes to the UniqueSalts vector, then sort the hashes by byte order and 
     * remove duplicates.
     */
    virtual void ExtractUncrackedSalts();
    
    /**
     * Sort predicate: returns true if d1.hash < d2.hash.
     * 
     * @param d1 First HashSalted struct
     * @param d2 Second HashSalted struct
     * @return true if d1.hash < d2.hash, else false.
     */
    static bool SaltedHashSortPredicate(const HashSalted &d1, const HashSalted &d2);
    
    /**
     * Unique predicate: returns true if d1.hash == d2.hash.
     * 
     * @param d1 First HashSalted struct
     * @param d2 Second HashSalted struct
     * @return true if d1.hash == d2.hash, else false.
     */
    
    static bool SaltedHashUniquePredicate(const HashSalted &d1, const HashSalted &d2);
    
public:

    /**
     * Default constructor for CHHashFileVSalted.
     * 
     * Sets up the data needed for the class as described below.
     * newHashLengthBytes specifies the length of the actual hash in bytes - 
     * so 16 for MD5 hashes, 20 for SHA1, etc.  This does not specify the
     * length of the hash line in the file, as this may include a salt of
     * arbitrary length.
     * 
     * newSaltIsFirst is set if the line is salt:hash, else the line is
     * assumed to be hash:salt
     * 
     * newLiteralSalt is set if the salt is literal (to be copied byte for byte).
     * Else, the salt is assumed to be ascii-hex and is decoded accordingly.
     * 
     * newSeperatorSymbol is set to the symbol that separates the hash and salt.
     * 
     * 
     * @param newHashLengthBytes The length of the target hash type, in bytes.
     * @param newMaxSaltLengthBytes The max length of the salt, 0 for unlimited.
     * @param newSaltIsFirst True if salt is first on each line.
     * @param newLiteralSalt True if salt is literal, else is assumed hex.
     * @param newSeperatorSymbol Set to the symbol separating hash and salt.
     * 
     */
    CHHashFileVSalted(int newHashLengthBytes, int newMaxSaltLengthBytes, 
            char newSaltIsFirst, char newSaltIsLiteral, char newSeperatorSymbol);

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
     * Exports the currently uncracked salts in a vector of vectors.
     * 
     * This function exports the salts associated with uncracked hashes in a 
     * vector of vectors in sorted order.
     * 
     * @return A vector of uncracked salts.
     */
    virtual std::vector<std::vector<uint8_t> > ExportUncrackedSaltList();

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
     * if the file was written successfully, else false.  They will be written
     * in the same format they were read in.
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
    virtual void ImportHashListFromRemoteSystem(::google::protobuf::Message & remoteData);
    
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
    virtual void ExportHashListToRemoteSystem(::google::protobuf:: Message &exportData);

    /**
     * Returns the current hash length in bytes.
     * 
     * @return Hash length in bytes.
     */
    virtual uint32_t GetHashLengthBytes() {
        return this->HashLengthBytes;
    }
    
};


#endif
