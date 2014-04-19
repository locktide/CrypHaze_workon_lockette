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
 * 
 * The class MFNHashTypePlain is the plain hash (unsalted) class implementation
 * for the new MFNHashType classes.  This class is still technology independent,
 * and implements the common functionality for hash types.  This handles the
 * basic setup and running of plain, unsalted hashes.
 *
 * This class also deals with the fact that some hashes are big endian and some
 * are little endian.  This refers to the loading of registers as compared to
 * the byte order in the hash.  MD5 is little endian, as you can simply load
 * the hash by converting the uint8_t array to a uint32_t pointer, and loading
 * the registers on a little endian architecture.  SHA1 is big endian, as the
 * hash to registers are loaded as though it is a big endian architecture.
 *
 * This is important to improve search performance.  The goal is for the search
 * algorithm on the device to never have to invert the byte ordering for hash
 * searching.  While this isn't a huge deal, as the bitmaps should take care
 * of most of this, it's still cleaner than the old method where the registers
 * have to be swapped for sorting and searching.
 */

#ifndef __MFNHASHTYPEPLAIN_H
#define __MFNHASHTYPEPLAIN_H

#include "MFN_Common/MFNHashType.h"

class MFNHashTypePlain : public MFNHashType {
public:
    /**
     * Constructor, providing the hash length in bytes.
     *
     * This is the constructor for all plain hash types.  This takes the length
     * of the hash in bytes, and handles all the setup for this.
     *
     * @param newHashLengthBytes The length of the hash being cracked.
     */
    MFNHashTypePlain(uint16_t newHashLengthBytes);

    /**
     * This is the entry point for password cracking of a given length.
     *
     * This will start the password cracking and launch all the required threads
     * for this password length.
     *
     * @param passwordLength The password length to crack.
     */
    void crackPasswordLength(int passwordLength);

    void GPU_Thread();

    virtual void sortHashes();

protected:
    /**
     * A mutex for changes to the static data structures in MFNHashTypePlain.
     */
    static boost::mutex MFNHashTypePlainMutex;

    virtual void RunGPUWorkunit(struct CHWorkunitRobustElement *WU);

    virtual void createLookupBitmaps();
    
    /**
     * Create an 8kb bitmap based on the provided hash list.
     * 
     * This function creates an 8kb bitmap based on the provided information.
     * startWord is what offset to start creating the bitmaps from - 0 for the
     * first word, 1 for the second word, etc.
     * The hashlist is passed in by reference, and is the list to create the 
     * bitmap for - either the raw list or the preprocessed list.
     * Finally, the result goes in the bitmap8kb vector.
     * Note that the bitmap uses the LOW order bits of each word, to prevent
     * the GPU from having to do an extra shift - it can just bitmask and do
     * one shift instead of having to shift the whole word.
     * 
     * The 8kb bitmaps are defined as follows:
     * 8192 bytes, 8 bits per byte.
     * Bits set are determined by the low 16 bits of each point in the hash.
     * Byte index is 13 bits, bit index is 3 bits.
     * Algorithm: To set:
     * First 13 bits of the hash (high order bits) are used as the index to the array.
     * Next 3 bits control the left-shift amount of the '1' bit.
     *
     * 
     * @param startWord The offset in the hash to start creating a bitmap for.
     * @param hashList The hashlist to create the bitmap for.
     * @param bitmap8kb The location to store the bitmap.
     */
    virtual void create8kbBitmap(uint8_t startWord, 
            std::vector<std::vector<uint8_t> > &hashList, std::vector<uint8_t> &bitmap8kb);


    /**
     * Create a 128mb bitmap based on the provided hash list.
     * 
     * This function creates a 128MB bitmap in the same general format as the
     * 8kb bitmap generator above.  It simply uses more bits (27 bits for the
     * index).
     * The startword is which word (32-bits) to create the bitmap for.
     * The hashlist is passed in by reference.
     * The bitmap128mb is the vector to create the bitmap in.
     * 
     * 
     * @param startWord 
     * @param hashList
     * @param bitmap128mb 
     */
    virtual void create128mbBitmap(uint8_t startWord, 
            std::vector<std::vector<uint8_t> > &hashList, std::vector<uint8_t> &bitmap128mb);

    /**
     * Create a lookup bitmap based on the provided hash list.
     *
     * This function creates a lookup bitmap in the same general format as the
     * 8kb bitmap generator above.  It simply uses more bits as specified.
     *
     * The startword is which word (32-bits) to create the bitmap for.
     * The hashlist is passed in by reference.
     * The bitmap128mb is the vector to create the bitmap in.
     *
     *
     * @param startWord
     * @param hashList
     * @param bitmap
     * @param bitmapSizeBytes Power of 2 size for bitmap.
     */
    virtual void createArbitraryBitmap(uint8_t startWord,
            std::vector<std::vector<uint8_t> > &hashList, std::vector<uint8_t> &bitmap128mb,
            uint32_t bitmapSizeBytes);

    /**
     * Copies the hashes from their vector of vectors format into a single
     * array that the device uses.
     */
    virtual void copyHashesIntoDeviceFormat();
    
    /**
     * Converts the vector of charset vectors into a single array of the length
     * that the device kernels use.
     */
    virtual void setupCharsetArrays();

    /**
     * Stores the specified start points as the actual characters that will go
     * onto the device, in 32-bit wide intervals, padded with the padding bit.
     *
     * This allows the device to simply load the values from this array, without
     * having to read the charset array.  It can load from the created array
     * into b0/b1/etc, and begin processing immediately.  This will likely be
     * used by all of the GPU and CPU kernels, as they can all load a vector
     * of 32-bit values in a sane parallel fashion.
     */
    virtual void setStartPasswords32(uint64_t perThread, uint64_t startPoint);


    /**
     * True if the various data is initialized, else false.  Used when threads
     * acquire the mutex to see if they must do anything or if they can go
     * directly to device setup.
     */
    static uint8_t staticDataInitialized;
   
    /**
     * The length of the hash type, in bytes.  This must be the same for all threads.
     */
    static uint16_t hashLengthBytes;

    /**
     * Current password length being cracked.  Same for all threads.
     */
    static uint16_t passwordLength;
    
    /**
     * Number of 32-bit words needed in total for each password.  This is the
     * password length + 1 (for padding) rounded up to the nearest 4 bytes.
     */
    static uint16_t passwordLengthWords;


    /**
     * A copy of the active hashes - this is the raw version, not the modified
     * version.
     */
    static std::vector<std::vector<uint8_t> > activeHashesRaw;

    /**
     * A copy of the pre-processed hashes.
     */
    static std::vector<std::vector<uint8_t> > activeHashesProcessed;

    /**
     * A list of the processed hashes, in the format the device wants - a long
     * list of bytes.  Created by copyHashesIntoDeviceFormat().
     */
    static std::vector<uint8_t> activeHashesProcessedDeviceformat;

    /**
     * The current charset being used.
     */
    static std::vector<std::vector<uint8_t> > currentCharset;

    /**
     * Vectors for 8kb bitmaps (for shared memory).
     */
    static std::vector<uint8_t> sharedBitmap8kb_a;
    static std::vector<uint8_t> sharedBitmap8kb_b;
    static std::vector<uint8_t> sharedBitmap8kb_c;
    static std::vector<uint8_t> sharedBitmap8kb_d;

    /**
     * Vectors for the 128MB bitmaps (for global memory)
     */
    static std::vector<uint8_t> globalBitmap128mb_a;
    static std::vector<uint8_t> globalBitmap128mb_b;
    static std::vector<uint8_t> globalBitmap128mb_c;
    static std::vector<uint8_t> globalBitmap128mb_d;
    
    /**
     * The charsetForwardLookup is a forward lookup vector for the charset space.
     * It is passwordLen * 128 bytes long, and contains at each 128 byte
     * boundary the characters for the next position.  If the charset is a
     * single charset, the length is only 128 bytes.
     */
    static std::vector<uint8_t> charsetForwardLookup;
    
    /**
     * The charsetReverseLookup is an experiment to reduce the kernel
     * register count and try for improved performance.  This maps the value
     * of each character to the position in the charset.
     */

    static std::vector<uint8_t> charsetReverseLookup;
    
    /**
     * charsetLengths contains the length of the charset for each
     * password position.  This is used to determine when to wrap.
     */
    static std::vector<uint8_t> charsetLengths;


    /**
     * Number of steps to run per thread.  Persists across workunits.  Per-thread.
     */
    uint32_t perStep;

    /**
     * True if a single charset is used, false if a multi charset is used.
     */
    static uint8_t isSingleCharset;

    /**
     * The client ID from the workunit class to handle per-thread cancellation.
     */
    uint16_t ClientId;

    /**
     * Number of threads to run.  On CPU tasks, this will be the number of threads.
     */
    uint32_t GPUThreads;

    /**
     * Number of blocks to run.  On CPU tasks, this will be 1.
     */
    uint32_t GPUBlocks;
    
    /**
     * Vector width: How many vectors wide each thread is.
     */
    uint32_t VectorWidth;

    /**
     * The total width of the kernel - how many hashes in parallel.
     * GPUBlocks * GPUThreads * VectorWidth
     */
    uint32_t TotalKernelWidth;
    
    /**
     * Target kernel execution time in ms.  0 for "run until done."
     */
    uint32_t kernelTimeMs;

    /**
     * Target GPU device ID, if relevant.
     */
    uint16_t gpuDeviceId;

    /**
     * Target OpenCL platform ID, if relevant.
     */
    uint16_t openCLPlatformId;

    /**
     * Vector containing the start values as 4-byte values, ready to be loaded
     * directly into b0/b1/etc, with the end padding bit set.  These are loaded
     * with the actual characters to start with, and do not need to be further
     * processed.  This is packed in a sane format for GPUs.  This means that it
     * stores all the b0s together, then all the b1s together, and so forth.
     */
    std::vector<uint8_t> HostStartPasswords32;


};

#endif