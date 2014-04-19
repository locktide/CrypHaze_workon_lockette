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

#ifndef __MFNDISPLAY_H
#define __MFNDISPLAY_H

#include <stdint.h>
#include <string>
#include <vector>
#include <boost/thread/mutex.hpp>
#include "MFN_Common/MFNDefines.h"

/**
 * This is a base display class for MFN devices.
 * 
 * Some of the existing functionality has been removed, as this class will now
 * get the workunit class and hashfile class automatically to get the WU
 * and cracked/total hash count.
 */

class MFNDisplay {
protected:
    // Thread type: CPU thread, GPU thread, or unused.
    std::vector<uint16_t> threadType;
    
    // Thread speeds in hashes per second
    std::vector<float> threadSpeeds;

    /**
     * A mutex for anything involving the thread type/rate vectors.  Given that
     * the new MFN framework will scale to 100s or more of hosts, the network
     * clients may be connecting and disconnecting at a decent rate.  This means
     * that the thread vectors may be getting resized decently often, and are
     * not threadsafe for writes without it.
     */
    boost::mutex displayThreadFunctionMutex;
    
    // Set for the debug class to enable prints in the functions.
    bool printDebugOutput;
    
    
    /**
     * Converts a rate into a human readable value with the K, M, B, etc suffix.
     * 
     * This function is used to convert widely varying rates into something that
     * humans can make sense of easily.
     * K = 1 000
     * M = 1 000 000
     * B = 1 000 000 000
     * T = 1 000 000 000 000
     * 
     * @param rate Rate to convert (raw floating point)
     * @return A string containing the rate, to two decimal points, with a suffix.
     */
    std::string getConvertedRateString(float rate);

public:
    
    MFNDisplay() {
        this->printDebugOutput = 0;
    }
    
    virtual ~MFNDisplay() {};

    virtual void Refresh() = 0;
    
    virtual void setHashName(std::string) = 0;
    virtual void setPasswordLen(uint16_t) = 0;
    virtual void addCrackedPassword(std::vector<uint8_t>) = 0;
    virtual void addStatusLine(std::string) = 0;
    virtual void addStatusLine(char *) = 0;
    // Sets the system mode: Standalone, network server, network client.
    virtual void setSystemMode(int, std::string) = 0;
    // Add or subtract from the number of connected clients
    virtual void alterNetworkClientCount(uint16_t) = 0;

    /**
     * Set the thread cracking speed given the thread ID.  Thread type has been
     * set already when the thread ID was obtained.
     * 
     * @param threadId The thread ID provided from getFreeThreadId
     * @param rate The cracking rate in hashes per second.
     */
    virtual void setThreadCrackSpeed(uint16_t threadId, float rate);

    /**
     * Returns a free thread ID to use, given the thread type.  This thread ID
     * should be kept for future calls to setThreadCrackSpeed.
     * 
     * @param newThreadType The thread type (CPU, GPU, Network, etc)
     * @return A unique thread ID to use in future calls.
     */
    virtual uint16_t getFreeThreadId(uint8_t newThreadType);
    
    /**
     * Release a thread ID from use.  This removes it from the display.
     */
    virtual void releaseThreadId(uint16_t oldThreadId);
    
    /**
     * Returns the total cracking rate for this host.
     * @return The sum of all the thread crack rates.
     */
    virtual float getCurrentCrackRate();
};

#endif