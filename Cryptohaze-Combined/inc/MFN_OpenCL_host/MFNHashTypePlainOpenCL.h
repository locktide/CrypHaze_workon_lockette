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
 * MFNHashTypePlainOpenCL implements the OpenCL specific functions for plain hash
 * types.  This is a rough duplicate of functions in CHHashTypePlain for the
 * existing type.
 */

#ifndef __MFNHASHTYPEPLAINOPENCL_H
#define __MFNHASHTYPEPLAINOPENCL_H

#include "MFN_Common/MFNHashTypePlain.h"

#include "OpenCL_Common/GRTOpenCL.h"

class MFNHashTypePlainOpenCL : public MFNHashTypePlain {
public:
    MFNHashTypePlainOpenCL(int hashLengthBytes);
    ~MFNHashTypePlainOpenCL();
    
    /**
     * Override base functionality with an actual add of devices.
     */
    int setOpenCLDeviceID(int newOpenCLPlatformId, int newOpenCLDeviceId);
    
protected:
    virtual void setupDevice();

    virtual void teardownDevice();

    virtual void allocateThreadAndDeviceMemory();

    virtual void freeThreadAndDeviceMemory();

    virtual void copyDataToDevice();

    virtual void copyStartPointsToDevice();
    
    virtual void setupClassForMultithreadedEntry();

    virtual void synchronizeThreads();

    virtual void setStartPoints(uint64_t perThread, uint64_t startPoint);

    virtual void copyDeviceFoundPasswordsToHost();

    // This needs to be here, as it requires the host success lists.
    virtual void outputFoundHashes();

    
    // Host and memory device addresses.  These are per-class now, instead
    // of a vector.  This should make things easier and more foolproof.

    CryptohazeOpenCL *OpenCL;

    /**
     * Device full hashlist pointer.
     *
     * This contains the device memory address in which the
     * device hast list is stored.  This is used for the device hashlist
     * allocation, copy, and free.
     */
    cl_mem DeviceHashlistAddress;

    /**
     * A pointer to the host found password array region.
     */
    uint8_t *HostFoundPasswordsAddress;

    /**
     * The device found password address.
     */
    cl_mem DeviceFoundPasswordsAddress;

    /**
     * Pointer containing the host success/found password flags
     */
    uint8_t *HostSuccessAddress;

    /**
     * Pointer containing the host success reported flags.
     */
    uint8_t *HostSuccessReportedAddress;

    /**
     * Pointer containing the devices success addresses
     */
    cl_mem DeviceSuccessAddress;

    /**
     * Pointers to the device bitmaps.  Null if not present.
     */
    cl_mem DeviceBitmap128mb_a_Address;
    cl_mem DeviceBitmap128mb_b_Address;
    cl_mem DeviceBitmap128mb_c_Address;
    cl_mem DeviceBitmap128mb_d_Address;

    cl_mem DeviceBitmap8kb_a_Address;
    
    /**
     * Pointer to device start point addresses
     */
    cl_mem DeviceStartPointAddress;

    /**
     * Pointer to the device start passwords
     */
    cl_mem DeviceStartPasswords32Address;

    /**
     * A pointer to the host start point address
     */
    uint8_t *HostStartPointAddress;
    
    cl_mem DeviceForwardCharsetAddress;
    cl_mem DeviceReverseCharsetAddress;
    cl_mem DeviceCharsetLengthsAddress;
    
    
    cl_program HashProgram;
    cl_kernel HashKernel;

};

#endif