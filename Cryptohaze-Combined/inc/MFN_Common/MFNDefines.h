/**
 * This file contains various defines that are used throughout the code.
 * Ideally, changing stuff here will change it everywhere with a recompile.
 * 
 * Keep this file clean - it will be included in CUDA kernels and OpenCL kernels.
 * 
 * This means no fancy expansions, no includes, no classes.  JUST DEFINES.
 */

#ifndef __MFNDEFINES_H_
#define __MFNDEFINES_H_

/**
 * The maximum password length supported by the plan hashfiles.
 */
#define MFN_HASH_TYPE_PLAIN_MAX_PASSLEN 48

/**
 * The maximum charset length supported by the plain hashfiles.
 */
#define MFN_HASH_TYPE_PLAIN_MAX_CHARSET_LENGTH 128

/**
 * Display class defines
 */
#define UNUSED_THREAD 0
#define GPU_THREAD 1
#define CPU_THREAD 2
#define NETWORK_HOST 3

#define SYSTEM_MODE_STANDALONE 1
#define SYSTEM_MODE_SERVER 2
#define SYSTEM_MODE_CLIENT 3


//=============== Defines for the hash types ====================
// Default unspecified hash type.
#define MFN_HASHTYPE_UNDEFINED 0x000

// Plain hashes: 0x1000 prefix
  // MD5: 0x000 prefix
    // MD5 Plain: Unsalted, arbitrary numbers
    #define MFN_HASHTYPE_PLAIN_MD5                  0x1000
    // MD5 Single: Unsalted, one hash.
    #define MFN_HASHTYPE_PLAIN_MD5_SINGLE           0x1001

  // MD5 Double: 0x0100 prefix
  // md5(md5($pass))
  #define MFN_HASHTYPE_DOUBLE_MD5                   0x1100

  // MD5 Triple: 0x0200 prefix
  // md5(md5(md5($pass)))
  #define MFN_HASHTYPE_TRIPLE_MD5                   0x1200
    
  // MD5 Duplicated: 0x0300 prefix
  // md5($pass.$pass)
  #define MFN_HASHTYPE_DUPLICATED_MD5               0x1300


  // NTLM: 0x400 prefix
  #define MFN_HASHTYPE_NTLM                         0x1400

  // NTLM Duplicated: 0x500 prefix
  #define MFN_HASHTYPE_DUPLICATED_NTLM              0x1500

  // LM Hashes: 0x600 prefix
  #define MFN_HASHTYPE_LM                           0x1600


//============ Defines for the hash factory ===========


// CHCharsetNew class identifier
#define CH_CHARSET_NEW_CLASS_ID 0x1000

// CHWorkunit class identifiers
#define CH_WORKUNIT_ROBUST_CLASS_ID 0x2000
#define CH_WORKUNIT_NETWORK_CLASS_ID 0x2001

// CHDisplay class identifiers
#define MFN_DISPLAY_CLASS_NCURSES 0x3000
#define MFN_DISPLAY_CLASS_DEBUG 0x3001
#define MFN_DISPLAY_CLASS_DAEMON 0x3002

// CHHashfile identifiers
#define CH_HASHFILE_PLAIN_16 0x4000
#define CH_HASHFILE_LM 0x4100

// Commandlinedata identifiers
#define CH_COMMANDLINEDATA 0x6000

// CHCUDAUtils identifiers
#define CH_CUDAUTILS 0x7000

// MFNHashIdentifiers identifiers
#define MFN_HASHIDENTIFIERS 0x8000

// Hashfile identifiers
#define CH_HASHTYPE_PLAIN_CUDA_MD5 0x10001

#define CH_HASHTYPE_PLAIN_OPENCL_MD5 0x20001

/**
 * Value for the default/invalid class ID.  This is set for classes that do not
 * have a default type.
 */
#define CH_CHARSET_CLASS_INVALID_ID 0xFFFFFFFF


// Byte-length identifiers for various password algorithms.
// These are used by the GPU for reporting what it found in multi-algorithm kernels.
#define MFN_PASSWORD_NOT_FOUND  0x0
#define MFN_PASSWORD_SINGLE_MD5 0x1
#define MFN_PASSWORD_DOUBLE_MD5 0x2
#define MFN_PASSWORD_TRIPLE_MD5 0x3
#define MFN_PASSWORD_NTLM       0x4

#endif