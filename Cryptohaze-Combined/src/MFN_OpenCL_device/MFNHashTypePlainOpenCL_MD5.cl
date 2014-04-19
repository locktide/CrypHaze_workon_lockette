



// Things we should define in the calling code...
#define CPU_DEBUG 0
//#define BITALIGN 1
//#define NVIDIA_HACKS
//#define PASSWORD_LENGTH 6

// Make my UI sane...
#ifndef __OPENCL_VERSION__
    #define __kernel
    #define __global
    #define __local
    #define __private
    #define __constant
    #define get_global_id(x)
    #define restrict
    #include <vector_types.h>
#endif

#ifndef VECTOR_WIDTH
    //#error "VECTOR_WIDTH must be defined for compile!"
    #define VECTOR_WIDTH 4
#endif

#ifndef PASSWORD_LENGTH
    #define PASSWORD_LENGTH 5
#endif

#if VECTOR_WIDTH == 1
    #define vector_type uint
    #define vload_type vload1
    #define vstore_type vstore1
    #define grt_vector_2 1
    #define vload1(offset, p) (offset + *p) 
    #define grt_vector_1 1
    #undef E0
    #define E0
#elif VECTOR_WIDTH == 2
    #define vector_type uint2
    #define vload_type vload2
    #define vstore_type vstore2
    #define grt_vector_2 1
#elif VECTOR_WIDTH == 4
    #define vector_type uint4
    #define vload_type vload4
    #define vstore_type vstore4
    #define grt_vector_4 1
#elif VECTOR_WIDTH == 8
    #define vector_type uint8
    #define vload_type vload8
    #define vstore_type vstore8
    #define grt_vector_8 1
#elif VECTOR_WIDTH == 16
    #define vector_type uint16
    #define vload_type vload16
    #define vstore_type vstore16
    #define grt_vector_16 1
#else
    #error "Vector width not specified or invalid vector width specified!"
#endif


#ifdef CPU_DEBUG
#pragma OPENCL EXTENSION cl_amd_printf : enable
#endif

// Hash defines

#define MD5S11 7
#define MD5S12 12
#define MD5S13 17
#define MD5S14 22
#define MD5S21 5
#define MD5S22 9
#define MD5S23 14
#define MD5S24 20
#define MD5S31 4
#define MD5S32 11
#define MD5S33 16
#define MD5S34 23
#define MD5S41 6
#define MD5S42 10
#define MD5S43 15
#define MD5S44 21

// OPTIMIZED MD5 FUNCTIONS HERE
//#define MD5F(x,y,z) (((y ^ z) & x) ^ z)
//#define MD5G(x,y,z) (((x & y) & z) ^ y)

/* F, G, H and I are basic MD5 functions.
 */
#define MD5F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define MD5G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define MD5H(x, y, z) ((x) ^ (y) ^ (z))
#define MD5I(x, y, z) ((y) ^ ((x) | (~z)))


/* ROTATE_LEFT rotates x left n bits.
 */


#ifdef BITALIGN
#pragma OPENCL EXTENSION cl_amd_media_ops : enable
#define MD5ROTATE_LEFT(x, y) amd_bitalign(x, x, (uint)(32 - y))
#define MD5FF(a, b, c, d, x, s, ac) { \
 (a) += amd_bytealign((b),(c),(d)) + (x) + (vector_type)(ac); \
 (a) = MD5ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }

#elif NVIDIA_HACKS
#define MD5ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))
#define MD5FF(a, b, c, d, x, s, ac) { \
 (a) += MD5F ((b), (c), (d)) + (x) + (vector_type)(ac); \
 (a) = MD5ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#else
#define MD5ROTATE_LEFT(x, y) rotate((vector_type)x, (uint)y)
#define MD5FF(a, b, c, d, x, s, ac) { \
 (a) += MD5F ((b), (c), (d)) + (x) + (vector_type)(ac); \
 (a) = MD5ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#endif


#define MD5GG(a, b, c, d, x, s, ac) { \
 (a) += MD5G ((b), (c), (d)) + (x) + (vector_type)(ac); \
 (a) = MD5ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define MD5HH(a, b, c, d, x, s, ac) { \
 (a) += MD5H ((b), (c), (d)) + (x) + (vector_type)(ac); \
 (a) = MD5ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define MD5II(a, b, c, d, x, s, ac) { \
 (a) += MD5I ((b), (c), (d)) + (x) + (vector_type)(ac); \
 (a) = MD5ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }




#define MD5_FIRST_3_ROUNDS() { \
a = (vector_type)0x67452301; \
b = (vector_type)0xefcdab89; \
c = (vector_type)0x98badcfe; \
d = (vector_type)0x10325476; \
MD5FF(a, b, c, d, b0, MD5S11, 0xd76aa478); \
MD5FF(d, a, b, c, b1, MD5S12, 0xe8c7b756); \
MD5FF(c, d, a, b, b2, MD5S13, 0x242070db); \
MD5FF(b, c, d, a, b3, MD5S14, 0xc1bdceee); \
MD5FF(a, b, c, d, b4, MD5S11, 0xf57c0faf); \
MD5FF(d, a, b, c, b5, MD5S12, 0x4787c62a); \
MD5FF(c, d, a, b, b6, MD5S13, 0xa8304613); \
MD5FF(b, c, d, a, b7, MD5S14, 0xfd469501); \
MD5FF(a, b, c, d, b8, MD5S11, 0x698098d8); \
MD5FF(d, a, b, c, b9, MD5S12, 0x8b44f7af); \
MD5FF(c, d, a, b, b10, MD5S13, 0xffff5bb1); \
MD5FF(b, c, d, a, b11, MD5S14, 0x895cd7be); \
MD5FF(a, b, c, d, b12, MD5S11, 0x6b901122); \
MD5FF(d, a, b, c, b13, MD5S12, 0xfd987193); \
MD5FF(c, d, a, b, b14, MD5S13, 0xa679438e); \
MD5FF(b, c, d, a, b15, MD5S14, 0x49b40821); \
MD5GG(a, b, c, d, b1, MD5S21, 0xf61e2562); \
MD5GG(d, a, b, c, b6, MD5S22, 0xc040b340); \
MD5GG(c, d, a, b, b11, MD5S23, 0x265e5a51); \
MD5GG(b, c, d, a, b0, MD5S24, 0xe9b6c7aa); \
MD5GG(a, b, c, d, b5, MD5S21, 0xd62f105d); \
MD5GG(d, a, b, c, b10, MD5S22, 0x2441453); \
MD5GG(c, d, a, b, b15, MD5S23, 0xd8a1e681); \
MD5GG(b, c, d, a, b4, MD5S24, 0xe7d3fbc8); \
MD5GG(a, b, c, d, b9, MD5S21, 0x21e1cde6); \
MD5GG(d, a, b, c, b14, MD5S22, 0xc33707d6); \
MD5GG(c, d, a, b, b3, MD5S23, 0xf4d50d87); \
MD5GG(b, c, d, a, b8, MD5S24, 0x455a14ed); \
MD5GG(a, b, c, d, b13, MD5S21, 0xa9e3e905); \
MD5GG(d, a, b, c, b2, MD5S22, 0xfcefa3f8); \
MD5GG(c, d, a, b, b7, MD5S23, 0x676f02d9); \
MD5GG(b, c, d, a, b12, MD5S24, 0x8d2a4c8a); \
MD5HH(a, b, c, d, b5, MD5S31, 0xfffa3942); \
MD5HH(d, a, b, c, b8, MD5S32, 0x8771f681); \
MD5HH(c, d, a, b, b11, MD5S33, 0x6d9d6122); \
MD5HH(b, c, d, a, b14, MD5S34, 0xfde5380c); \
MD5HH(a, b, c, d, b1, MD5S31, 0xa4beea44); \
MD5HH(d, a, b, c, b4, MD5S32, 0x4bdecfa9); \
MD5HH(c, d, a, b, b7, MD5S33, 0xf6bb4b60); \
MD5HH(b, c, d, a, b10, MD5S34, 0xbebfbc70); \
MD5HH(a, b, c, d, b13, MD5S31, 0x289b7ec6); \
MD5HH(d, a, b, c, b0, MD5S32, 0xeaa127fa); \
MD5HH(c, d, a, b, b3, MD5S33, 0xd4ef3085); \
MD5HH(b, c, d, a, b6, MD5S34, 0x4881d05); \
MD5HH(a, b, c, d, b9, MD5S31, 0xd9d4d039); \
MD5HH(d, a, b, c, b12, MD5S32, 0xe6db99e5); \
MD5HH(c, d, a, b, b15, MD5S33, 0x1fa27cf8); \
MD5HH(b, c, d, a, b2, MD5S34, 0xc4ac5665); \
}


/**
 * The maximum charset length supported by this hash type.
 */
#define MFN_HASH_TYPE_PLAIN_CUDA_MD5_MAX_CHARSET_LENGTH 128

#define ResetCharacterAtPosition(character, position, suffix) { \
    int offset = position / 4; \
    if (offset == 0) { \
        b0.s##suffix &= ~(0x000000ff << (8 * (position % 4))); \
        b0.s##suffix |= character << (8 * (position % 4)); \
    } else if (offset == 1) { \
        b1.s##suffix &= ~(0x000000ff << (8 * (position % 4))); \
        b1.s##suffix |= character << (8 * (position % 4)); \
    } \
}


// dfp: Device Found Passwords
// dfpf: Device Found Passwords Flags
#define CopyFoundPasswordToMemory(dfp, dfpf, suffix) { \
    switch ( PASSWORD_LENGTH ) { \
        case 16: \
            dfp[search_index * PASSWORD_LENGTH + 15] = (b3.s##suffix >> 24) & 0xff; \
        case 15: \
            dfp[search_index * PASSWORD_LENGTH + 14] = (b3.s##suffix >> 16) & 0xff; \
        case 14: \
            dfp[search_index * PASSWORD_LENGTH + 13] = (b3.s##suffix >> 8) & 0xff; \
        case 13: \
            dfp[search_index * PASSWORD_LENGTH + 12] = (b3.s##suffix >> 0) & 0xff; \
        case 12: \
            dfp[search_index * PASSWORD_LENGTH + 11] = (b2.s##suffix >> 24) & 0xff; \
        case 11: \
            dfp[search_index * PASSWORD_LENGTH + 10] = (b2.s##suffix >> 16) & 0xff; \
        case 10: \
            dfp[search_index * PASSWORD_LENGTH + 9] = (b2.s##suffix >> 8) & 0xff; \
        case 9: \
            dfp[search_index * PASSWORD_LENGTH + 8] = (b2.s##suffix >> 0) & 0xff; \
        case 8: \
            dfp[search_index * PASSWORD_LENGTH + 7] = (b1.s##suffix >> 24) & 0xff; \
        case 7: \
            dfp[search_index * PASSWORD_LENGTH + 6] = (b1.s##suffix >> 16) & 0xff; \
        case 6: \
            dfp[search_index * PASSWORD_LENGTH + 5] = (b1.s##suffix >> 8) & 0xff; \
        case 5: \
            dfp[search_index * PASSWORD_LENGTH + 4] = (b1.s##suffix >> 0) & 0xff; \
        case 4: \
            dfp[search_index * PASSWORD_LENGTH + 3] = (b0.s##suffix >> 24) & 0xff; \
        case 3: \
            dfp[search_index * PASSWORD_LENGTH + 2] = (b0.s##suffix >> 16) & 0xff; \
        case 2: \
            dfp[search_index * PASSWORD_LENGTH + 1] = (b0.s##suffix >> 8) & 0xff; \
        case 1: \
            dfp[search_index * PASSWORD_LENGTH + 0] = (b0.s##suffix >> 0) & 0xff; \
    } \
    deviceGlobalFoundPasswordFlagsPlainMD5[search_index] = (unsigned char) 1; \
}


#define CheckPassword128LE(dgh, dfp, dfpf, dnh, suffix) { \
    search_high = dnh; \
    search_low = 0; \
    while (search_low < search_high) { \
        search_index = search_low + (search_high - search_low) / 2; \
        current_hash_value = dgh[4 * search_index]; \
        if (current_hash_value < a.s##suffix) { \
            search_low = search_index + 1; \
        } else { \
            search_high = search_index; \
        } \
        if ((a.s##suffix == current_hash_value) && (search_low < dnh)) { \
            break; \
        } \
    } \
    if (a.s##suffix == current_hash_value) { \
        while (search_index && (a.s##suffix == dgh[(search_index - 1) * 4])) { \
            search_index--; \
        } \
        while ((a.s##suffix == dgh[search_index * 4])) { \
            if (b.s##suffix == dgh[search_index * 4 + 1]) { \
                if (c.s##suffix == dgh[search_index * 4 + 2]) { \
                    if (d.s##suffix == dgh[search_index * 4 + 3]) { \
                    /*printf("YEHAA!\n");*/ \
                    CopyFoundPasswordToMemory(dfp, dfpf, suffix); \
                    } \
                } \
            } \
            search_index++; \
        } \
    } \
}


// sb: shared bitmap a
// gb{a-d}: global bitmap a-d
// dgh: Device Global hashlist
// dfp: Device Found Passwords
// dfpf: Device Found Passwords Flags
// dnh: Device number hashes
#define checkPassword(sb, gba, gbb, gbc, gbd, dgh, dfp, dfpf, dnh, suffix) { \
    if ((sb[(a.s##suffix & 0x0000ffff) >> 3] >> (a.s##suffix & 0x00000007)) & 0x00000001) { \
        if (!(gba) || ((gba[(a.s##suffix >> 3) & 0x07FFFFFF] >> (a.s##suffix & 0x7)) & 0x1)) { \
            if (!gbb || ((gbb[(b.s##suffix >> 3) & 0x07FFFFFF] >> (b.s##suffix & 0x7)) & 0x1)) { \
                if (!gbc || ((gbc[(c.s##suffix >> 3) & 0x07FFFFFF] >> (c.s##suffix & 0x7)) & 0x1)) { \
                    if (!gbd || ((gbd[(d.s##suffix >> 3) & 0x07FFFFFF] >> (d.s##suffix & 0x7)) & 0x1)) { \
                        /*printf("Bitmap HIT!\n");*/ \
                        CheckPassword128LE(dgh, dfp, dfpf, dnh, suffix); \
                    } \
                } \
            } \
        } \
    } \
}





#define loadPasswordSingle(gsp, dt, pl, vectorpos) { \
/*printf("Thread %d vecpos %d pos0: %d\n", get_global_id(0), vectorpos, 0 * dt + (get_global_id(0) * VECTOR_WIDTH) + vectorpos);*/ \
if (pl > 0) {ResetCharacterAtPosition(gsp[0 * dt + (get_global_id(0) * VECTOR_WIDTH) + vectorpos], 0, vectorpos);} \
if (pl > 1) {ResetCharacterAtPosition(gsp[1 * dt + (get_global_id(0) * VECTOR_WIDTH) + vectorpos], 1, vectorpos);} \
if (pl > 2) {ResetCharacterAtPosition(gsp[2 * dt + (get_global_id(0) * VECTOR_WIDTH) + vectorpos], 2, vectorpos);} \
if (pl > 3) {ResetCharacterAtPosition(gsp[3 * dt + (get_global_id(0) * VECTOR_WIDTH) + vectorpos], 3, vectorpos);} \
if (pl > 4) {ResetCharacterAtPosition(gsp[4 * dt + (get_global_id(0) * VECTOR_WIDTH) + vectorpos], 4, vectorpos);} \
if (pl > 5) {ResetCharacterAtPosition(gsp[5 * dt + (get_global_id(0) * VECTOR_WIDTH) + vectorpos], 5, vectorpos);} \
if (pl > 6) {ResetCharacterAtPosition(gsp[6 * dt + (get_global_id(0) * VECTOR_WIDTH) + vectorpos], 6, vectorpos);} \
if (pl > 7) {ResetCharacterAtPosition(gsp[7 * dt + (get_global_id(0) * VECTOR_WIDTH) + vectorpos], 7, vectorpos);} \
if (pl > 8) {ResetCharacterAtPosition(gsp[8 * dt + (get_global_id(0) * VECTOR_WIDTH) + vectorpos], 8, vectorpos);} \
ResetCharacterAtPosition(0x80, pl, vectorpos); \
}

__kernel void MFNHashTypePlainOpenCL_MD5(
    __constant unsigned char const * restrict deviceCharsetPlainMD5, /* 0 */
    __constant unsigned char const * restrict deviceReverseCharsetPlainMD5, /* 1 */
    __constant unsigned char const * restrict charsetLengthsPlainMD5, /* 2 */
    __constant unsigned char const * restrict constantBitmapAPlainMD5, /* 3 */
        
    __private unsigned long const numberOfHashesPlainMD5, /* 4 */
    __global   unsigned int const * restrict deviceGlobalHashlistAddressPlainMD5, /* 5 */
    __global   unsigned char *deviceGlobalFoundPasswordsPlainMD5, /* 6 */
    __global   unsigned char *deviceGlobalFoundPasswordFlagsPlainMD5, /* 7 */
        
    __global   unsigned char const * restrict deviceGlobalBitmapAPlainMD5, /* 8 */
    __global   unsigned char const * restrict deviceGlobalBitmapBPlainMD5, /* 9 */
    __global   unsigned char const * restrict deviceGlobalBitmapCPlainMD5, /* 10 */
    __global   unsigned char const * restrict deviceGlobalBitmapDPlainMD5, /* 11 */
        
    __global   unsigned char *deviceGlobalStartPointsPlainMD5, /* 12 */
    __private unsigned long const deviceNumberThreadsPlainMD5, /* 13 */
    __private unsigned int const deviceNumberStepsToRunPlainMD5, /* 14 */
    __global   unsigned int const * restrict deviceGlobalStartPasswordsPlainMD5 /* 15 */
) {
    // Start the kernel.
    __local unsigned char sharedCharsetPlainMD5[MFN_HASH_TYPE_PLAIN_CUDA_MD5_MAX_CHARSET_LENGTH * PASSWORD_LENGTH];
    __local unsigned char sharedReverseCharsetPlainMD5[MFN_HASH_TYPE_PLAIN_CUDA_MD5_MAX_CHARSET_LENGTH * PASSWORD_LENGTH];
    __local unsigned char sharedCharsetLengthsPlainMD5[PASSWORD_LENGTH];
    __local unsigned char sharedBitmap[8192];
    vector_type b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, a, b, c, d, bitmap_index;

    unsigned long password_count = 0;
    unsigned int passOffset;
    unsigned int search_high, search_low, search_index, current_hash_value;
#if CPU_DEBUG
    //printf("Kernel start, global id %d\n", get_global_id(0));
    
    if (get_global_id(0) == 0) {
        printf("Charset forward: %c %c %c ...\n", 
                deviceCharsetPlainMD5[0], deviceCharsetPlainMD5[1], deviceCharsetPlainMD5[2]);
        printf("Charset lengths: %d %d %d...\n", charsetLengthsPlainMD5[0], 
                charsetLengthsPlainMD5[1], charsetLengthsPlainMD5[2]);
        printf("Number hashes: %d\n", numberOfHashesPlainMD5);
        printf("Bitmap A: %lu\n", deviceGlobalBitmapAPlainMD5);
        printf("Bitmap B: %lu\n", deviceGlobalBitmapBPlainMD5);
        printf("Bitmap C: %lu\n", deviceGlobalBitmapCPlainMD5);
        printf("Bitmap D: %lu\n", deviceGlobalBitmapDPlainMD5);
        printf("Number threads: %lu\n", deviceNumberThreadsPlainMD5);
        printf("Steps to run: %u\n", deviceNumberStepsToRunPlainMD5);
        printf("PASSWORD_LENGTH: %d\n", PASSWORD_LENGTH);
        printf("VECTOR_WIDTH: %d\n", VECTOR_WIDTH);
        
        int i, j;
        
        //for (i = 0; i < (deviceNumberThreadsPlainMD5 * PASSWORD_LENGTH); i++) {
        //    printf("%c", deviceGlobalStartPointsPlainMD5[i]);
        //}
        
        vector_type data0;
        
        //data0 = char0;
        
        //printf("data0.s1: %02x\n", data0.s1);
        //printf("data0.s2: %02x\n", data0.s2);
        //printf("data0.s3: %02x\n", data0.s3);
    }
#endif
    {
        uint counter;
        for (counter = 0; counter < (8192); counter++) {
            sharedBitmap[counter] = constantBitmapAPlainMD5[counter];
        }
        for (counter = 0; counter < (MFN_HASH_TYPE_PLAIN_CUDA_MD5_MAX_CHARSET_LENGTH * PASSWORD_LENGTH); counter++) {
            sharedCharsetPlainMD5[counter] = deviceCharsetPlainMD5[counter];
            sharedReverseCharsetPlainMD5[counter] = deviceReverseCharsetPlainMD5[counter];
        }
        for (counter = 0; counter < PASSWORD_LENGTH; counter++) {
            sharedCharsetLengthsPlainMD5[counter] = charsetLengthsPlainMD5[counter];
        }
    }
    
    b0 = b1 = b2 = b3 = b4 = b5 = b6 = b7 = b8 = b9 = b10 = b11 = b12 = b13 = b14 = b15 = (vector_type)0;
    b14 = (vector_type) (PASSWORD_LENGTH * 8);
    a = b = c = d = (vector_type) 0;

    b0 = vload_type(get_global_id(0), &deviceGlobalStartPasswordsPlainMD5[0]);
    if (PASSWORD_LENGTH > 3) {b1 = vload_type(get_global_id(0), &deviceGlobalStartPasswordsPlainMD5[1 * deviceNumberThreadsPlainMD5]);}
    if (PASSWORD_LENGTH > 7) {b2 = vload_type(get_global_id(0), &deviceGlobalStartPasswordsPlainMD5[2 * deviceNumberThreadsPlainMD5]);}
    if (PASSWORD_LENGTH > 11) {b3 = vload_type(get_global_id(0), &deviceGlobalStartPasswordsPlainMD5[3 * deviceNumberThreadsPlainMD5]);}
        
    while (password_count < deviceNumberStepsToRunPlainMD5) {
        MD5_FIRST_3_ROUNDS();
        MD5II(a, b, c, d, b0, MD5S41, 0xf4292244);
        MD5II(d, a, b, c, b7, MD5S42, 0x432aff97);
        MD5II(c, d, a, b, b14, MD5S43, 0xab9423a7);
        MD5II(b, c, d, a, b5, MD5S44, 0xfc93a039);
        MD5II(a, b, c, d, b12, MD5S41, 0x655b59c3);
        MD5II(d, a, b, c, b3, MD5S42, 0x8f0ccc92); 
        MD5II(c, d, a, b, b10, MD5S43, 0xffeff47d);
        MD5II(b, c, d, a, b1, MD5S44, 0x85845dd1);
        if (PASSWORD_LENGTH > 8) {
            MD5II (a, b, c, d, b8, MD5S41, 0x6fa87e4f);
            MD5II (d, a, b, c, b15, MD5S42, 0xfe2ce6e0);
            MD5II (c, d, a, b, b6, MD5S43, 0xa3014314);
            MD5II (b, c, d, a, b13, MD5S44, 0x4e0811a1);
            MD5II (a, b, c, d, b4, MD5S41, 0xf7537e82); 
            MD5II (d, a, b, c, b11, MD5S42, 0xbd3af235);
            MD5II (c, d, a, b, b2, MD5S43, 0x2ad7d2bb); 
            MD5II (b, c, d, a, b9, MD5S44, 0xeb86d391);
        }
/*
        printf(".s0 pass: %c%c%c%c%c%c hash: %08x%08x%08x%08x\n",
                (b0.s0 >> 0) & 0xff, (b0.s0 >> 8) & 0xff,
                (b0.s0 >> 16) & 0xff, (b0.s0 >> 24) & 0xff,
                (b1.s0 >> 0) & 0xff, (b1.s0 >> 8) & 0xff,
                a.s0, b.s0, c.s0, d.s0);
        printf(".s1 pass: %c%c%c%c%c%c hash: %08x%08x%08x%08x\n",
                (b0.s1 >> 0) & 0xff, (b0.s1 >> 8) & 0xff,
                (b0.s1 >> 16) & 0xff, (b0.s1 >> 24) & 0xff,
                (b1.s1 >> 0) & 0xff, (b1.s1 >> 8) & 0xff,
                a.s1, b.s1, c.s1, d.s1);
        printf(".s2 pass: %c%c%c%c%c%c hash: %08x%08x%08x%08x\n",
                (b0.s2 >> 0) & 0xff, (b0.s2 >> 8) & 0xff,
                (b0.s2 >> 16) & 0xff, (b0.s2 >> 24) & 0xff,
                (b1.s2 >> 0) & 0xff, (b1.s2 >> 8) & 0xff,
                a.s2, b.s2, c.s2, d.s2);
        printf(".s3 pass: %c%c%c%c%c%c hash: %08x%08x%08x%08x\n",
                (b0.s3 >> 0) & 0xff, (b0.s3 >> 8) & 0xff,
                (b0.s3 >> 16) & 0xff, (b0.s3 >> 24) & 0xff,
                (b1.s3 >> 0) & 0xff, (b1.s3 >> 8) & 0xff,
                a.s3, b.s3, c.s3, d.s3);
*/
        //checkHash128LE(a, b, c, d, b0, b1, b2, b3, sharedBitmap);
// dgh: Device Global hashlist
// dfp: Device Found Passwords
// dfpf: Device Found Passwords Flags
// dnh: Device number hashes
#if grt_vector_1 || grt_vector_2 || grt_vector_4 || grt_vector_8 || grt_vector_16
        checkPassword(sharedBitmap, deviceGlobalBitmapAPlainMD5, 
                deviceGlobalBitmapBPlainMD5, deviceGlobalBitmapCPlainMD5, 
                deviceGlobalBitmapDPlainMD5, deviceGlobalHashlistAddressPlainMD5, 
                deviceGlobalFoundPasswordsPlainMD5, deviceGlobalFoundPasswordFlagsPlainMD5,
                numberOfHashesPlainMD5, 0);
#endif
#if grt_vector_2 || grt_vector_4 || grt_vector_8 || grt_vector_16
        checkPassword(sharedBitmap, deviceGlobalBitmapAPlainMD5, 
                deviceGlobalBitmapBPlainMD5, deviceGlobalBitmapCPlainMD5, 
                deviceGlobalBitmapDPlainMD5, deviceGlobalHashlistAddressPlainMD5, 
                deviceGlobalFoundPasswordsPlainMD5, deviceGlobalFoundPasswordFlagsPlainMD5,
                numberOfHashesPlainMD5, 1);
#endif
#if grt_vector_4 || grt_vector_8 || grt_vector_16
        checkPassword(sharedBitmap, deviceGlobalBitmapAPlainMD5, 
                deviceGlobalBitmapBPlainMD5, deviceGlobalBitmapCPlainMD5, 
                deviceGlobalBitmapDPlainMD5, deviceGlobalHashlistAddressPlainMD5, 
                deviceGlobalFoundPasswordsPlainMD5, deviceGlobalFoundPasswordFlagsPlainMD5,
                numberOfHashesPlainMD5, 2);
        checkPassword(sharedBitmap, deviceGlobalBitmapAPlainMD5, 
                deviceGlobalBitmapBPlainMD5, deviceGlobalBitmapCPlainMD5, 
                deviceGlobalBitmapDPlainMD5, deviceGlobalHashlistAddressPlainMD5, 
                deviceGlobalFoundPasswordsPlainMD5, deviceGlobalFoundPasswordFlagsPlainMD5,
                numberOfHashesPlainMD5, 3);
#endif
#if grt_vector_8 || grt_vector_16
        checkPassword(sharedBitmap, deviceGlobalBitmapAPlainMD5, 
                deviceGlobalBitmapBPlainMD5, deviceGlobalBitmapCPlainMD5, 
                deviceGlobalBitmapDPlainMD5, deviceGlobalHashlistAddressPlainMD5, 
                deviceGlobalFoundPasswordsPlainMD5, deviceGlobalFoundPasswordFlagsPlainMD5,
                numberOfHashesPlainMD5, 4);
        checkPassword(sharedBitmap, deviceGlobalBitmapAPlainMD5, 
                deviceGlobalBitmapBPlainMD5, deviceGlobalBitmapCPlainMD5, 
                deviceGlobalBitmapDPlainMD5, deviceGlobalHashlistAddressPlainMD5, 
                deviceGlobalFoundPasswordsPlainMD5, deviceGlobalFoundPasswordFlagsPlainMD5,
                numberOfHashesPlainMD5, 5);
        checkPassword(sharedBitmap, deviceGlobalBitmapAPlainMD5, 
                deviceGlobalBitmapBPlainMD5, deviceGlobalBitmapCPlainMD5, 
                deviceGlobalBitmapDPlainMD5, deviceGlobalHashlistAddressPlainMD5, 
                deviceGlobalFoundPasswordsPlainMD5, deviceGlobalFoundPasswordFlagsPlainMD5,
                numberOfHashesPlainMD5, 6);
        checkPassword(sharedBitmap, deviceGlobalBitmapAPlainMD5, 
                deviceGlobalBitmapBPlainMD5, deviceGlobalBitmapCPlainMD5, 
                deviceGlobalBitmapDPlainMD5, deviceGlobalHashlistAddressPlainMD5, 
                deviceGlobalFoundPasswordsPlainMD5, deviceGlobalFoundPasswordFlagsPlainMD5,
                numberOfHashesPlainMD5, 7);
#endif
#if grt_vector_16
        checkPassword(sharedBitmap, deviceGlobalBitmapAPlainMD5, 
                deviceGlobalBitmapBPlainMD5, deviceGlobalBitmapCPlainMD5, 
                deviceGlobalBitmapDPlainMD5, deviceGlobalHashlistAddressPlainMD5, 
                deviceGlobalFoundPasswordsPlainMD5, deviceGlobalFoundPasswordFlagsPlainMD5,
                numberOfHashesPlainMD5, 8);
        checkPassword(sharedBitmap, deviceGlobalBitmapAPlainMD5, 
                deviceGlobalBitmapBPlainMD5, deviceGlobalBitmapCPlainMD5, 
                deviceGlobalBitmapDPlainMD5, deviceGlobalHashlistAddressPlainMD5, 
                deviceGlobalFoundPasswordsPlainMD5, deviceGlobalFoundPasswordFlagsPlainMD5,
                numberOfHashesPlainMD5, 9);
        checkPassword(sharedBitmap, deviceGlobalBitmapAPlainMD5, 
                deviceGlobalBitmapBPlainMD5, deviceGlobalBitmapCPlainMD5, 
                deviceGlobalBitmapDPlainMD5, deviceGlobalHashlistAddressPlainMD5, 
                deviceGlobalFoundPasswordsPlainMD5, deviceGlobalFoundPasswordFlagsPlainMD5,
                numberOfHashesPlainMD5, 10);
        checkPassword(sharedBitmap, deviceGlobalBitmapAPlainMD5, 
                deviceGlobalBitmapBPlainMD5, deviceGlobalBitmapCPlainMD5, 
                deviceGlobalBitmapDPlainMD5, deviceGlobalHashlistAddressPlainMD5, 
                deviceGlobalFoundPasswordsPlainMD5, deviceGlobalFoundPasswordFlagsPlainMD5,
                numberOfHashesPlainMD5, 11);
        checkPassword(sharedBitmap, deviceGlobalBitmapAPlainMD5, 
                deviceGlobalBitmapBPlainMD5, deviceGlobalBitmapCPlainMD5, 
                deviceGlobalBitmapDPlainMD5, deviceGlobalHashlistAddressPlainMD5, 
                deviceGlobalFoundPasswordsPlainMD5, deviceGlobalFoundPasswordFlagsPlainMD5,
                numberOfHashesPlainMD5, 12);
        checkPassword(sharedBitmap, deviceGlobalBitmapAPlainMD5, 
                deviceGlobalBitmapBPlainMD5, deviceGlobalBitmapCPlainMD5, 
                deviceGlobalBitmapDPlainMD5, deviceGlobalHashlistAddressPlainMD5, 
                deviceGlobalFoundPasswordsPlainMD5, deviceGlobalFoundPasswordFlagsPlainMD5,
                numberOfHashesPlainMD5, 13);
        checkPassword(sharedBitmap, deviceGlobalBitmapAPlainMD5, 
                deviceGlobalBitmapBPlainMD5, deviceGlobalBitmapCPlainMD5, 
                deviceGlobalBitmapDPlainMD5, deviceGlobalHashlistAddressPlainMD5, 
                deviceGlobalFoundPasswordsPlainMD5, deviceGlobalFoundPasswordFlagsPlainMD5,
                numberOfHashesPlainMD5, 14);
        checkPassword(sharedBitmap, deviceGlobalBitmapAPlainMD5, 
                deviceGlobalBitmapBPlainMD5, deviceGlobalBitmapCPlainMD5, 
                deviceGlobalBitmapDPlainMD5, deviceGlobalHashlistAddressPlainMD5, 
                deviceGlobalFoundPasswordsPlainMD5, deviceGlobalFoundPasswordFlagsPlainMD5,
                numberOfHashesPlainMD5, 15);
#endif
        
        if (charsetLengthsPlainMD5[1] == 0) {
            switch (PASSWORD_LENGTH) {
                case 1:
#if grt_vector_1 || grt_vector_2 || grt_vector_4 || grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL1 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 0);
#endif
#if grt_vector_2 || grt_vector_4 || grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL1 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 1);
#endif
#if grt_vector_4 || grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL1 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 2);
                    MFNSingleIncrementorsOpenCL1 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 3);
#endif
#if grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL1 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 4);
                    MFNSingleIncrementorsOpenCL1 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 5);
                    MFNSingleIncrementorsOpenCL1 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 6);
                    MFNSingleIncrementorsOpenCL1 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 7);
#endif
#if grt_vector_16
                    MFNSingleIncrementorsOpenCL1 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 8);
                    MFNSingleIncrementorsOpenCL1 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 9);
                    MFNSingleIncrementorsOpenCL1 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 10);
                    MFNSingleIncrementorsOpenCL1 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 11);
                    MFNSingleIncrementorsOpenCL1 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 12);
                    MFNSingleIncrementorsOpenCL1 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 13);
                    MFNSingleIncrementorsOpenCL1 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 14);
                    MFNSingleIncrementorsOpenCL1 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 15);
#endif
                break;
                case 2:
#if grt_vector_1 || grt_vector_2 || grt_vector_4 || grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL2 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 0);
#endif
#if grt_vector_2 || grt_vector_4 || grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL2 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 1);
#endif
#if grt_vector_4 || grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL2 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 2);
                    MFNSingleIncrementorsOpenCL2 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 3);
#endif
#if grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL2 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 4);
                    MFNSingleIncrementorsOpenCL2 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 5);
                    MFNSingleIncrementorsOpenCL2 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 6);
                    MFNSingleIncrementorsOpenCL2 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 7);
#endif
#if grt_vector_16
                    MFNSingleIncrementorsOpenCL2 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 8);
                    MFNSingleIncrementorsOpenCL2 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 9);
                    MFNSingleIncrementorsOpenCL2 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 10);
                    MFNSingleIncrementorsOpenCL2 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 11);
                    MFNSingleIncrementorsOpenCL2 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 12);
                    MFNSingleIncrementorsOpenCL2 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 13);
                    MFNSingleIncrementorsOpenCL2 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 14);
                    MFNSingleIncrementorsOpenCL2 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 15);
#endif
                break;
                case 3:
#if grt_vector_1 || grt_vector_2 || grt_vector_4 || grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL3 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 0);
#endif
#if grt_vector_2 || grt_vector_4 || grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL3 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 1);
#endif
#if grt_vector_4 || grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL3 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 2);
                    MFNSingleIncrementorsOpenCL3 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 3);
#endif
#if grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL3 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 4);
                    MFNSingleIncrementorsOpenCL3 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 5);
                    MFNSingleIncrementorsOpenCL3 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 6);
                    MFNSingleIncrementorsOpenCL3 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 7);
#endif
#if grt_vector_16
                    MFNSingleIncrementorsOpenCL3 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 8);
                    MFNSingleIncrementorsOpenCL3 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 9);
                    MFNSingleIncrementorsOpenCL3 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 10);
                    MFNSingleIncrementorsOpenCL3 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 11);
                    MFNSingleIncrementorsOpenCL3 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 12);
                    MFNSingleIncrementorsOpenCL3 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 13);
                    MFNSingleIncrementorsOpenCL3 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 14);
                    MFNSingleIncrementorsOpenCL3 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 15);
#endif
                break;
                case 4:
#if grt_vector_1 || grt_vector_2 || grt_vector_4 || grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL4 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 0);
#endif
#if grt_vector_2 || grt_vector_4 || grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL4 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 1);
#endif
#if grt_vector_4 || grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL4 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 2);
                    MFNSingleIncrementorsOpenCL4 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 3);
#endif
#if grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL4 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 4);
                    MFNSingleIncrementorsOpenCL4 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 5);
                    MFNSingleIncrementorsOpenCL4 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 6);
                    MFNSingleIncrementorsOpenCL4 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 7);
#endif
#if grt_vector_16
                    MFNSingleIncrementorsOpenCL4 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 8);
                    MFNSingleIncrementorsOpenCL4 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 9);
                    MFNSingleIncrementorsOpenCL4 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 10);
                    MFNSingleIncrementorsOpenCL4 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 11);
                    MFNSingleIncrementorsOpenCL4 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 12);
                    MFNSingleIncrementorsOpenCL4 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 13);
                    MFNSingleIncrementorsOpenCL4 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 14);
                    MFNSingleIncrementorsOpenCL4 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 15);
#endif
                break;
                case 5:
#if grt_vector_1 || grt_vector_2 || grt_vector_4 || grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL5 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 0);
#endif
#if grt_vector_2 || grt_vector_4 || grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL5 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 1);
#endif
#if grt_vector_4 || grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL5 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 2);
                    MFNSingleIncrementorsOpenCL5 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 3);
#endif
#if grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL5 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 4);
                    MFNSingleIncrementorsOpenCL5 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 5);
                    MFNSingleIncrementorsOpenCL5 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 6);
                    MFNSingleIncrementorsOpenCL5 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 7);
#endif
#if grt_vector_16
                    MFNSingleIncrementorsOpenCL5 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 8);
                    MFNSingleIncrementorsOpenCL5 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 9);
                    MFNSingleIncrementorsOpenCL5 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 10);
                    MFNSingleIncrementorsOpenCL5 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 11);
                    MFNSingleIncrementorsOpenCL5 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 12);
                    MFNSingleIncrementorsOpenCL5 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 13);
                    MFNSingleIncrementorsOpenCL5 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 14);
                    MFNSingleIncrementorsOpenCL5 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 15);
#endif
                break;
                case 6:
#if grt_vector_1 || grt_vector_2 || grt_vector_4 || grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL6 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 0);
#endif
#if grt_vector_2 || grt_vector_4 || grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL6 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 1);
#endif
#if grt_vector_4 || grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL6 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 2);
                    MFNSingleIncrementorsOpenCL6 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 3);
#endif
#if grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL6 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 4);
                    MFNSingleIncrementorsOpenCL6 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 5);
                    MFNSingleIncrementorsOpenCL6 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 6);
                    MFNSingleIncrementorsOpenCL6 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 7);
#endif
#if grt_vector_16
                    MFNSingleIncrementorsOpenCL6 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 8);
                    MFNSingleIncrementorsOpenCL6 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 9);
                    MFNSingleIncrementorsOpenCL6 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 10);
                    MFNSingleIncrementorsOpenCL6 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 11);
                    MFNSingleIncrementorsOpenCL6 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 12);
                    MFNSingleIncrementorsOpenCL6 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 13);
                    MFNSingleIncrementorsOpenCL6 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 14);
                    MFNSingleIncrementorsOpenCL6 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 15);
#endif
                break;
                case 7:
#if grt_vector_1 || grt_vector_2 || grt_vector_4 || grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL7 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 0);
#endif
#if grt_vector_2 || grt_vector_4 || grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL7 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 1);
#endif
#if grt_vector_4 || grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL7 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 2);
                    MFNSingleIncrementorsOpenCL7 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 3);
#endif
#if grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL7 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 4);
                    MFNSingleIncrementorsOpenCL7 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 5);
                    MFNSingleIncrementorsOpenCL7 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 6);
                    MFNSingleIncrementorsOpenCL7 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 7);
#endif
#if grt_vector_16
                    MFNSingleIncrementorsOpenCL7 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 8);
                    MFNSingleIncrementorsOpenCL7 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 9);
                    MFNSingleIncrementorsOpenCL7 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 10);
                    MFNSingleIncrementorsOpenCL7 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 11);
                    MFNSingleIncrementorsOpenCL7 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 12);
                    MFNSingleIncrementorsOpenCL7 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 13);
                    MFNSingleIncrementorsOpenCL7 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 14);
                    MFNSingleIncrementorsOpenCL7 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 15);
#endif
                break;
                case 8:
#if grt_vector_1 || grt_vector_2 || grt_vector_4 || grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL8 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 0);
#endif
#if grt_vector_2 || grt_vector_4 || grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL8 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 1);
#endif
#if grt_vector_4 || grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL8 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 2);
                    MFNSingleIncrementorsOpenCL8 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 3);
#endif
#if grt_vector_8 || grt_vector_16
                    MFNSingleIncrementorsOpenCL8 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 4);
                    MFNSingleIncrementorsOpenCL8 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 5);
                    MFNSingleIncrementorsOpenCL8 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 6);
                    MFNSingleIncrementorsOpenCL8 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 7);
#endif
#if grt_vector_16
                    MFNSingleIncrementorsOpenCL8 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 8);
                    MFNSingleIncrementorsOpenCL8 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 9);
                    MFNSingleIncrementorsOpenCL8 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 10);
                    MFNSingleIncrementorsOpenCL8 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 11);
                    MFNSingleIncrementorsOpenCL8 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 12);
                    MFNSingleIncrementorsOpenCL8 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 13);
                    MFNSingleIncrementorsOpenCL8 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 14);
                    MFNSingleIncrementorsOpenCL8 (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5, 15);
#endif
                break;
            }
        } else {
                //makeMFNMultipleIncrementors##PASSWORD_LENGTH (sharedCharsetPlainMD5, sharedReverseCharsetPlainMD5, sharedCharsetLengthsPlainMD5);
        }
        password_count++; 
    }
    vstore_type(b0, get_global_id(0), &deviceGlobalStartPasswordsPlainMD5[0]);
    if (PASSWORD_LENGTH > 3) {vstore_type(b1, get_global_id(0), &deviceGlobalStartPasswordsPlainMD5[1 * deviceNumberThreadsPlainMD5]);}
    if (PASSWORD_LENGTH > 7) {vstore_type(b2, get_global_id(0), &deviceGlobalStartPasswordsPlainMD5[2 * deviceNumberThreadsPlainMD5]);}
    if (PASSWORD_LENGTH > 11) {vstore_type(b3, get_global_id(0), &deviceGlobalStartPasswordsPlainMD5[3 * deviceNumberThreadsPlainMD5]);}
  
}
