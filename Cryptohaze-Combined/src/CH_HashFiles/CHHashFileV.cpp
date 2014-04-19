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


#include <vector>
#include <string>
#include <stdlib.h>


std::vector<uint8_t> CHHashFileV::convertAsciiToBinary(std::string asciiHex) {
    std::vector<uint8_t> returnVector;
    char convertSpace[3];
    uint32_t result;
    int i;

    // Check for even length - if not even, return null vector.
    if (asciiHex.length() % 2) {
        return returnVector;
    }

    // Loop until either maxLength is hit, or strlen(intput) / 2 is hit.
    for (i = 0; i < (asciiHex.length() / 2); i++) {
        convertSpace[0] = asciiHex[2 * i];
        convertSpace[1] = asciiHex[2 * i + 1];
        convertSpace[2] = 0;
        sscanf(convertSpace, "%2x", &result);
        // Do this to prevent scanf from overwriting memory with a 4 byte value...
        returnVector.push_back((uint8_t) result & 0xff);
    }
    return returnVector;
}


std::vector<uint8_t> CHHashFileV::convertAsciiToBinary(std::vector<char> asciiHex) {
    std::vector<uint8_t> returnVector;
    char convertSpace[3];
    uint32_t result;
    int i;

    // Check for even length - if not even, return null vector.
    if (asciiHex.size() % 2) {
        return returnVector;
    }

    // Loop until either maxLength is hit, or strlen(intput) / 2 is hit.
    for (i = 0; i < (asciiHex.size() / 2); i++) {
        convertSpace[0] = asciiHex[2 * i];
        convertSpace[1] = asciiHex[2 * i + 1];
        convertSpace[2] = 0;
        sscanf(convertSpace, "%2x", &result);
        // Do this to prevent scanf from overwriting memory with a 4 byte value...
        returnVector.push_back((uint8_t) result & 0xff);
    }
    return returnVector;
}
