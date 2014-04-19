#define makeMFNSingleIncrementorsNTLM1(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[(b0 >> 0) & 0xff]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[0] << 0);\
} } 


#define makeMFNSingleIncrementorsNTLM2(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[(b0 >> 0) & 0xff]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[0] << 0);\
  passOffset = charsetReverse[(b0 >> 16) & 0xff]; \
  b0 &= 0xff00ffff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[passOffset] << 16);\
  if (passOffset >= charsetLengths[0]) { \
    b0 &= 0xff00ffff;\
    b0 |= (uint32_t)(charsetForward[0] << 16);\
} } } 


#define makeMFNSingleIncrementorsNTLM3(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[(b0 >> 0) & 0xff]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[0] << 0);\
  passOffset = charsetReverse[(b0 >> 16) & 0xff]; \
  b0 &= 0xff00ffff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[passOffset] << 16);\
  if (passOffset >= charsetLengths[0]) { \
    b0 &= 0xff00ffff;\
    b0 |= (uint32_t)(charsetForward[0] << 16);\
    passOffset = charsetReverse[(b1 >> 0) & 0xff]; \
    b1 &= 0xffffff00;\
    passOffset++;\
    b1 |= (uint32_t)(charsetForward[passOffset] << 0);\
    if (passOffset >= charsetLengths[0]) { \
      b1 &= 0xffffff00;\
      b1 |= (uint32_t)(charsetForward[0] << 0);\
} } } } 


#define makeMFNSingleIncrementorsNTLM4(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[(b0 >> 0) & 0xff]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[0] << 0);\
  passOffset = charsetReverse[(b0 >> 16) & 0xff]; \
  b0 &= 0xff00ffff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[passOffset] << 16);\
  if (passOffset >= charsetLengths[0]) { \
    b0 &= 0xff00ffff;\
    b0 |= (uint32_t)(charsetForward[0] << 16);\
    passOffset = charsetReverse[(b1 >> 0) & 0xff]; \
    b1 &= 0xffffff00;\
    passOffset++;\
    b1 |= (uint32_t)(charsetForward[passOffset] << 0);\
    if (passOffset >= charsetLengths[0]) { \
      b1 &= 0xffffff00;\
      b1 |= (uint32_t)(charsetForward[0] << 0);\
      passOffset = charsetReverse[(b1 >> 16) & 0xff]; \
      b1 &= 0xff00ffff;\
      passOffset++;\
      b1 |= (uint32_t)(charsetForward[passOffset] << 16);\
      if (passOffset >= charsetLengths[0]) { \
        b1 &= 0xff00ffff;\
        b1 |= (uint32_t)(charsetForward[0] << 16);\
} } } } } 


#define makeMFNSingleIncrementorsNTLM5(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[(b0 >> 0) & 0xff]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[0] << 0);\
  passOffset = charsetReverse[(b0 >> 16) & 0xff]; \
  b0 &= 0xff00ffff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[passOffset] << 16);\
  if (passOffset >= charsetLengths[0]) { \
    b0 &= 0xff00ffff;\
    b0 |= (uint32_t)(charsetForward[0] << 16);\
    passOffset = charsetReverse[(b1 >> 0) & 0xff]; \
    b1 &= 0xffffff00;\
    passOffset++;\
    b1 |= (uint32_t)(charsetForward[passOffset] << 0);\
    if (passOffset >= charsetLengths[0]) { \
      b1 &= 0xffffff00;\
      b1 |= (uint32_t)(charsetForward[0] << 0);\
      passOffset = charsetReverse[(b1 >> 16) & 0xff]; \
      b1 &= 0xff00ffff;\
      passOffset++;\
      b1 |= (uint32_t)(charsetForward[passOffset] << 16);\
      if (passOffset >= charsetLengths[0]) { \
        b1 &= 0xff00ffff;\
        b1 |= (uint32_t)(charsetForward[0] << 16);\
        passOffset = charsetReverse[(b2 >> 0) & 0xff]; \
        b2 &= 0xffffff00;\
        passOffset++;\
        b2 |= (uint32_t)(charsetForward[passOffset] << 0);\
        if (passOffset >= charsetLengths[0]) { \
          b2 &= 0xffffff00;\
          b2 |= (uint32_t)(charsetForward[0] << 0);\
} } } } } } 


#define makeMFNSingleIncrementorsNTLM6(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[(b0 >> 0) & 0xff]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[0] << 0);\
  passOffset = charsetReverse[(b0 >> 16) & 0xff]; \
  b0 &= 0xff00ffff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[passOffset] << 16);\
  if (passOffset >= charsetLengths[0]) { \
    b0 &= 0xff00ffff;\
    b0 |= (uint32_t)(charsetForward[0] << 16);\
    passOffset = charsetReverse[(b1 >> 0) & 0xff]; \
    b1 &= 0xffffff00;\
    passOffset++;\
    b1 |= (uint32_t)(charsetForward[passOffset] << 0);\
    if (passOffset >= charsetLengths[0]) { \
      b1 &= 0xffffff00;\
      b1 |= (uint32_t)(charsetForward[0] << 0);\
      passOffset = charsetReverse[(b1 >> 16) & 0xff]; \
      b1 &= 0xff00ffff;\
      passOffset++;\
      b1 |= (uint32_t)(charsetForward[passOffset] << 16);\
      if (passOffset >= charsetLengths[0]) { \
        b1 &= 0xff00ffff;\
        b1 |= (uint32_t)(charsetForward[0] << 16);\
        passOffset = charsetReverse[(b2 >> 0) & 0xff]; \
        b2 &= 0xffffff00;\
        passOffset++;\
        b2 |= (uint32_t)(charsetForward[passOffset] << 0);\
        if (passOffset >= charsetLengths[0]) { \
          b2 &= 0xffffff00;\
          b2 |= (uint32_t)(charsetForward[0] << 0);\
          passOffset = charsetReverse[(b2 >> 16) & 0xff]; \
          b2 &= 0xff00ffff;\
          passOffset++;\
          b2 |= (uint32_t)(charsetForward[passOffset] << 16);\
          if (passOffset >= charsetLengths[0]) { \
            b2 &= 0xff00ffff;\
            b2 |= (uint32_t)(charsetForward[0] << 16);\
} } } } } } } 


#define makeMFNSingleIncrementorsNTLM7(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[(b0 >> 0) & 0xff]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[0] << 0);\
  passOffset = charsetReverse[(b0 >> 16) & 0xff]; \
  b0 &= 0xff00ffff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[passOffset] << 16);\
  if (passOffset >= charsetLengths[0]) { \
    b0 &= 0xff00ffff;\
    b0 |= (uint32_t)(charsetForward[0] << 16);\
    passOffset = charsetReverse[(b1 >> 0) & 0xff]; \
    b1 &= 0xffffff00;\
    passOffset++;\
    b1 |= (uint32_t)(charsetForward[passOffset] << 0);\
    if (passOffset >= charsetLengths[0]) { \
      b1 &= 0xffffff00;\
      b1 |= (uint32_t)(charsetForward[0] << 0);\
      passOffset = charsetReverse[(b1 >> 16) & 0xff]; \
      b1 &= 0xff00ffff;\
      passOffset++;\
      b1 |= (uint32_t)(charsetForward[passOffset] << 16);\
      if (passOffset >= charsetLengths[0]) { \
        b1 &= 0xff00ffff;\
        b1 |= (uint32_t)(charsetForward[0] << 16);\
        passOffset = charsetReverse[(b2 >> 0) & 0xff]; \
        b2 &= 0xffffff00;\
        passOffset++;\
        b2 |= (uint32_t)(charsetForward[passOffset] << 0);\
        if (passOffset >= charsetLengths[0]) { \
          b2 &= 0xffffff00;\
          b2 |= (uint32_t)(charsetForward[0] << 0);\
          passOffset = charsetReverse[(b2 >> 16) & 0xff]; \
          b2 &= 0xff00ffff;\
          passOffset++;\
          b2 |= (uint32_t)(charsetForward[passOffset] << 16);\
          if (passOffset >= charsetLengths[0]) { \
            b2 &= 0xff00ffff;\
            b2 |= (uint32_t)(charsetForward[0] << 16);\
            passOffset = charsetReverse[(b3 >> 0) & 0xff]; \
            b3 &= 0xffffff00;\
            passOffset++;\
            b3 |= (uint32_t)(charsetForward[passOffset] << 0);\
            if (passOffset >= charsetLengths[0]) { \
              b3 &= 0xffffff00;\
              b3 |= (uint32_t)(charsetForward[0] << 0);\
} } } } } } } } 


#define makeMFNSingleIncrementorsNTLM8(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[(b0 >> 0) & 0xff]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[0] << 0);\
  passOffset = charsetReverse[(b0 >> 16) & 0xff]; \
  b0 &= 0xff00ffff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[passOffset] << 16);\
  if (passOffset >= charsetLengths[0]) { \
    b0 &= 0xff00ffff;\
    b0 |= (uint32_t)(charsetForward[0] << 16);\
    passOffset = charsetReverse[(b1 >> 0) & 0xff]; \
    b1 &= 0xffffff00;\
    passOffset++;\
    b1 |= (uint32_t)(charsetForward[passOffset] << 0);\
    if (passOffset >= charsetLengths[0]) { \
      b1 &= 0xffffff00;\
      b1 |= (uint32_t)(charsetForward[0] << 0);\
      passOffset = charsetReverse[(b1 >> 16) & 0xff]; \
      b1 &= 0xff00ffff;\
      passOffset++;\
      b1 |= (uint32_t)(charsetForward[passOffset] << 16);\
      if (passOffset >= charsetLengths[0]) { \
        b1 &= 0xff00ffff;\
        b1 |= (uint32_t)(charsetForward[0] << 16);\
        passOffset = charsetReverse[(b2 >> 0) & 0xff]; \
        b2 &= 0xffffff00;\
        passOffset++;\
        b2 |= (uint32_t)(charsetForward[passOffset] << 0);\
        if (passOffset >= charsetLengths[0]) { \
          b2 &= 0xffffff00;\
          b2 |= (uint32_t)(charsetForward[0] << 0);\
          passOffset = charsetReverse[(b2 >> 16) & 0xff]; \
          b2 &= 0xff00ffff;\
          passOffset++;\
          b2 |= (uint32_t)(charsetForward[passOffset] << 16);\
          if (passOffset >= charsetLengths[0]) { \
            b2 &= 0xff00ffff;\
            b2 |= (uint32_t)(charsetForward[0] << 16);\
            passOffset = charsetReverse[(b3 >> 0) & 0xff]; \
            b3 &= 0xffffff00;\
            passOffset++;\
            b3 |= (uint32_t)(charsetForward[passOffset] << 0);\
            if (passOffset >= charsetLengths[0]) { \
              b3 &= 0xffffff00;\
              b3 |= (uint32_t)(charsetForward[0] << 0);\
              passOffset = charsetReverse[(b3 >> 16) & 0xff]; \
              b3 &= 0xff00ffff;\
              passOffset++;\
              b3 |= (uint32_t)(charsetForward[passOffset] << 16);\
              if (passOffset >= charsetLengths[0]) { \
                b3 &= 0xff00ffff;\
                b3 |= (uint32_t)(charsetForward[0] << 16);\
} } } } } } } } } 


#define makeMFNSingleIncrementorsNTLM9(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[(b0 >> 0) & 0xff]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[0] << 0);\
  passOffset = charsetReverse[(b0 >> 16) & 0xff]; \
  b0 &= 0xff00ffff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[passOffset] << 16);\
  if (passOffset >= charsetLengths[0]) { \
    b0 &= 0xff00ffff;\
    b0 |= (uint32_t)(charsetForward[0] << 16);\
    passOffset = charsetReverse[(b1 >> 0) & 0xff]; \
    b1 &= 0xffffff00;\
    passOffset++;\
    b1 |= (uint32_t)(charsetForward[passOffset] << 0);\
    if (passOffset >= charsetLengths[0]) { \
      b1 &= 0xffffff00;\
      b1 |= (uint32_t)(charsetForward[0] << 0);\
      passOffset = charsetReverse[(b1 >> 16) & 0xff]; \
      b1 &= 0xff00ffff;\
      passOffset++;\
      b1 |= (uint32_t)(charsetForward[passOffset] << 16);\
      if (passOffset >= charsetLengths[0]) { \
        b1 &= 0xff00ffff;\
        b1 |= (uint32_t)(charsetForward[0] << 16);\
        passOffset = charsetReverse[(b2 >> 0) & 0xff]; \
        b2 &= 0xffffff00;\
        passOffset++;\
        b2 |= (uint32_t)(charsetForward[passOffset] << 0);\
        if (passOffset >= charsetLengths[0]) { \
          b2 &= 0xffffff00;\
          b2 |= (uint32_t)(charsetForward[0] << 0);\
          passOffset = charsetReverse[(b2 >> 16) & 0xff]; \
          b2 &= 0xff00ffff;\
          passOffset++;\
          b2 |= (uint32_t)(charsetForward[passOffset] << 16);\
          if (passOffset >= charsetLengths[0]) { \
            b2 &= 0xff00ffff;\
            b2 |= (uint32_t)(charsetForward[0] << 16);\
            passOffset = charsetReverse[(b3 >> 0) & 0xff]; \
            b3 &= 0xffffff00;\
            passOffset++;\
            b3 |= (uint32_t)(charsetForward[passOffset] << 0);\
            if (passOffset >= charsetLengths[0]) { \
              b3 &= 0xffffff00;\
              b3 |= (uint32_t)(charsetForward[0] << 0);\
              passOffset = charsetReverse[(b3 >> 16) & 0xff]; \
              b3 &= 0xff00ffff;\
              passOffset++;\
              b3 |= (uint32_t)(charsetForward[passOffset] << 16);\
              if (passOffset >= charsetLengths[0]) { \
                b3 &= 0xff00ffff;\
                b3 |= (uint32_t)(charsetForward[0] << 16);\
                passOffset = charsetReverse[(b4 >> 0) & 0xff]; \
                b4 &= 0xffffff00;\
                passOffset++;\
                b4 |= (uint32_t)(charsetForward[passOffset] << 0);\
                if (passOffset >= charsetLengths[0]) { \
                  b4 &= 0xffffff00;\
                  b4 |= (uint32_t)(charsetForward[0] << 0);\
} } } } } } } } } } 


#define makeMFNSingleIncrementorsNTLM10(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[(b0 >> 0) & 0xff]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[0] << 0);\
  passOffset = charsetReverse[(b0 >> 16) & 0xff]; \
  b0 &= 0xff00ffff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[passOffset] << 16);\
  if (passOffset >= charsetLengths[0]) { \
    b0 &= 0xff00ffff;\
    b0 |= (uint32_t)(charsetForward[0] << 16);\
    passOffset = charsetReverse[(b1 >> 0) & 0xff]; \
    b1 &= 0xffffff00;\
    passOffset++;\
    b1 |= (uint32_t)(charsetForward[passOffset] << 0);\
    if (passOffset >= charsetLengths[0]) { \
      b1 &= 0xffffff00;\
      b1 |= (uint32_t)(charsetForward[0] << 0);\
      passOffset = charsetReverse[(b1 >> 16) & 0xff]; \
      b1 &= 0xff00ffff;\
      passOffset++;\
      b1 |= (uint32_t)(charsetForward[passOffset] << 16);\
      if (passOffset >= charsetLengths[0]) { \
        b1 &= 0xff00ffff;\
        b1 |= (uint32_t)(charsetForward[0] << 16);\
        passOffset = charsetReverse[(b2 >> 0) & 0xff]; \
        b2 &= 0xffffff00;\
        passOffset++;\
        b2 |= (uint32_t)(charsetForward[passOffset] << 0);\
        if (passOffset >= charsetLengths[0]) { \
          b2 &= 0xffffff00;\
          b2 |= (uint32_t)(charsetForward[0] << 0);\
          passOffset = charsetReverse[(b2 >> 16) & 0xff]; \
          b2 &= 0xff00ffff;\
          passOffset++;\
          b2 |= (uint32_t)(charsetForward[passOffset] << 16);\
          if (passOffset >= charsetLengths[0]) { \
            b2 &= 0xff00ffff;\
            b2 |= (uint32_t)(charsetForward[0] << 16);\
            passOffset = charsetReverse[(b3 >> 0) & 0xff]; \
            b3 &= 0xffffff00;\
            passOffset++;\
            b3 |= (uint32_t)(charsetForward[passOffset] << 0);\
            if (passOffset >= charsetLengths[0]) { \
              b3 &= 0xffffff00;\
              b3 |= (uint32_t)(charsetForward[0] << 0);\
              passOffset = charsetReverse[(b3 >> 16) & 0xff]; \
              b3 &= 0xff00ffff;\
              passOffset++;\
              b3 |= (uint32_t)(charsetForward[passOffset] << 16);\
              if (passOffset >= charsetLengths[0]) { \
                b3 &= 0xff00ffff;\
                b3 |= (uint32_t)(charsetForward[0] << 16);\
                passOffset = charsetReverse[(b4 >> 0) & 0xff]; \
                b4 &= 0xffffff00;\
                passOffset++;\
                b4 |= (uint32_t)(charsetForward[passOffset] << 0);\
                if (passOffset >= charsetLengths[0]) { \
                  b4 &= 0xffffff00;\
                  b4 |= (uint32_t)(charsetForward[0] << 0);\
                  passOffset = charsetReverse[(b4 >> 16) & 0xff]; \
                  b4 &= 0xff00ffff;\
                  passOffset++;\
                  b4 |= (uint32_t)(charsetForward[passOffset] << 16);\
                  if (passOffset >= charsetLengths[0]) { \
                    b4 &= 0xff00ffff;\
                    b4 |= (uint32_t)(charsetForward[0] << 16);\
} } } } } } } } } } } 


#define makeMFNSingleIncrementorsNTLM11(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[(b0 >> 0) & 0xff]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[0] << 0);\
  passOffset = charsetReverse[(b0 >> 16) & 0xff]; \
  b0 &= 0xff00ffff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[passOffset] << 16);\
  if (passOffset >= charsetLengths[0]) { \
    b0 &= 0xff00ffff;\
    b0 |= (uint32_t)(charsetForward[0] << 16);\
    passOffset = charsetReverse[(b1 >> 0) & 0xff]; \
    b1 &= 0xffffff00;\
    passOffset++;\
    b1 |= (uint32_t)(charsetForward[passOffset] << 0);\
    if (passOffset >= charsetLengths[0]) { \
      b1 &= 0xffffff00;\
      b1 |= (uint32_t)(charsetForward[0] << 0);\
      passOffset = charsetReverse[(b1 >> 16) & 0xff]; \
      b1 &= 0xff00ffff;\
      passOffset++;\
      b1 |= (uint32_t)(charsetForward[passOffset] << 16);\
      if (passOffset >= charsetLengths[0]) { \
        b1 &= 0xff00ffff;\
        b1 |= (uint32_t)(charsetForward[0] << 16);\
        passOffset = charsetReverse[(b2 >> 0) & 0xff]; \
        b2 &= 0xffffff00;\
        passOffset++;\
        b2 |= (uint32_t)(charsetForward[passOffset] << 0);\
        if (passOffset >= charsetLengths[0]) { \
          b2 &= 0xffffff00;\
          b2 |= (uint32_t)(charsetForward[0] << 0);\
          passOffset = charsetReverse[(b2 >> 16) & 0xff]; \
          b2 &= 0xff00ffff;\
          passOffset++;\
          b2 |= (uint32_t)(charsetForward[passOffset] << 16);\
          if (passOffset >= charsetLengths[0]) { \
            b2 &= 0xff00ffff;\
            b2 |= (uint32_t)(charsetForward[0] << 16);\
            passOffset = charsetReverse[(b3 >> 0) & 0xff]; \
            b3 &= 0xffffff00;\
            passOffset++;\
            b3 |= (uint32_t)(charsetForward[passOffset] << 0);\
            if (passOffset >= charsetLengths[0]) { \
              b3 &= 0xffffff00;\
              b3 |= (uint32_t)(charsetForward[0] << 0);\
              passOffset = charsetReverse[(b3 >> 16) & 0xff]; \
              b3 &= 0xff00ffff;\
              passOffset++;\
              b3 |= (uint32_t)(charsetForward[passOffset] << 16);\
              if (passOffset >= charsetLengths[0]) { \
                b3 &= 0xff00ffff;\
                b3 |= (uint32_t)(charsetForward[0] << 16);\
                passOffset = charsetReverse[(b4 >> 0) & 0xff]; \
                b4 &= 0xffffff00;\
                passOffset++;\
                b4 |= (uint32_t)(charsetForward[passOffset] << 0);\
                if (passOffset >= charsetLengths[0]) { \
                  b4 &= 0xffffff00;\
                  b4 |= (uint32_t)(charsetForward[0] << 0);\
                  passOffset = charsetReverse[(b4 >> 16) & 0xff]; \
                  b4 &= 0xff00ffff;\
                  passOffset++;\
                  b4 |= (uint32_t)(charsetForward[passOffset] << 16);\
                  if (passOffset >= charsetLengths[0]) { \
                    b4 &= 0xff00ffff;\
                    b4 |= (uint32_t)(charsetForward[0] << 16);\
                    passOffset = charsetReverse[(b5 >> 0) & 0xff]; \
                    b5 &= 0xffffff00;\
                    passOffset++;\
                    b5 |= (uint32_t)(charsetForward[passOffset] << 0);\
                    if (passOffset >= charsetLengths[0]) { \
                      b5 &= 0xffffff00;\
                      b5 |= (uint32_t)(charsetForward[0] << 0);\
} } } } } } } } } } } } 


#define makeMFNSingleIncrementorsNTLM12(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[(b0 >> 0) & 0xff]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[0] << 0);\
  passOffset = charsetReverse[(b0 >> 16) & 0xff]; \
  b0 &= 0xff00ffff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[passOffset] << 16);\
  if (passOffset >= charsetLengths[0]) { \
    b0 &= 0xff00ffff;\
    b0 |= (uint32_t)(charsetForward[0] << 16);\
    passOffset = charsetReverse[(b1 >> 0) & 0xff]; \
    b1 &= 0xffffff00;\
    passOffset++;\
    b1 |= (uint32_t)(charsetForward[passOffset] << 0);\
    if (passOffset >= charsetLengths[0]) { \
      b1 &= 0xffffff00;\
      b1 |= (uint32_t)(charsetForward[0] << 0);\
      passOffset = charsetReverse[(b1 >> 16) & 0xff]; \
      b1 &= 0xff00ffff;\
      passOffset++;\
      b1 |= (uint32_t)(charsetForward[passOffset] << 16);\
      if (passOffset >= charsetLengths[0]) { \
        b1 &= 0xff00ffff;\
        b1 |= (uint32_t)(charsetForward[0] << 16);\
        passOffset = charsetReverse[(b2 >> 0) & 0xff]; \
        b2 &= 0xffffff00;\
        passOffset++;\
        b2 |= (uint32_t)(charsetForward[passOffset] << 0);\
        if (passOffset >= charsetLengths[0]) { \
          b2 &= 0xffffff00;\
          b2 |= (uint32_t)(charsetForward[0] << 0);\
          passOffset = charsetReverse[(b2 >> 16) & 0xff]; \
          b2 &= 0xff00ffff;\
          passOffset++;\
          b2 |= (uint32_t)(charsetForward[passOffset] << 16);\
          if (passOffset >= charsetLengths[0]) { \
            b2 &= 0xff00ffff;\
            b2 |= (uint32_t)(charsetForward[0] << 16);\
            passOffset = charsetReverse[(b3 >> 0) & 0xff]; \
            b3 &= 0xffffff00;\
            passOffset++;\
            b3 |= (uint32_t)(charsetForward[passOffset] << 0);\
            if (passOffset >= charsetLengths[0]) { \
              b3 &= 0xffffff00;\
              b3 |= (uint32_t)(charsetForward[0] << 0);\
              passOffset = charsetReverse[(b3 >> 16) & 0xff]; \
              b3 &= 0xff00ffff;\
              passOffset++;\
              b3 |= (uint32_t)(charsetForward[passOffset] << 16);\
              if (passOffset >= charsetLengths[0]) { \
                b3 &= 0xff00ffff;\
                b3 |= (uint32_t)(charsetForward[0] << 16);\
                passOffset = charsetReverse[(b4 >> 0) & 0xff]; \
                b4 &= 0xffffff00;\
                passOffset++;\
                b4 |= (uint32_t)(charsetForward[passOffset] << 0);\
                if (passOffset >= charsetLengths[0]) { \
                  b4 &= 0xffffff00;\
                  b4 |= (uint32_t)(charsetForward[0] << 0);\
                  passOffset = charsetReverse[(b4 >> 16) & 0xff]; \
                  b4 &= 0xff00ffff;\
                  passOffset++;\
                  b4 |= (uint32_t)(charsetForward[passOffset] << 16);\
                  if (passOffset >= charsetLengths[0]) { \
                    b4 &= 0xff00ffff;\
                    b4 |= (uint32_t)(charsetForward[0] << 16);\
                    passOffset = charsetReverse[(b5 >> 0) & 0xff]; \
                    b5 &= 0xffffff00;\
                    passOffset++;\
                    b5 |= (uint32_t)(charsetForward[passOffset] << 0);\
                    if (passOffset >= charsetLengths[0]) { \
                      b5 &= 0xffffff00;\
                      b5 |= (uint32_t)(charsetForward[0] << 0);\
                      passOffset = charsetReverse[(b5 >> 16) & 0xff]; \
                      b5 &= 0xff00ffff;\
                      passOffset++;\
                      b5 |= (uint32_t)(charsetForward[passOffset] << 16);\
                      if (passOffset >= charsetLengths[0]) { \
                        b5 &= 0xff00ffff;\
                        b5 |= (uint32_t)(charsetForward[0] << 16);\
} } } } } } } } } } } } } 


#define makeMFNSingleIncrementorsNTLM13(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[(b0 >> 0) & 0xff]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[0] << 0);\
  passOffset = charsetReverse[(b0 >> 16) & 0xff]; \
  b0 &= 0xff00ffff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[passOffset] << 16);\
  if (passOffset >= charsetLengths[0]) { \
    b0 &= 0xff00ffff;\
    b0 |= (uint32_t)(charsetForward[0] << 16);\
    passOffset = charsetReverse[(b1 >> 0) & 0xff]; \
    b1 &= 0xffffff00;\
    passOffset++;\
    b1 |= (uint32_t)(charsetForward[passOffset] << 0);\
    if (passOffset >= charsetLengths[0]) { \
      b1 &= 0xffffff00;\
      b1 |= (uint32_t)(charsetForward[0] << 0);\
      passOffset = charsetReverse[(b1 >> 16) & 0xff]; \
      b1 &= 0xff00ffff;\
      passOffset++;\
      b1 |= (uint32_t)(charsetForward[passOffset] << 16);\
      if (passOffset >= charsetLengths[0]) { \
        b1 &= 0xff00ffff;\
        b1 |= (uint32_t)(charsetForward[0] << 16);\
        passOffset = charsetReverse[(b2 >> 0) & 0xff]; \
        b2 &= 0xffffff00;\
        passOffset++;\
        b2 |= (uint32_t)(charsetForward[passOffset] << 0);\
        if (passOffset >= charsetLengths[0]) { \
          b2 &= 0xffffff00;\
          b2 |= (uint32_t)(charsetForward[0] << 0);\
          passOffset = charsetReverse[(b2 >> 16) & 0xff]; \
          b2 &= 0xff00ffff;\
          passOffset++;\
          b2 |= (uint32_t)(charsetForward[passOffset] << 16);\
          if (passOffset >= charsetLengths[0]) { \
            b2 &= 0xff00ffff;\
            b2 |= (uint32_t)(charsetForward[0] << 16);\
            passOffset = charsetReverse[(b3 >> 0) & 0xff]; \
            b3 &= 0xffffff00;\
            passOffset++;\
            b3 |= (uint32_t)(charsetForward[passOffset] << 0);\
            if (passOffset >= charsetLengths[0]) { \
              b3 &= 0xffffff00;\
              b3 |= (uint32_t)(charsetForward[0] << 0);\
              passOffset = charsetReverse[(b3 >> 16) & 0xff]; \
              b3 &= 0xff00ffff;\
              passOffset++;\
              b3 |= (uint32_t)(charsetForward[passOffset] << 16);\
              if (passOffset >= charsetLengths[0]) { \
                b3 &= 0xff00ffff;\
                b3 |= (uint32_t)(charsetForward[0] << 16);\
                passOffset = charsetReverse[(b4 >> 0) & 0xff]; \
                b4 &= 0xffffff00;\
                passOffset++;\
                b4 |= (uint32_t)(charsetForward[passOffset] << 0);\
                if (passOffset >= charsetLengths[0]) { \
                  b4 &= 0xffffff00;\
                  b4 |= (uint32_t)(charsetForward[0] << 0);\
                  passOffset = charsetReverse[(b4 >> 16) & 0xff]; \
                  b4 &= 0xff00ffff;\
                  passOffset++;\
                  b4 |= (uint32_t)(charsetForward[passOffset] << 16);\
                  if (passOffset >= charsetLengths[0]) { \
                    b4 &= 0xff00ffff;\
                    b4 |= (uint32_t)(charsetForward[0] << 16);\
                    passOffset = charsetReverse[(b5 >> 0) & 0xff]; \
                    b5 &= 0xffffff00;\
                    passOffset++;\
                    b5 |= (uint32_t)(charsetForward[passOffset] << 0);\
                    if (passOffset >= charsetLengths[0]) { \
                      b5 &= 0xffffff00;\
                      b5 |= (uint32_t)(charsetForward[0] << 0);\
                      passOffset = charsetReverse[(b5 >> 16) & 0xff]; \
                      b5 &= 0xff00ffff;\
                      passOffset++;\
                      b5 |= (uint32_t)(charsetForward[passOffset] << 16);\
                      if (passOffset >= charsetLengths[0]) { \
                        b5 &= 0xff00ffff;\
                        b5 |= (uint32_t)(charsetForward[0] << 16);\
                        passOffset = charsetReverse[(b6 >> 0) & 0xff]; \
                        b6 &= 0xffffff00;\
                        passOffset++;\
                        b6 |= (uint32_t)(charsetForward[passOffset] << 0);\
                        if (passOffset >= charsetLengths[0]) { \
                          b6 &= 0xffffff00;\
                          b6 |= (uint32_t)(charsetForward[0] << 0);\
} } } } } } } } } } } } } } 


#define makeMFNSingleIncrementorsNTLM14(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[(b0 >> 0) & 0xff]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[0] << 0);\
  passOffset = charsetReverse[(b0 >> 16) & 0xff]; \
  b0 &= 0xff00ffff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[passOffset] << 16);\
  if (passOffset >= charsetLengths[0]) { \
    b0 &= 0xff00ffff;\
    b0 |= (uint32_t)(charsetForward[0] << 16);\
    passOffset = charsetReverse[(b1 >> 0) & 0xff]; \
    b1 &= 0xffffff00;\
    passOffset++;\
    b1 |= (uint32_t)(charsetForward[passOffset] << 0);\
    if (passOffset >= charsetLengths[0]) { \
      b1 &= 0xffffff00;\
      b1 |= (uint32_t)(charsetForward[0] << 0);\
      passOffset = charsetReverse[(b1 >> 16) & 0xff]; \
      b1 &= 0xff00ffff;\
      passOffset++;\
      b1 |= (uint32_t)(charsetForward[passOffset] << 16);\
      if (passOffset >= charsetLengths[0]) { \
        b1 &= 0xff00ffff;\
        b1 |= (uint32_t)(charsetForward[0] << 16);\
        passOffset = charsetReverse[(b2 >> 0) & 0xff]; \
        b2 &= 0xffffff00;\
        passOffset++;\
        b2 |= (uint32_t)(charsetForward[passOffset] << 0);\
        if (passOffset >= charsetLengths[0]) { \
          b2 &= 0xffffff00;\
          b2 |= (uint32_t)(charsetForward[0] << 0);\
          passOffset = charsetReverse[(b2 >> 16) & 0xff]; \
          b2 &= 0xff00ffff;\
          passOffset++;\
          b2 |= (uint32_t)(charsetForward[passOffset] << 16);\
          if (passOffset >= charsetLengths[0]) { \
            b2 &= 0xff00ffff;\
            b2 |= (uint32_t)(charsetForward[0] << 16);\
            passOffset = charsetReverse[(b3 >> 0) & 0xff]; \
            b3 &= 0xffffff00;\
            passOffset++;\
            b3 |= (uint32_t)(charsetForward[passOffset] << 0);\
            if (passOffset >= charsetLengths[0]) { \
              b3 &= 0xffffff00;\
              b3 |= (uint32_t)(charsetForward[0] << 0);\
              passOffset = charsetReverse[(b3 >> 16) & 0xff]; \
              b3 &= 0xff00ffff;\
              passOffset++;\
              b3 |= (uint32_t)(charsetForward[passOffset] << 16);\
              if (passOffset >= charsetLengths[0]) { \
                b3 &= 0xff00ffff;\
                b3 |= (uint32_t)(charsetForward[0] << 16);\
                passOffset = charsetReverse[(b4 >> 0) & 0xff]; \
                b4 &= 0xffffff00;\
                passOffset++;\
                b4 |= (uint32_t)(charsetForward[passOffset] << 0);\
                if (passOffset >= charsetLengths[0]) { \
                  b4 &= 0xffffff00;\
                  b4 |= (uint32_t)(charsetForward[0] << 0);\
                  passOffset = charsetReverse[(b4 >> 16) & 0xff]; \
                  b4 &= 0xff00ffff;\
                  passOffset++;\
                  b4 |= (uint32_t)(charsetForward[passOffset] << 16);\
                  if (passOffset >= charsetLengths[0]) { \
                    b4 &= 0xff00ffff;\
                    b4 |= (uint32_t)(charsetForward[0] << 16);\
                    passOffset = charsetReverse[(b5 >> 0) & 0xff]; \
                    b5 &= 0xffffff00;\
                    passOffset++;\
                    b5 |= (uint32_t)(charsetForward[passOffset] << 0);\
                    if (passOffset >= charsetLengths[0]) { \
                      b5 &= 0xffffff00;\
                      b5 |= (uint32_t)(charsetForward[0] << 0);\
                      passOffset = charsetReverse[(b5 >> 16) & 0xff]; \
                      b5 &= 0xff00ffff;\
                      passOffset++;\
                      b5 |= (uint32_t)(charsetForward[passOffset] << 16);\
                      if (passOffset >= charsetLengths[0]) { \
                        b5 &= 0xff00ffff;\
                        b5 |= (uint32_t)(charsetForward[0] << 16);\
                        passOffset = charsetReverse[(b6 >> 0) & 0xff]; \
                        b6 &= 0xffffff00;\
                        passOffset++;\
                        b6 |= (uint32_t)(charsetForward[passOffset] << 0);\
                        if (passOffset >= charsetLengths[0]) { \
                          b6 &= 0xffffff00;\
                          b6 |= (uint32_t)(charsetForward[0] << 0);\
                          passOffset = charsetReverse[(b6 >> 16) & 0xff]; \
                          b6 &= 0xff00ffff;\
                          passOffset++;\
                          b6 |= (uint32_t)(charsetForward[passOffset] << 16);\
                          if (passOffset >= charsetLengths[0]) { \
                            b6 &= 0xff00ffff;\
                            b6 |= (uint32_t)(charsetForward[0] << 16);\
} } } } } } } } } } } } } } } 


#define makeMFNSingleIncrementorsNTLM15(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[(b0 >> 0) & 0xff]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[0] << 0);\
  passOffset = charsetReverse[(b0 >> 16) & 0xff]; \
  b0 &= 0xff00ffff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[passOffset] << 16);\
  if (passOffset >= charsetLengths[0]) { \
    b0 &= 0xff00ffff;\
    b0 |= (uint32_t)(charsetForward[0] << 16);\
    passOffset = charsetReverse[(b1 >> 0) & 0xff]; \
    b1 &= 0xffffff00;\
    passOffset++;\
    b1 |= (uint32_t)(charsetForward[passOffset] << 0);\
    if (passOffset >= charsetLengths[0]) { \
      b1 &= 0xffffff00;\
      b1 |= (uint32_t)(charsetForward[0] << 0);\
      passOffset = charsetReverse[(b1 >> 16) & 0xff]; \
      b1 &= 0xff00ffff;\
      passOffset++;\
      b1 |= (uint32_t)(charsetForward[passOffset] << 16);\
      if (passOffset >= charsetLengths[0]) { \
        b1 &= 0xff00ffff;\
        b1 |= (uint32_t)(charsetForward[0] << 16);\
        passOffset = charsetReverse[(b2 >> 0) & 0xff]; \
        b2 &= 0xffffff00;\
        passOffset++;\
        b2 |= (uint32_t)(charsetForward[passOffset] << 0);\
        if (passOffset >= charsetLengths[0]) { \
          b2 &= 0xffffff00;\
          b2 |= (uint32_t)(charsetForward[0] << 0);\
          passOffset = charsetReverse[(b2 >> 16) & 0xff]; \
          b2 &= 0xff00ffff;\
          passOffset++;\
          b2 |= (uint32_t)(charsetForward[passOffset] << 16);\
          if (passOffset >= charsetLengths[0]) { \
            b2 &= 0xff00ffff;\
            b2 |= (uint32_t)(charsetForward[0] << 16);\
            passOffset = charsetReverse[(b3 >> 0) & 0xff]; \
            b3 &= 0xffffff00;\
            passOffset++;\
            b3 |= (uint32_t)(charsetForward[passOffset] << 0);\
            if (passOffset >= charsetLengths[0]) { \
              b3 &= 0xffffff00;\
              b3 |= (uint32_t)(charsetForward[0] << 0);\
              passOffset = charsetReverse[(b3 >> 16) & 0xff]; \
              b3 &= 0xff00ffff;\
              passOffset++;\
              b3 |= (uint32_t)(charsetForward[passOffset] << 16);\
              if (passOffset >= charsetLengths[0]) { \
                b3 &= 0xff00ffff;\
                b3 |= (uint32_t)(charsetForward[0] << 16);\
                passOffset = charsetReverse[(b4 >> 0) & 0xff]; \
                b4 &= 0xffffff00;\
                passOffset++;\
                b4 |= (uint32_t)(charsetForward[passOffset] << 0);\
                if (passOffset >= charsetLengths[0]) { \
                  b4 &= 0xffffff00;\
                  b4 |= (uint32_t)(charsetForward[0] << 0);\
                  passOffset = charsetReverse[(b4 >> 16) & 0xff]; \
                  b4 &= 0xff00ffff;\
                  passOffset++;\
                  b4 |= (uint32_t)(charsetForward[passOffset] << 16);\
                  if (passOffset >= charsetLengths[0]) { \
                    b4 &= 0xff00ffff;\
                    b4 |= (uint32_t)(charsetForward[0] << 16);\
                    passOffset = charsetReverse[(b5 >> 0) & 0xff]; \
                    b5 &= 0xffffff00;\
                    passOffset++;\
                    b5 |= (uint32_t)(charsetForward[passOffset] << 0);\
                    if (passOffset >= charsetLengths[0]) { \
                      b5 &= 0xffffff00;\
                      b5 |= (uint32_t)(charsetForward[0] << 0);\
                      passOffset = charsetReverse[(b5 >> 16) & 0xff]; \
                      b5 &= 0xff00ffff;\
                      passOffset++;\
                      b5 |= (uint32_t)(charsetForward[passOffset] << 16);\
                      if (passOffset >= charsetLengths[0]) { \
                        b5 &= 0xff00ffff;\
                        b5 |= (uint32_t)(charsetForward[0] << 16);\
                        passOffset = charsetReverse[(b6 >> 0) & 0xff]; \
                        b6 &= 0xffffff00;\
                        passOffset++;\
                        b6 |= (uint32_t)(charsetForward[passOffset] << 0);\
                        if (passOffset >= charsetLengths[0]) { \
                          b6 &= 0xffffff00;\
                          b6 |= (uint32_t)(charsetForward[0] << 0);\
                          passOffset = charsetReverse[(b6 >> 16) & 0xff]; \
                          b6 &= 0xff00ffff;\
                          passOffset++;\
                          b6 |= (uint32_t)(charsetForward[passOffset] << 16);\
                          if (passOffset >= charsetLengths[0]) { \
                            b6 &= 0xff00ffff;\
                            b6 |= (uint32_t)(charsetForward[0] << 16);\
                            passOffset = charsetReverse[(b7 >> 0) & 0xff]; \
                            b7 &= 0xffffff00;\
                            passOffset++;\
                            b7 |= (uint32_t)(charsetForward[passOffset] << 0);\
                            if (passOffset >= charsetLengths[0]) { \
                              b7 &= 0xffffff00;\
                              b7 |= (uint32_t)(charsetForward[0] << 0);\
} } } } } } } } } } } } } } } } 


#define makeMFNSingleIncrementorsNTLM16(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[(b0 >> 0) & 0xff]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[0] << 0);\
  passOffset = charsetReverse[(b0 >> 16) & 0xff]; \
  b0 &= 0xff00ffff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[passOffset] << 16);\
  if (passOffset >= charsetLengths[0]) { \
    b0 &= 0xff00ffff;\
    b0 |= (uint32_t)(charsetForward[0] << 16);\
    passOffset = charsetReverse[(b1 >> 0) & 0xff]; \
    b1 &= 0xffffff00;\
    passOffset++;\
    b1 |= (uint32_t)(charsetForward[passOffset] << 0);\
    if (passOffset >= charsetLengths[0]) { \
      b1 &= 0xffffff00;\
      b1 |= (uint32_t)(charsetForward[0] << 0);\
      passOffset = charsetReverse[(b1 >> 16) & 0xff]; \
      b1 &= 0xff00ffff;\
      passOffset++;\
      b1 |= (uint32_t)(charsetForward[passOffset] << 16);\
      if (passOffset >= charsetLengths[0]) { \
        b1 &= 0xff00ffff;\
        b1 |= (uint32_t)(charsetForward[0] << 16);\
        passOffset = charsetReverse[(b2 >> 0) & 0xff]; \
        b2 &= 0xffffff00;\
        passOffset++;\
        b2 |= (uint32_t)(charsetForward[passOffset] << 0);\
        if (passOffset >= charsetLengths[0]) { \
          b2 &= 0xffffff00;\
          b2 |= (uint32_t)(charsetForward[0] << 0);\
          passOffset = charsetReverse[(b2 >> 16) & 0xff]; \
          b2 &= 0xff00ffff;\
          passOffset++;\
          b2 |= (uint32_t)(charsetForward[passOffset] << 16);\
          if (passOffset >= charsetLengths[0]) { \
            b2 &= 0xff00ffff;\
            b2 |= (uint32_t)(charsetForward[0] << 16);\
            passOffset = charsetReverse[(b3 >> 0) & 0xff]; \
            b3 &= 0xffffff00;\
            passOffset++;\
            b3 |= (uint32_t)(charsetForward[passOffset] << 0);\
            if (passOffset >= charsetLengths[0]) { \
              b3 &= 0xffffff00;\
              b3 |= (uint32_t)(charsetForward[0] << 0);\
              passOffset = charsetReverse[(b3 >> 16) & 0xff]; \
              b3 &= 0xff00ffff;\
              passOffset++;\
              b3 |= (uint32_t)(charsetForward[passOffset] << 16);\
              if (passOffset >= charsetLengths[0]) { \
                b3 &= 0xff00ffff;\
                b3 |= (uint32_t)(charsetForward[0] << 16);\
                passOffset = charsetReverse[(b4 >> 0) & 0xff]; \
                b4 &= 0xffffff00;\
                passOffset++;\
                b4 |= (uint32_t)(charsetForward[passOffset] << 0);\
                if (passOffset >= charsetLengths[0]) { \
                  b4 &= 0xffffff00;\
                  b4 |= (uint32_t)(charsetForward[0] << 0);\
                  passOffset = charsetReverse[(b4 >> 16) & 0xff]; \
                  b4 &= 0xff00ffff;\
                  passOffset++;\
                  b4 |= (uint32_t)(charsetForward[passOffset] << 16);\
                  if (passOffset >= charsetLengths[0]) { \
                    b4 &= 0xff00ffff;\
                    b4 |= (uint32_t)(charsetForward[0] << 16);\
                    passOffset = charsetReverse[(b5 >> 0) & 0xff]; \
                    b5 &= 0xffffff00;\
                    passOffset++;\
                    b5 |= (uint32_t)(charsetForward[passOffset] << 0);\
                    if (passOffset >= charsetLengths[0]) { \
                      b5 &= 0xffffff00;\
                      b5 |= (uint32_t)(charsetForward[0] << 0);\
                      passOffset = charsetReverse[(b5 >> 16) & 0xff]; \
                      b5 &= 0xff00ffff;\
                      passOffset++;\
                      b5 |= (uint32_t)(charsetForward[passOffset] << 16);\
                      if (passOffset >= charsetLengths[0]) { \
                        b5 &= 0xff00ffff;\
                        b5 |= (uint32_t)(charsetForward[0] << 16);\
                        passOffset = charsetReverse[(b6 >> 0) & 0xff]; \
                        b6 &= 0xffffff00;\
                        passOffset++;\
                        b6 |= (uint32_t)(charsetForward[passOffset] << 0);\
                        if (passOffset >= charsetLengths[0]) { \
                          b6 &= 0xffffff00;\
                          b6 |= (uint32_t)(charsetForward[0] << 0);\
                          passOffset = charsetReverse[(b6 >> 16) & 0xff]; \
                          b6 &= 0xff00ffff;\
                          passOffset++;\
                          b6 |= (uint32_t)(charsetForward[passOffset] << 16);\
                          if (passOffset >= charsetLengths[0]) { \
                            b6 &= 0xff00ffff;\
                            b6 |= (uint32_t)(charsetForward[0] << 16);\
                            passOffset = charsetReverse[(b7 >> 0) & 0xff]; \
                            b7 &= 0xffffff00;\
                            passOffset++;\
                            b7 |= (uint32_t)(charsetForward[passOffset] << 0);\
                            if (passOffset >= charsetLengths[0]) { \
                              b7 &= 0xffffff00;\
                              b7 |= (uint32_t)(charsetForward[0] << 0);\
                              passOffset = charsetReverse[(b7 >> 16) & 0xff]; \
                              b7 &= 0xff00ffff;\
                              passOffset++;\
                              b7 |= (uint32_t)(charsetForward[passOffset] << 16);\
                              if (passOffset >= charsetLengths[0]) { \
                                b7 &= 0xff00ffff;\
                                b7 |= (uint32_t)(charsetForward[0] << 16);\
} } } } } } } } } } } } } } } } } 


#define makeMFNMultipleIncrementorsNTLM1(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[((128 * 0) + (b0 >> 0) & 0xff)]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[(128 * 0) + passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[(128 * 0)] << 0);\
} } 


#define makeMFNMultipleIncrementorsNTLM2(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[((128 * 0) + (b0 >> 0) & 0xff)]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[(128 * 0) + passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[(128 * 0)] << 0);\
  passOffset = charsetReverse[((128 * 1) + (b0 >> 8) & 0xff)]; \
  b0 &= 0xffff00ff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[(128 * 1) + passOffset] << 8);\
  if (passOffset >= charsetLengths[1]) { \
    b0 &= 0xffff00ff;\
    b0 |= (uint32_t)(charsetForward[(128 * 1)] << 8);\
} } } 


#define makeMFNMultipleIncrementorsNTLM3(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[((128 * 0) + (b0 >> 0) & 0xff)]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[(128 * 0) + passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[(128 * 0)] << 0);\
  passOffset = charsetReverse[((128 * 1) + (b0 >> 8) & 0xff)]; \
  b0 &= 0xffff00ff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[(128 * 1) + passOffset] << 8);\
  if (passOffset >= charsetLengths[1]) { \
    b0 &= 0xffff00ff;\
    b0 |= (uint32_t)(charsetForward[(128 * 1)] << 8);\
    passOffset = charsetReverse[((128 * 2) + (b0 >> 16) & 0xff)]; \
    b0 &= 0xff00ffff;\
    passOffset++;\
    b0 |= (uint32_t)(charsetForward[(128 * 2) + passOffset] << 16);\
    if (passOffset >= charsetLengths[2]) { \
      b0 &= 0xff00ffff;\
      b0 |= (uint32_t)(charsetForward[(128 * 2)] << 16);\
} } } } 


#define makeMFNMultipleIncrementorsNTLM4(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[((128 * 0) + (b0 >> 0) & 0xff)]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[(128 * 0) + passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[(128 * 0)] << 0);\
  passOffset = charsetReverse[((128 * 1) + (b0 >> 8) & 0xff)]; \
  b0 &= 0xffff00ff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[(128 * 1) + passOffset] << 8);\
  if (passOffset >= charsetLengths[1]) { \
    b0 &= 0xffff00ff;\
    b0 |= (uint32_t)(charsetForward[(128 * 1)] << 8);\
    passOffset = charsetReverse[((128 * 2) + (b0 >> 16) & 0xff)]; \
    b0 &= 0xff00ffff;\
    passOffset++;\
    b0 |= (uint32_t)(charsetForward[(128 * 2) + passOffset] << 16);\
    if (passOffset >= charsetLengths[2]) { \
      b0 &= 0xff00ffff;\
      b0 |= (uint32_t)(charsetForward[(128 * 2)] << 16);\
      passOffset = charsetReverse[((128 * 3) + (b0 >> 24) & 0xff)]; \
      b0 &= 0x00ffffff;\
      passOffset++;\
      b0 |= (uint32_t)(charsetForward[(128 * 3) + passOffset] << 24);\
      if (passOffset >= charsetLengths[3]) { \
        b0 &= 0x00ffffff;\
        b0 |= (uint32_t)(charsetForward[(128 * 3)] << 24);\
} } } } } 


#define makeMFNMultipleIncrementorsNTLM5(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[((128 * 0) + (b0 >> 0) & 0xff)]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[(128 * 0) + passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[(128 * 0)] << 0);\
  passOffset = charsetReverse[((128 * 1) + (b0 >> 8) & 0xff)]; \
  b0 &= 0xffff00ff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[(128 * 1) + passOffset] << 8);\
  if (passOffset >= charsetLengths[1]) { \
    b0 &= 0xffff00ff;\
    b0 |= (uint32_t)(charsetForward[(128 * 1)] << 8);\
    passOffset = charsetReverse[((128 * 2) + (b0 >> 16) & 0xff)]; \
    b0 &= 0xff00ffff;\
    passOffset++;\
    b0 |= (uint32_t)(charsetForward[(128 * 2) + passOffset] << 16);\
    if (passOffset >= charsetLengths[2]) { \
      b0 &= 0xff00ffff;\
      b0 |= (uint32_t)(charsetForward[(128 * 2)] << 16);\
      passOffset = charsetReverse[((128 * 3) + (b0 >> 24) & 0xff)]; \
      b0 &= 0x00ffffff;\
      passOffset++;\
      b0 |= (uint32_t)(charsetForward[(128 * 3) + passOffset] << 24);\
      if (passOffset >= charsetLengths[3]) { \
        b0 &= 0x00ffffff;\
        b0 |= (uint32_t)(charsetForward[(128 * 3)] << 24);\
        passOffset = charsetReverse[((128 * 4) + (b1 >> 0) & 0xff)]; \
        b1 &= 0xffffff00;\
        passOffset++;\
        b1 |= (uint32_t)(charsetForward[(128 * 4) + passOffset] << 0);\
        if (passOffset >= charsetLengths[4]) { \
          b1 &= 0xffffff00;\
          b1 |= (uint32_t)(charsetForward[(128 * 4)] << 0);\
} } } } } } 


#define makeMFNMultipleIncrementorsNTLM6(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[((128 * 0) + (b0 >> 0) & 0xff)]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[(128 * 0) + passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[(128 * 0)] << 0);\
  passOffset = charsetReverse[((128 * 1) + (b0 >> 8) & 0xff)]; \
  b0 &= 0xffff00ff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[(128 * 1) + passOffset] << 8);\
  if (passOffset >= charsetLengths[1]) { \
    b0 &= 0xffff00ff;\
    b0 |= (uint32_t)(charsetForward[(128 * 1)] << 8);\
    passOffset = charsetReverse[((128 * 2) + (b0 >> 16) & 0xff)]; \
    b0 &= 0xff00ffff;\
    passOffset++;\
    b0 |= (uint32_t)(charsetForward[(128 * 2) + passOffset] << 16);\
    if (passOffset >= charsetLengths[2]) { \
      b0 &= 0xff00ffff;\
      b0 |= (uint32_t)(charsetForward[(128 * 2)] << 16);\
      passOffset = charsetReverse[((128 * 3) + (b0 >> 24) & 0xff)]; \
      b0 &= 0x00ffffff;\
      passOffset++;\
      b0 |= (uint32_t)(charsetForward[(128 * 3) + passOffset] << 24);\
      if (passOffset >= charsetLengths[3]) { \
        b0 &= 0x00ffffff;\
        b0 |= (uint32_t)(charsetForward[(128 * 3)] << 24);\
        passOffset = charsetReverse[((128 * 4) + (b1 >> 0) & 0xff)]; \
        b1 &= 0xffffff00;\
        passOffset++;\
        b1 |= (uint32_t)(charsetForward[(128 * 4) + passOffset] << 0);\
        if (passOffset >= charsetLengths[4]) { \
          b1 &= 0xffffff00;\
          b1 |= (uint32_t)(charsetForward[(128 * 4)] << 0);\
          passOffset = charsetReverse[((128 * 5) + (b1 >> 8) & 0xff)]; \
          b1 &= 0xffff00ff;\
          passOffset++;\
          b1 |= (uint32_t)(charsetForward[(128 * 5) + passOffset] << 8);\
          if (passOffset >= charsetLengths[5]) { \
            b1 &= 0xffff00ff;\
            b1 |= (uint32_t)(charsetForward[(128 * 5)] << 8);\
} } } } } } } 


#define makeMFNMultipleIncrementorsNTLM7(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[((128 * 0) + (b0 >> 0) & 0xff)]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[(128 * 0) + passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[(128 * 0)] << 0);\
  passOffset = charsetReverse[((128 * 1) + (b0 >> 8) & 0xff)]; \
  b0 &= 0xffff00ff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[(128 * 1) + passOffset] << 8);\
  if (passOffset >= charsetLengths[1]) { \
    b0 &= 0xffff00ff;\
    b0 |= (uint32_t)(charsetForward[(128 * 1)] << 8);\
    passOffset = charsetReverse[((128 * 2) + (b0 >> 16) & 0xff)]; \
    b0 &= 0xff00ffff;\
    passOffset++;\
    b0 |= (uint32_t)(charsetForward[(128 * 2) + passOffset] << 16);\
    if (passOffset >= charsetLengths[2]) { \
      b0 &= 0xff00ffff;\
      b0 |= (uint32_t)(charsetForward[(128 * 2)] << 16);\
      passOffset = charsetReverse[((128 * 3) + (b0 >> 24) & 0xff)]; \
      b0 &= 0x00ffffff;\
      passOffset++;\
      b0 |= (uint32_t)(charsetForward[(128 * 3) + passOffset] << 24);\
      if (passOffset >= charsetLengths[3]) { \
        b0 &= 0x00ffffff;\
        b0 |= (uint32_t)(charsetForward[(128 * 3)] << 24);\
        passOffset = charsetReverse[((128 * 4) + (b1 >> 0) & 0xff)]; \
        b1 &= 0xffffff00;\
        passOffset++;\
        b1 |= (uint32_t)(charsetForward[(128 * 4) + passOffset] << 0);\
        if (passOffset >= charsetLengths[4]) { \
          b1 &= 0xffffff00;\
          b1 |= (uint32_t)(charsetForward[(128 * 4)] << 0);\
          passOffset = charsetReverse[((128 * 5) + (b1 >> 8) & 0xff)]; \
          b1 &= 0xffff00ff;\
          passOffset++;\
          b1 |= (uint32_t)(charsetForward[(128 * 5) + passOffset] << 8);\
          if (passOffset >= charsetLengths[5]) { \
            b1 &= 0xffff00ff;\
            b1 |= (uint32_t)(charsetForward[(128 * 5)] << 8);\
            passOffset = charsetReverse[((128 * 6) + (b1 >> 16) & 0xff)]; \
            b1 &= 0xff00ffff;\
            passOffset++;\
            b1 |= (uint32_t)(charsetForward[(128 * 6) + passOffset] << 16);\
            if (passOffset >= charsetLengths[6]) { \
              b1 &= 0xff00ffff;\
              b1 |= (uint32_t)(charsetForward[(128 * 6)] << 16);\
} } } } } } } } 


#define makeMFNMultipleIncrementorsNTLM8(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[((128 * 0) + (b0 >> 0) & 0xff)]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[(128 * 0) + passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[(128 * 0)] << 0);\
  passOffset = charsetReverse[((128 * 1) + (b0 >> 8) & 0xff)]; \
  b0 &= 0xffff00ff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[(128 * 1) + passOffset] << 8);\
  if (passOffset >= charsetLengths[1]) { \
    b0 &= 0xffff00ff;\
    b0 |= (uint32_t)(charsetForward[(128 * 1)] << 8);\
    passOffset = charsetReverse[((128 * 2) + (b0 >> 16) & 0xff)]; \
    b0 &= 0xff00ffff;\
    passOffset++;\
    b0 |= (uint32_t)(charsetForward[(128 * 2) + passOffset] << 16);\
    if (passOffset >= charsetLengths[2]) { \
      b0 &= 0xff00ffff;\
      b0 |= (uint32_t)(charsetForward[(128 * 2)] << 16);\
      passOffset = charsetReverse[((128 * 3) + (b0 >> 24) & 0xff)]; \
      b0 &= 0x00ffffff;\
      passOffset++;\
      b0 |= (uint32_t)(charsetForward[(128 * 3) + passOffset] << 24);\
      if (passOffset >= charsetLengths[3]) { \
        b0 &= 0x00ffffff;\
        b0 |= (uint32_t)(charsetForward[(128 * 3)] << 24);\
        passOffset = charsetReverse[((128 * 4) + (b1 >> 0) & 0xff)]; \
        b1 &= 0xffffff00;\
        passOffset++;\
        b1 |= (uint32_t)(charsetForward[(128 * 4) + passOffset] << 0);\
        if (passOffset >= charsetLengths[4]) { \
          b1 &= 0xffffff00;\
          b1 |= (uint32_t)(charsetForward[(128 * 4)] << 0);\
          passOffset = charsetReverse[((128 * 5) + (b1 >> 8) & 0xff)]; \
          b1 &= 0xffff00ff;\
          passOffset++;\
          b1 |= (uint32_t)(charsetForward[(128 * 5) + passOffset] << 8);\
          if (passOffset >= charsetLengths[5]) { \
            b1 &= 0xffff00ff;\
            b1 |= (uint32_t)(charsetForward[(128 * 5)] << 8);\
            passOffset = charsetReverse[((128 * 6) + (b1 >> 16) & 0xff)]; \
            b1 &= 0xff00ffff;\
            passOffset++;\
            b1 |= (uint32_t)(charsetForward[(128 * 6) + passOffset] << 16);\
            if (passOffset >= charsetLengths[6]) { \
              b1 &= 0xff00ffff;\
              b1 |= (uint32_t)(charsetForward[(128 * 6)] << 16);\
              passOffset = charsetReverse[((128 * 7) + (b1 >> 24) & 0xff)]; \
              b1 &= 0x00ffffff;\
              passOffset++;\
              b1 |= (uint32_t)(charsetForward[(128 * 7) + passOffset] << 24);\
              if (passOffset >= charsetLengths[7]) { \
                b1 &= 0x00ffffff;\
                b1 |= (uint32_t)(charsetForward[(128 * 7)] << 24);\
} } } } } } } } } 


#define makeMFNMultipleIncrementorsNTLM9(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[((128 * 0) + (b0 >> 0) & 0xff)]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[(128 * 0) + passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[(128 * 0)] << 0);\
  passOffset = charsetReverse[((128 * 1) + (b0 >> 8) & 0xff)]; \
  b0 &= 0xffff00ff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[(128 * 1) + passOffset] << 8);\
  if (passOffset >= charsetLengths[1]) { \
    b0 &= 0xffff00ff;\
    b0 |= (uint32_t)(charsetForward[(128 * 1)] << 8);\
    passOffset = charsetReverse[((128 * 2) + (b0 >> 16) & 0xff)]; \
    b0 &= 0xff00ffff;\
    passOffset++;\
    b0 |= (uint32_t)(charsetForward[(128 * 2) + passOffset] << 16);\
    if (passOffset >= charsetLengths[2]) { \
      b0 &= 0xff00ffff;\
      b0 |= (uint32_t)(charsetForward[(128 * 2)] << 16);\
      passOffset = charsetReverse[((128 * 3) + (b0 >> 24) & 0xff)]; \
      b0 &= 0x00ffffff;\
      passOffset++;\
      b0 |= (uint32_t)(charsetForward[(128 * 3) + passOffset] << 24);\
      if (passOffset >= charsetLengths[3]) { \
        b0 &= 0x00ffffff;\
        b0 |= (uint32_t)(charsetForward[(128 * 3)] << 24);\
        passOffset = charsetReverse[((128 * 4) + (b1 >> 0) & 0xff)]; \
        b1 &= 0xffffff00;\
        passOffset++;\
        b1 |= (uint32_t)(charsetForward[(128 * 4) + passOffset] << 0);\
        if (passOffset >= charsetLengths[4]) { \
          b1 &= 0xffffff00;\
          b1 |= (uint32_t)(charsetForward[(128 * 4)] << 0);\
          passOffset = charsetReverse[((128 * 5) + (b1 >> 8) & 0xff)]; \
          b1 &= 0xffff00ff;\
          passOffset++;\
          b1 |= (uint32_t)(charsetForward[(128 * 5) + passOffset] << 8);\
          if (passOffset >= charsetLengths[5]) { \
            b1 &= 0xffff00ff;\
            b1 |= (uint32_t)(charsetForward[(128 * 5)] << 8);\
            passOffset = charsetReverse[((128 * 6) + (b1 >> 16) & 0xff)]; \
            b1 &= 0xff00ffff;\
            passOffset++;\
            b1 |= (uint32_t)(charsetForward[(128 * 6) + passOffset] << 16);\
            if (passOffset >= charsetLengths[6]) { \
              b1 &= 0xff00ffff;\
              b1 |= (uint32_t)(charsetForward[(128 * 6)] << 16);\
              passOffset = charsetReverse[((128 * 7) + (b1 >> 24) & 0xff)]; \
              b1 &= 0x00ffffff;\
              passOffset++;\
              b1 |= (uint32_t)(charsetForward[(128 * 7) + passOffset] << 24);\
              if (passOffset >= charsetLengths[7]) { \
                b1 &= 0x00ffffff;\
                b1 |= (uint32_t)(charsetForward[(128 * 7)] << 24);\
                passOffset = charsetReverse[((128 * 8) + (b2 >> 0) & 0xff)]; \
                b2 &= 0xffffff00;\
                passOffset++;\
                b2 |= (uint32_t)(charsetForward[(128 * 8) + passOffset] << 0);\
                if (passOffset >= charsetLengths[8]) { \
                  b2 &= 0xffffff00;\
                  b2 |= (uint32_t)(charsetForward[(128 * 8)] << 0);\
} } } } } } } } } } 


#define makeMFNMultipleIncrementorsNTLM10(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[((128 * 0) + (b0 >> 0) & 0xff)]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[(128 * 0) + passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[(128 * 0)] << 0);\
  passOffset = charsetReverse[((128 * 1) + (b0 >> 8) & 0xff)]; \
  b0 &= 0xffff00ff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[(128 * 1) + passOffset] << 8);\
  if (passOffset >= charsetLengths[1]) { \
    b0 &= 0xffff00ff;\
    b0 |= (uint32_t)(charsetForward[(128 * 1)] << 8);\
    passOffset = charsetReverse[((128 * 2) + (b0 >> 16) & 0xff)]; \
    b0 &= 0xff00ffff;\
    passOffset++;\
    b0 |= (uint32_t)(charsetForward[(128 * 2) + passOffset] << 16);\
    if (passOffset >= charsetLengths[2]) { \
      b0 &= 0xff00ffff;\
      b0 |= (uint32_t)(charsetForward[(128 * 2)] << 16);\
      passOffset = charsetReverse[((128 * 3) + (b0 >> 24) & 0xff)]; \
      b0 &= 0x00ffffff;\
      passOffset++;\
      b0 |= (uint32_t)(charsetForward[(128 * 3) + passOffset] << 24);\
      if (passOffset >= charsetLengths[3]) { \
        b0 &= 0x00ffffff;\
        b0 |= (uint32_t)(charsetForward[(128 * 3)] << 24);\
        passOffset = charsetReverse[((128 * 4) + (b1 >> 0) & 0xff)]; \
        b1 &= 0xffffff00;\
        passOffset++;\
        b1 |= (uint32_t)(charsetForward[(128 * 4) + passOffset] << 0);\
        if (passOffset >= charsetLengths[4]) { \
          b1 &= 0xffffff00;\
          b1 |= (uint32_t)(charsetForward[(128 * 4)] << 0);\
          passOffset = charsetReverse[((128 * 5) + (b1 >> 8) & 0xff)]; \
          b1 &= 0xffff00ff;\
          passOffset++;\
          b1 |= (uint32_t)(charsetForward[(128 * 5) + passOffset] << 8);\
          if (passOffset >= charsetLengths[5]) { \
            b1 &= 0xffff00ff;\
            b1 |= (uint32_t)(charsetForward[(128 * 5)] << 8);\
            passOffset = charsetReverse[((128 * 6) + (b1 >> 16) & 0xff)]; \
            b1 &= 0xff00ffff;\
            passOffset++;\
            b1 |= (uint32_t)(charsetForward[(128 * 6) + passOffset] << 16);\
            if (passOffset >= charsetLengths[6]) { \
              b1 &= 0xff00ffff;\
              b1 |= (uint32_t)(charsetForward[(128 * 6)] << 16);\
              passOffset = charsetReverse[((128 * 7) + (b1 >> 24) & 0xff)]; \
              b1 &= 0x00ffffff;\
              passOffset++;\
              b1 |= (uint32_t)(charsetForward[(128 * 7) + passOffset] << 24);\
              if (passOffset >= charsetLengths[7]) { \
                b1 &= 0x00ffffff;\
                b1 |= (uint32_t)(charsetForward[(128 * 7)] << 24);\
                passOffset = charsetReverse[((128 * 8) + (b2 >> 0) & 0xff)]; \
                b2 &= 0xffffff00;\
                passOffset++;\
                b2 |= (uint32_t)(charsetForward[(128 * 8) + passOffset] << 0);\
                if (passOffset >= charsetLengths[8]) { \
                  b2 &= 0xffffff00;\
                  b2 |= (uint32_t)(charsetForward[(128 * 8)] << 0);\
                  passOffset = charsetReverse[((128 * 9) + (b2 >> 8) & 0xff)]; \
                  b2 &= 0xffff00ff;\
                  passOffset++;\
                  b2 |= (uint32_t)(charsetForward[(128 * 9) + passOffset] << 8);\
                  if (passOffset >= charsetLengths[9]) { \
                    b2 &= 0xffff00ff;\
                    b2 |= (uint32_t)(charsetForward[(128 * 9)] << 8);\
} } } } } } } } } } } 


#define makeMFNMultipleIncrementorsNTLM11(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[((128 * 0) + (b0 >> 0) & 0xff)]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[(128 * 0) + passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[(128 * 0)] << 0);\
  passOffset = charsetReverse[((128 * 1) + (b0 >> 8) & 0xff)]; \
  b0 &= 0xffff00ff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[(128 * 1) + passOffset] << 8);\
  if (passOffset >= charsetLengths[1]) { \
    b0 &= 0xffff00ff;\
    b0 |= (uint32_t)(charsetForward[(128 * 1)] << 8);\
    passOffset = charsetReverse[((128 * 2) + (b0 >> 16) & 0xff)]; \
    b0 &= 0xff00ffff;\
    passOffset++;\
    b0 |= (uint32_t)(charsetForward[(128 * 2) + passOffset] << 16);\
    if (passOffset >= charsetLengths[2]) { \
      b0 &= 0xff00ffff;\
      b0 |= (uint32_t)(charsetForward[(128 * 2)] << 16);\
      passOffset = charsetReverse[((128 * 3) + (b0 >> 24) & 0xff)]; \
      b0 &= 0x00ffffff;\
      passOffset++;\
      b0 |= (uint32_t)(charsetForward[(128 * 3) + passOffset] << 24);\
      if (passOffset >= charsetLengths[3]) { \
        b0 &= 0x00ffffff;\
        b0 |= (uint32_t)(charsetForward[(128 * 3)] << 24);\
        passOffset = charsetReverse[((128 * 4) + (b1 >> 0) & 0xff)]; \
        b1 &= 0xffffff00;\
        passOffset++;\
        b1 |= (uint32_t)(charsetForward[(128 * 4) + passOffset] << 0);\
        if (passOffset >= charsetLengths[4]) { \
          b1 &= 0xffffff00;\
          b1 |= (uint32_t)(charsetForward[(128 * 4)] << 0);\
          passOffset = charsetReverse[((128 * 5) + (b1 >> 8) & 0xff)]; \
          b1 &= 0xffff00ff;\
          passOffset++;\
          b1 |= (uint32_t)(charsetForward[(128 * 5) + passOffset] << 8);\
          if (passOffset >= charsetLengths[5]) { \
            b1 &= 0xffff00ff;\
            b1 |= (uint32_t)(charsetForward[(128 * 5)] << 8);\
            passOffset = charsetReverse[((128 * 6) + (b1 >> 16) & 0xff)]; \
            b1 &= 0xff00ffff;\
            passOffset++;\
            b1 |= (uint32_t)(charsetForward[(128 * 6) + passOffset] << 16);\
            if (passOffset >= charsetLengths[6]) { \
              b1 &= 0xff00ffff;\
              b1 |= (uint32_t)(charsetForward[(128 * 6)] << 16);\
              passOffset = charsetReverse[((128 * 7) + (b1 >> 24) & 0xff)]; \
              b1 &= 0x00ffffff;\
              passOffset++;\
              b1 |= (uint32_t)(charsetForward[(128 * 7) + passOffset] << 24);\
              if (passOffset >= charsetLengths[7]) { \
                b1 &= 0x00ffffff;\
                b1 |= (uint32_t)(charsetForward[(128 * 7)] << 24);\
                passOffset = charsetReverse[((128 * 8) + (b2 >> 0) & 0xff)]; \
                b2 &= 0xffffff00;\
                passOffset++;\
                b2 |= (uint32_t)(charsetForward[(128 * 8) + passOffset] << 0);\
                if (passOffset >= charsetLengths[8]) { \
                  b2 &= 0xffffff00;\
                  b2 |= (uint32_t)(charsetForward[(128 * 8)] << 0);\
                  passOffset = charsetReverse[((128 * 9) + (b2 >> 8) & 0xff)]; \
                  b2 &= 0xffff00ff;\
                  passOffset++;\
                  b2 |= (uint32_t)(charsetForward[(128 * 9) + passOffset] << 8);\
                  if (passOffset >= charsetLengths[9]) { \
                    b2 &= 0xffff00ff;\
                    b2 |= (uint32_t)(charsetForward[(128 * 9)] << 8);\
                    passOffset = charsetReverse[((128 * 10) + (b2 >> 16) & 0xff)]; \
                    b2 &= 0xff00ffff;\
                    passOffset++;\
                    b2 |= (uint32_t)(charsetForward[(128 * 10) + passOffset] << 16);\
                    if (passOffset >= charsetLengths[10]) { \
                      b2 &= 0xff00ffff;\
                      b2 |= (uint32_t)(charsetForward[(128 * 10)] << 16);\
} } } } } } } } } } } } 


#define makeMFNMultipleIncrementorsNTLM12(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[((128 * 0) + (b0 >> 0) & 0xff)]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[(128 * 0) + passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[(128 * 0)] << 0);\
  passOffset = charsetReverse[((128 * 1) + (b0 >> 8) & 0xff)]; \
  b0 &= 0xffff00ff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[(128 * 1) + passOffset] << 8);\
  if (passOffset >= charsetLengths[1]) { \
    b0 &= 0xffff00ff;\
    b0 |= (uint32_t)(charsetForward[(128 * 1)] << 8);\
    passOffset = charsetReverse[((128 * 2) + (b0 >> 16) & 0xff)]; \
    b0 &= 0xff00ffff;\
    passOffset++;\
    b0 |= (uint32_t)(charsetForward[(128 * 2) + passOffset] << 16);\
    if (passOffset >= charsetLengths[2]) { \
      b0 &= 0xff00ffff;\
      b0 |= (uint32_t)(charsetForward[(128 * 2)] << 16);\
      passOffset = charsetReverse[((128 * 3) + (b0 >> 24) & 0xff)]; \
      b0 &= 0x00ffffff;\
      passOffset++;\
      b0 |= (uint32_t)(charsetForward[(128 * 3) + passOffset] << 24);\
      if (passOffset >= charsetLengths[3]) { \
        b0 &= 0x00ffffff;\
        b0 |= (uint32_t)(charsetForward[(128 * 3)] << 24);\
        passOffset = charsetReverse[((128 * 4) + (b1 >> 0) & 0xff)]; \
        b1 &= 0xffffff00;\
        passOffset++;\
        b1 |= (uint32_t)(charsetForward[(128 * 4) + passOffset] << 0);\
        if (passOffset >= charsetLengths[4]) { \
          b1 &= 0xffffff00;\
          b1 |= (uint32_t)(charsetForward[(128 * 4)] << 0);\
          passOffset = charsetReverse[((128 * 5) + (b1 >> 8) & 0xff)]; \
          b1 &= 0xffff00ff;\
          passOffset++;\
          b1 |= (uint32_t)(charsetForward[(128 * 5) + passOffset] << 8);\
          if (passOffset >= charsetLengths[5]) { \
            b1 &= 0xffff00ff;\
            b1 |= (uint32_t)(charsetForward[(128 * 5)] << 8);\
            passOffset = charsetReverse[((128 * 6) + (b1 >> 16) & 0xff)]; \
            b1 &= 0xff00ffff;\
            passOffset++;\
            b1 |= (uint32_t)(charsetForward[(128 * 6) + passOffset] << 16);\
            if (passOffset >= charsetLengths[6]) { \
              b1 &= 0xff00ffff;\
              b1 |= (uint32_t)(charsetForward[(128 * 6)] << 16);\
              passOffset = charsetReverse[((128 * 7) + (b1 >> 24) & 0xff)]; \
              b1 &= 0x00ffffff;\
              passOffset++;\
              b1 |= (uint32_t)(charsetForward[(128 * 7) + passOffset] << 24);\
              if (passOffset >= charsetLengths[7]) { \
                b1 &= 0x00ffffff;\
                b1 |= (uint32_t)(charsetForward[(128 * 7)] << 24);\
                passOffset = charsetReverse[((128 * 8) + (b2 >> 0) & 0xff)]; \
                b2 &= 0xffffff00;\
                passOffset++;\
                b2 |= (uint32_t)(charsetForward[(128 * 8) + passOffset] << 0);\
                if (passOffset >= charsetLengths[8]) { \
                  b2 &= 0xffffff00;\
                  b2 |= (uint32_t)(charsetForward[(128 * 8)] << 0);\
                  passOffset = charsetReverse[((128 * 9) + (b2 >> 8) & 0xff)]; \
                  b2 &= 0xffff00ff;\
                  passOffset++;\
                  b2 |= (uint32_t)(charsetForward[(128 * 9) + passOffset] << 8);\
                  if (passOffset >= charsetLengths[9]) { \
                    b2 &= 0xffff00ff;\
                    b2 |= (uint32_t)(charsetForward[(128 * 9)] << 8);\
                    passOffset = charsetReverse[((128 * 10) + (b2 >> 16) & 0xff)]; \
                    b2 &= 0xff00ffff;\
                    passOffset++;\
                    b2 |= (uint32_t)(charsetForward[(128 * 10) + passOffset] << 16);\
                    if (passOffset >= charsetLengths[10]) { \
                      b2 &= 0xff00ffff;\
                      b2 |= (uint32_t)(charsetForward[(128 * 10)] << 16);\
                      passOffset = charsetReverse[((128 * 11) + (b2 >> 24) & 0xff)]; \
                      b2 &= 0x00ffffff;\
                      passOffset++;\
                      b2 |= (uint32_t)(charsetForward[(128 * 11) + passOffset] << 24);\
                      if (passOffset >= charsetLengths[11]) { \
                        b2 &= 0x00ffffff;\
                        b2 |= (uint32_t)(charsetForward[(128 * 11)] << 24);\
} } } } } } } } } } } } } 


#define makeMFNMultipleIncrementorsNTLM13(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[((128 * 0) + (b0 >> 0) & 0xff)]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[(128 * 0) + passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[(128 * 0)] << 0);\
  passOffset = charsetReverse[((128 * 1) + (b0 >> 8) & 0xff)]; \
  b0 &= 0xffff00ff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[(128 * 1) + passOffset] << 8);\
  if (passOffset >= charsetLengths[1]) { \
    b0 &= 0xffff00ff;\
    b0 |= (uint32_t)(charsetForward[(128 * 1)] << 8);\
    passOffset = charsetReverse[((128 * 2) + (b0 >> 16) & 0xff)]; \
    b0 &= 0xff00ffff;\
    passOffset++;\
    b0 |= (uint32_t)(charsetForward[(128 * 2) + passOffset] << 16);\
    if (passOffset >= charsetLengths[2]) { \
      b0 &= 0xff00ffff;\
      b0 |= (uint32_t)(charsetForward[(128 * 2)] << 16);\
      passOffset = charsetReverse[((128 * 3) + (b0 >> 24) & 0xff)]; \
      b0 &= 0x00ffffff;\
      passOffset++;\
      b0 |= (uint32_t)(charsetForward[(128 * 3) + passOffset] << 24);\
      if (passOffset >= charsetLengths[3]) { \
        b0 &= 0x00ffffff;\
        b0 |= (uint32_t)(charsetForward[(128 * 3)] << 24);\
        passOffset = charsetReverse[((128 * 4) + (b1 >> 0) & 0xff)]; \
        b1 &= 0xffffff00;\
        passOffset++;\
        b1 |= (uint32_t)(charsetForward[(128 * 4) + passOffset] << 0);\
        if (passOffset >= charsetLengths[4]) { \
          b1 &= 0xffffff00;\
          b1 |= (uint32_t)(charsetForward[(128 * 4)] << 0);\
          passOffset = charsetReverse[((128 * 5) + (b1 >> 8) & 0xff)]; \
          b1 &= 0xffff00ff;\
          passOffset++;\
          b1 |= (uint32_t)(charsetForward[(128 * 5) + passOffset] << 8);\
          if (passOffset >= charsetLengths[5]) { \
            b1 &= 0xffff00ff;\
            b1 |= (uint32_t)(charsetForward[(128 * 5)] << 8);\
            passOffset = charsetReverse[((128 * 6) + (b1 >> 16) & 0xff)]; \
            b1 &= 0xff00ffff;\
            passOffset++;\
            b1 |= (uint32_t)(charsetForward[(128 * 6) + passOffset] << 16);\
            if (passOffset >= charsetLengths[6]) { \
              b1 &= 0xff00ffff;\
              b1 |= (uint32_t)(charsetForward[(128 * 6)] << 16);\
              passOffset = charsetReverse[((128 * 7) + (b1 >> 24) & 0xff)]; \
              b1 &= 0x00ffffff;\
              passOffset++;\
              b1 |= (uint32_t)(charsetForward[(128 * 7) + passOffset] << 24);\
              if (passOffset >= charsetLengths[7]) { \
                b1 &= 0x00ffffff;\
                b1 |= (uint32_t)(charsetForward[(128 * 7)] << 24);\
                passOffset = charsetReverse[((128 * 8) + (b2 >> 0) & 0xff)]; \
                b2 &= 0xffffff00;\
                passOffset++;\
                b2 |= (uint32_t)(charsetForward[(128 * 8) + passOffset] << 0);\
                if (passOffset >= charsetLengths[8]) { \
                  b2 &= 0xffffff00;\
                  b2 |= (uint32_t)(charsetForward[(128 * 8)] << 0);\
                  passOffset = charsetReverse[((128 * 9) + (b2 >> 8) & 0xff)]; \
                  b2 &= 0xffff00ff;\
                  passOffset++;\
                  b2 |= (uint32_t)(charsetForward[(128 * 9) + passOffset] << 8);\
                  if (passOffset >= charsetLengths[9]) { \
                    b2 &= 0xffff00ff;\
                    b2 |= (uint32_t)(charsetForward[(128 * 9)] << 8);\
                    passOffset = charsetReverse[((128 * 10) + (b2 >> 16) & 0xff)]; \
                    b2 &= 0xff00ffff;\
                    passOffset++;\
                    b2 |= (uint32_t)(charsetForward[(128 * 10) + passOffset] << 16);\
                    if (passOffset >= charsetLengths[10]) { \
                      b2 &= 0xff00ffff;\
                      b2 |= (uint32_t)(charsetForward[(128 * 10)] << 16);\
                      passOffset = charsetReverse[((128 * 11) + (b2 >> 24) & 0xff)]; \
                      b2 &= 0x00ffffff;\
                      passOffset++;\
                      b2 |= (uint32_t)(charsetForward[(128 * 11) + passOffset] << 24);\
                      if (passOffset >= charsetLengths[11]) { \
                        b2 &= 0x00ffffff;\
                        b2 |= (uint32_t)(charsetForward[(128 * 11)] << 24);\
                        passOffset = charsetReverse[((128 * 12) + (b3 >> 0) & 0xff)]; \
                        b3 &= 0xffffff00;\
                        passOffset++;\
                        b3 |= (uint32_t)(charsetForward[(128 * 12) + passOffset] << 0);\
                        if (passOffset >= charsetLengths[12]) { \
                          b3 &= 0xffffff00;\
                          b3 |= (uint32_t)(charsetForward[(128 * 12)] << 0);\
} } } } } } } } } } } } } } 


#define makeMFNMultipleIncrementorsNTLM14(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[((128 * 0) + (b0 >> 0) & 0xff)]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[(128 * 0) + passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[(128 * 0)] << 0);\
  passOffset = charsetReverse[((128 * 1) + (b0 >> 8) & 0xff)]; \
  b0 &= 0xffff00ff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[(128 * 1) + passOffset] << 8);\
  if (passOffset >= charsetLengths[1]) { \
    b0 &= 0xffff00ff;\
    b0 |= (uint32_t)(charsetForward[(128 * 1)] << 8);\
    passOffset = charsetReverse[((128 * 2) + (b0 >> 16) & 0xff)]; \
    b0 &= 0xff00ffff;\
    passOffset++;\
    b0 |= (uint32_t)(charsetForward[(128 * 2) + passOffset] << 16);\
    if (passOffset >= charsetLengths[2]) { \
      b0 &= 0xff00ffff;\
      b0 |= (uint32_t)(charsetForward[(128 * 2)] << 16);\
      passOffset = charsetReverse[((128 * 3) + (b0 >> 24) & 0xff)]; \
      b0 &= 0x00ffffff;\
      passOffset++;\
      b0 |= (uint32_t)(charsetForward[(128 * 3) + passOffset] << 24);\
      if (passOffset >= charsetLengths[3]) { \
        b0 &= 0x00ffffff;\
        b0 |= (uint32_t)(charsetForward[(128 * 3)] << 24);\
        passOffset = charsetReverse[((128 * 4) + (b1 >> 0) & 0xff)]; \
        b1 &= 0xffffff00;\
        passOffset++;\
        b1 |= (uint32_t)(charsetForward[(128 * 4) + passOffset] << 0);\
        if (passOffset >= charsetLengths[4]) { \
          b1 &= 0xffffff00;\
          b1 |= (uint32_t)(charsetForward[(128 * 4)] << 0);\
          passOffset = charsetReverse[((128 * 5) + (b1 >> 8) & 0xff)]; \
          b1 &= 0xffff00ff;\
          passOffset++;\
          b1 |= (uint32_t)(charsetForward[(128 * 5) + passOffset] << 8);\
          if (passOffset >= charsetLengths[5]) { \
            b1 &= 0xffff00ff;\
            b1 |= (uint32_t)(charsetForward[(128 * 5)] << 8);\
            passOffset = charsetReverse[((128 * 6) + (b1 >> 16) & 0xff)]; \
            b1 &= 0xff00ffff;\
            passOffset++;\
            b1 |= (uint32_t)(charsetForward[(128 * 6) + passOffset] << 16);\
            if (passOffset >= charsetLengths[6]) { \
              b1 &= 0xff00ffff;\
              b1 |= (uint32_t)(charsetForward[(128 * 6)] << 16);\
              passOffset = charsetReverse[((128 * 7) + (b1 >> 24) & 0xff)]; \
              b1 &= 0x00ffffff;\
              passOffset++;\
              b1 |= (uint32_t)(charsetForward[(128 * 7) + passOffset] << 24);\
              if (passOffset >= charsetLengths[7]) { \
                b1 &= 0x00ffffff;\
                b1 |= (uint32_t)(charsetForward[(128 * 7)] << 24);\
                passOffset = charsetReverse[((128 * 8) + (b2 >> 0) & 0xff)]; \
                b2 &= 0xffffff00;\
                passOffset++;\
                b2 |= (uint32_t)(charsetForward[(128 * 8) + passOffset] << 0);\
                if (passOffset >= charsetLengths[8]) { \
                  b2 &= 0xffffff00;\
                  b2 |= (uint32_t)(charsetForward[(128 * 8)] << 0);\
                  passOffset = charsetReverse[((128 * 9) + (b2 >> 8) & 0xff)]; \
                  b2 &= 0xffff00ff;\
                  passOffset++;\
                  b2 |= (uint32_t)(charsetForward[(128 * 9) + passOffset] << 8);\
                  if (passOffset >= charsetLengths[9]) { \
                    b2 &= 0xffff00ff;\
                    b2 |= (uint32_t)(charsetForward[(128 * 9)] << 8);\
                    passOffset = charsetReverse[((128 * 10) + (b2 >> 16) & 0xff)]; \
                    b2 &= 0xff00ffff;\
                    passOffset++;\
                    b2 |= (uint32_t)(charsetForward[(128 * 10) + passOffset] << 16);\
                    if (passOffset >= charsetLengths[10]) { \
                      b2 &= 0xff00ffff;\
                      b2 |= (uint32_t)(charsetForward[(128 * 10)] << 16);\
                      passOffset = charsetReverse[((128 * 11) + (b2 >> 24) & 0xff)]; \
                      b2 &= 0x00ffffff;\
                      passOffset++;\
                      b2 |= (uint32_t)(charsetForward[(128 * 11) + passOffset] << 24);\
                      if (passOffset >= charsetLengths[11]) { \
                        b2 &= 0x00ffffff;\
                        b2 |= (uint32_t)(charsetForward[(128 * 11)] << 24);\
                        passOffset = charsetReverse[((128 * 12) + (b3 >> 0) & 0xff)]; \
                        b3 &= 0xffffff00;\
                        passOffset++;\
                        b3 |= (uint32_t)(charsetForward[(128 * 12) + passOffset] << 0);\
                        if (passOffset >= charsetLengths[12]) { \
                          b3 &= 0xffffff00;\
                          b3 |= (uint32_t)(charsetForward[(128 * 12)] << 0);\
                          passOffset = charsetReverse[((128 * 13) + (b3 >> 8) & 0xff)]; \
                          b3 &= 0xffff00ff;\
                          passOffset++;\
                          b3 |= (uint32_t)(charsetForward[(128 * 13) + passOffset] << 8);\
                          if (passOffset >= charsetLengths[13]) { \
                            b3 &= 0xffff00ff;\
                            b3 |= (uint32_t)(charsetForward[(128 * 13)] << 8);\
} } } } } } } } } } } } } } } 


#define makeMFNMultipleIncrementorsNTLM15(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[((128 * 0) + (b0 >> 0) & 0xff)]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[(128 * 0) + passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[(128 * 0)] << 0);\
  passOffset = charsetReverse[((128 * 1) + (b0 >> 8) & 0xff)]; \
  b0 &= 0xffff00ff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[(128 * 1) + passOffset] << 8);\
  if (passOffset >= charsetLengths[1]) { \
    b0 &= 0xffff00ff;\
    b0 |= (uint32_t)(charsetForward[(128 * 1)] << 8);\
    passOffset = charsetReverse[((128 * 2) + (b0 >> 16) & 0xff)]; \
    b0 &= 0xff00ffff;\
    passOffset++;\
    b0 |= (uint32_t)(charsetForward[(128 * 2) + passOffset] << 16);\
    if (passOffset >= charsetLengths[2]) { \
      b0 &= 0xff00ffff;\
      b0 |= (uint32_t)(charsetForward[(128 * 2)] << 16);\
      passOffset = charsetReverse[((128 * 3) + (b0 >> 24) & 0xff)]; \
      b0 &= 0x00ffffff;\
      passOffset++;\
      b0 |= (uint32_t)(charsetForward[(128 * 3) + passOffset] << 24);\
      if (passOffset >= charsetLengths[3]) { \
        b0 &= 0x00ffffff;\
        b0 |= (uint32_t)(charsetForward[(128 * 3)] << 24);\
        passOffset = charsetReverse[((128 * 4) + (b1 >> 0) & 0xff)]; \
        b1 &= 0xffffff00;\
        passOffset++;\
        b1 |= (uint32_t)(charsetForward[(128 * 4) + passOffset] << 0);\
        if (passOffset >= charsetLengths[4]) { \
          b1 &= 0xffffff00;\
          b1 |= (uint32_t)(charsetForward[(128 * 4)] << 0);\
          passOffset = charsetReverse[((128 * 5) + (b1 >> 8) & 0xff)]; \
          b1 &= 0xffff00ff;\
          passOffset++;\
          b1 |= (uint32_t)(charsetForward[(128 * 5) + passOffset] << 8);\
          if (passOffset >= charsetLengths[5]) { \
            b1 &= 0xffff00ff;\
            b1 |= (uint32_t)(charsetForward[(128 * 5)] << 8);\
            passOffset = charsetReverse[((128 * 6) + (b1 >> 16) & 0xff)]; \
            b1 &= 0xff00ffff;\
            passOffset++;\
            b1 |= (uint32_t)(charsetForward[(128 * 6) + passOffset] << 16);\
            if (passOffset >= charsetLengths[6]) { \
              b1 &= 0xff00ffff;\
              b1 |= (uint32_t)(charsetForward[(128 * 6)] << 16);\
              passOffset = charsetReverse[((128 * 7) + (b1 >> 24) & 0xff)]; \
              b1 &= 0x00ffffff;\
              passOffset++;\
              b1 |= (uint32_t)(charsetForward[(128 * 7) + passOffset] << 24);\
              if (passOffset >= charsetLengths[7]) { \
                b1 &= 0x00ffffff;\
                b1 |= (uint32_t)(charsetForward[(128 * 7)] << 24);\
                passOffset = charsetReverse[((128 * 8) + (b2 >> 0) & 0xff)]; \
                b2 &= 0xffffff00;\
                passOffset++;\
                b2 |= (uint32_t)(charsetForward[(128 * 8) + passOffset] << 0);\
                if (passOffset >= charsetLengths[8]) { \
                  b2 &= 0xffffff00;\
                  b2 |= (uint32_t)(charsetForward[(128 * 8)] << 0);\
                  passOffset = charsetReverse[((128 * 9) + (b2 >> 8) & 0xff)]; \
                  b2 &= 0xffff00ff;\
                  passOffset++;\
                  b2 |= (uint32_t)(charsetForward[(128 * 9) + passOffset] << 8);\
                  if (passOffset >= charsetLengths[9]) { \
                    b2 &= 0xffff00ff;\
                    b2 |= (uint32_t)(charsetForward[(128 * 9)] << 8);\
                    passOffset = charsetReverse[((128 * 10) + (b2 >> 16) & 0xff)]; \
                    b2 &= 0xff00ffff;\
                    passOffset++;\
                    b2 |= (uint32_t)(charsetForward[(128 * 10) + passOffset] << 16);\
                    if (passOffset >= charsetLengths[10]) { \
                      b2 &= 0xff00ffff;\
                      b2 |= (uint32_t)(charsetForward[(128 * 10)] << 16);\
                      passOffset = charsetReverse[((128 * 11) + (b2 >> 24) & 0xff)]; \
                      b2 &= 0x00ffffff;\
                      passOffset++;\
                      b2 |= (uint32_t)(charsetForward[(128 * 11) + passOffset] << 24);\
                      if (passOffset >= charsetLengths[11]) { \
                        b2 &= 0x00ffffff;\
                        b2 |= (uint32_t)(charsetForward[(128 * 11)] << 24);\
                        passOffset = charsetReverse[((128 * 12) + (b3 >> 0) & 0xff)]; \
                        b3 &= 0xffffff00;\
                        passOffset++;\
                        b3 |= (uint32_t)(charsetForward[(128 * 12) + passOffset] << 0);\
                        if (passOffset >= charsetLengths[12]) { \
                          b3 &= 0xffffff00;\
                          b3 |= (uint32_t)(charsetForward[(128 * 12)] << 0);\
                          passOffset = charsetReverse[((128 * 13) + (b3 >> 8) & 0xff)]; \
                          b3 &= 0xffff00ff;\
                          passOffset++;\
                          b3 |= (uint32_t)(charsetForward[(128 * 13) + passOffset] << 8);\
                          if (passOffset >= charsetLengths[13]) { \
                            b3 &= 0xffff00ff;\
                            b3 |= (uint32_t)(charsetForward[(128 * 13)] << 8);\
                            passOffset = charsetReverse[((128 * 14) + (b3 >> 16) & 0xff)]; \
                            b3 &= 0xff00ffff;\
                            passOffset++;\
                            b3 |= (uint32_t)(charsetForward[(128 * 14) + passOffset] << 16);\
                            if (passOffset >= charsetLengths[14]) { \
                              b3 &= 0xff00ffff;\
                              b3 |= (uint32_t)(charsetForward[(128 * 14)] << 16);\
} } } } } } } } } } } } } } } } 


#define makeMFNMultipleIncrementorsNTLM16(charsetForward, charsetReverse, charsetLengths) {\
passOffset = charsetReverse[((128 * 0) + (b0 >> 0) & 0xff)]; \
b0 &= 0xffffff00;\
passOffset++;\
b0 |= (uint32_t)(charsetForward[(128 * 0) + passOffset] << 0);\
if (passOffset >= charsetLengths[0]) { \
  b0 &= 0xffffff00;\
  b0 |= (uint32_t)(charsetForward[(128 * 0)] << 0);\
  passOffset = charsetReverse[((128 * 1) + (b0 >> 8) & 0xff)]; \
  b0 &= 0xffff00ff;\
  passOffset++;\
  b0 |= (uint32_t)(charsetForward[(128 * 1) + passOffset] << 8);\
  if (passOffset >= charsetLengths[1]) { \
    b0 &= 0xffff00ff;\
    b0 |= (uint32_t)(charsetForward[(128 * 1)] << 8);\
    passOffset = charsetReverse[((128 * 2) + (b0 >> 16) & 0xff)]; \
    b0 &= 0xff00ffff;\
    passOffset++;\
    b0 |= (uint32_t)(charsetForward[(128 * 2) + passOffset] << 16);\
    if (passOffset >= charsetLengths[2]) { \
      b0 &= 0xff00ffff;\
      b0 |= (uint32_t)(charsetForward[(128 * 2)] << 16);\
      passOffset = charsetReverse[((128 * 3) + (b0 >> 24) & 0xff)]; \
      b0 &= 0x00ffffff;\
      passOffset++;\
      b0 |= (uint32_t)(charsetForward[(128 * 3) + passOffset] << 24);\
      if (passOffset >= charsetLengths[3]) { \
        b0 &= 0x00ffffff;\
        b0 |= (uint32_t)(charsetForward[(128 * 3)] << 24);\
        passOffset = charsetReverse[((128 * 4) + (b1 >> 0) & 0xff)]; \
        b1 &= 0xffffff00;\
        passOffset++;\
        b1 |= (uint32_t)(charsetForward[(128 * 4) + passOffset] << 0);\
        if (passOffset >= charsetLengths[4]) { \
          b1 &= 0xffffff00;\
          b1 |= (uint32_t)(charsetForward[(128 * 4)] << 0);\
          passOffset = charsetReverse[((128 * 5) + (b1 >> 8) & 0xff)]; \
          b1 &= 0xffff00ff;\
          passOffset++;\
          b1 |= (uint32_t)(charsetForward[(128 * 5) + passOffset] << 8);\
          if (passOffset >= charsetLengths[5]) { \
            b1 &= 0xffff00ff;\
            b1 |= (uint32_t)(charsetForward[(128 * 5)] << 8);\
            passOffset = charsetReverse[((128 * 6) + (b1 >> 16) & 0xff)]; \
            b1 &= 0xff00ffff;\
            passOffset++;\
            b1 |= (uint32_t)(charsetForward[(128 * 6) + passOffset] << 16);\
            if (passOffset >= charsetLengths[6]) { \
              b1 &= 0xff00ffff;\
              b1 |= (uint32_t)(charsetForward[(128 * 6)] << 16);\
              passOffset = charsetReverse[((128 * 7) + (b1 >> 24) & 0xff)]; \
              b1 &= 0x00ffffff;\
              passOffset++;\
              b1 |= (uint32_t)(charsetForward[(128 * 7) + passOffset] << 24);\
              if (passOffset >= charsetLengths[7]) { \
                b1 &= 0x00ffffff;\
                b1 |= (uint32_t)(charsetForward[(128 * 7)] << 24);\
                passOffset = charsetReverse[((128 * 8) + (b2 >> 0) & 0xff)]; \
                b2 &= 0xffffff00;\
                passOffset++;\
                b2 |= (uint32_t)(charsetForward[(128 * 8) + passOffset] << 0);\
                if (passOffset >= charsetLengths[8]) { \
                  b2 &= 0xffffff00;\
                  b2 |= (uint32_t)(charsetForward[(128 * 8)] << 0);\
                  passOffset = charsetReverse[((128 * 9) + (b2 >> 8) & 0xff)]; \
                  b2 &= 0xffff00ff;\
                  passOffset++;\
                  b2 |= (uint32_t)(charsetForward[(128 * 9) + passOffset] << 8);\
                  if (passOffset >= charsetLengths[9]) { \
                    b2 &= 0xffff00ff;\
                    b2 |= (uint32_t)(charsetForward[(128 * 9)] << 8);\
                    passOffset = charsetReverse[((128 * 10) + (b2 >> 16) & 0xff)]; \
                    b2 &= 0xff00ffff;\
                    passOffset++;\
                    b2 |= (uint32_t)(charsetForward[(128 * 10) + passOffset] << 16);\
                    if (passOffset >= charsetLengths[10]) { \
                      b2 &= 0xff00ffff;\
                      b2 |= (uint32_t)(charsetForward[(128 * 10)] << 16);\
                      passOffset = charsetReverse[((128 * 11) + (b2 >> 24) & 0xff)]; \
                      b2 &= 0x00ffffff;\
                      passOffset++;\
                      b2 |= (uint32_t)(charsetForward[(128 * 11) + passOffset] << 24);\
                      if (passOffset >= charsetLengths[11]) { \
                        b2 &= 0x00ffffff;\
                        b2 |= (uint32_t)(charsetForward[(128 * 11)] << 24);\
                        passOffset = charsetReverse[((128 * 12) + (b3 >> 0) & 0xff)]; \
                        b3 &= 0xffffff00;\
                        passOffset++;\
                        b3 |= (uint32_t)(charsetForward[(128 * 12) + passOffset] << 0);\
                        if (passOffset >= charsetLengths[12]) { \
                          b3 &= 0xffffff00;\
                          b3 |= (uint32_t)(charsetForward[(128 * 12)] << 0);\
                          passOffset = charsetReverse[((128 * 13) + (b3 >> 8) & 0xff)]; \
                          b3 &= 0xffff00ff;\
                          passOffset++;\
                          b3 |= (uint32_t)(charsetForward[(128 * 13) + passOffset] << 8);\
                          if (passOffset >= charsetLengths[13]) { \
                            b3 &= 0xffff00ff;\
                            b3 |= (uint32_t)(charsetForward[(128 * 13)] << 8);\
                            passOffset = charsetReverse[((128 * 14) + (b3 >> 16) & 0xff)]; \
                            b3 &= 0xff00ffff;\
                            passOffset++;\
                            b3 |= (uint32_t)(charsetForward[(128 * 14) + passOffset] << 16);\
                            if (passOffset >= charsetLengths[14]) { \
                              b3 &= 0xff00ffff;\
                              b3 |= (uint32_t)(charsetForward[(128 * 14)] << 16);\
                              passOffset = charsetReverse[((128 * 15) + (b3 >> 24) & 0xff)]; \
                              b3 &= 0x00ffffff;\
                              passOffset++;\
                              b3 |= (uint32_t)(charsetForward[(128 * 15) + passOffset] << 24);\
                              if (passOffset >= charsetLengths[15]) { \
                                b3 &= 0x00ffffff;\
                                b3 |= (uint32_t)(charsetForward[(128 * 15)] << 24);\
} } } } } } } } } } } } } } } } } 


