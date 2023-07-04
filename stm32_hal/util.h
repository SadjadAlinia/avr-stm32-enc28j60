#include <string.h>

unsigned char Low(const unsigned short value);
unsigned char High(const unsigned short value);
void LowPut(unsigned short *value, const unsigned char ch);

void HighPut(unsigned short *value, const unsigned char ch);
unsigned short CharsToShort(const unsigned char *value);
void CharsPutShort(unsigned char *chars, const unsigned short value);

unsigned long CharsToLong(const unsigned char *value);

unsigned char ParseLong(unsigned long *number, const unsigned char *ch, const unsigned short length);

unsigned char CharsCmp(const unsigned char *ch1, const unsigned short length1, const unsigned char *ch2, const unsigned short length2);
void CharsCat(unsigned char *destination, unsigned short *destinationLength, const unsigned char *source, const unsigned short sourceLength);
