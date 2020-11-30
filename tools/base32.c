
/** Characters that can appear (case-insensitively) in a base32 encoding. */
#define BASE32_CHARS "abcdefghijklmnopqrstuvwxyz234567"

/** Implements base32 encoding as in RFC 4648. */
void base32_encode(char *dest, const unsigned char *src)
{
  unsigned int i, v, u;

  unsigned char bit;

  unsigned char nbits = 80;
  /* We need enough space for the encoded data and the extra NUL byte. */


  /* Make sure we leave no uninitialized data in the destination buffer. */


  for(i=0;i<16; i++) dest[i]=0;

  for (i=0,bit=0; bit < nbits; ++i, bit+=5) {
    /* set v to the 16-bit value starting at src[bits/8], 0-padded. */
    unsigned char idx = bit / 8;
    v = ((unsigned char)src[idx]) << 8;
    if (idx+1 < 10)
      v += (unsigned char)src[idx+1];
    /* set u to the 5-bit value at the bit'th bit of buf. */
    u = (v >> (11-(bit%8))) & 0x1F;
    dest[i] = BASE32_CHARS[u];
  }
  //dest[i] = '\0';
}


/** Implements base32 decoding as in RFC 4648.
 * Returns 0 if successful, -1 otherwise.
 */
int base32_decode(unsigned char *dest, const char *src)
{

  unsigned char i;
  unsigned char j, bit;
  char tmp[16];


  for(i=0;i<10;i++) dest[i]=0;


  /* Convert base32 encoded chars to the 5-bit values that they represent. */

  for (j = 0; j < 16; ++j)
  {
    if (src[j] > 0x60 && src[j] < 0x7B) tmp[j] = src[j] - 0x61;
    else if (src[j] > 0x31 && src[j] < 0x38) tmp[j] = src[j] - 0x18;
    else if (src[j] > 0x40 && src[j] < 0x5B) tmp[j] = src[j] - 0x41;
    else 
	{
      //printf("illegal character in base32 encoded string");
      return -1;
    }
  }

  /* Assemble result byte-wise by applying five possible cases. */
  for (i = 0, bit = 0; bit < 80; ++i, bit += 8) 
  {
    switch (bit % 40) {
    case 0:
      dest[i] = (((unsigned char)tmp[(bit/5)]) << 3) +
                (((unsigned char)tmp[(bit/5)+1]) >> 2);
      break;
    case 8:
      dest[i] = (((unsigned char)tmp[(bit/5)]) << 6) +
                (((unsigned char)tmp[(bit/5)+1]) << 1) +
                (((unsigned char)tmp[(bit/5)+2]) >> 4);
      break;
    case 16:
      dest[i] = (((unsigned char)tmp[(bit/5)]) << 4) +
                (((unsigned char)tmp[(bit/5)+1]) >> 1);
      break;
    case 24:
      dest[i] = (((unsigned char)tmp[(bit/5)]) << 7) +
                (((unsigned char)tmp[(bit/5)+1]) << 2) +
                (((unsigned char)tmp[(bit/5)+2]) >> 3);
      break;
    case 32:
      dest[i] = (((unsigned char)tmp[(bit/5)]) << 5) +
                ((unsigned char)tmp[(bit/5)+1]);
      break;
    }
  }

  return 0;
}