

unsigned int crc32_le(unsigned char const *p, unsigned int len);
unsigned int crc32_leupd(unsigned char const *p, unsigned int len, unsigned int crc4);
unsigned int mtoi(unsigned char const *p);
void mtom(unsigned char *pd, unsigned char const *ps, int const a);
void itom(unsigned char *p, unsigned int const a);
unsigned short mtos(unsigned char const *p);
void stom(unsigned char *p, unsigned short const a);

unsigned short telcrc16(unsigned char const *p, int len);
unsigned char dutcrc8(unsigned char* data, int len);

unsigned int m2u(unsigned char* m);
void u2m(unsigned int u, unsigned char* m);

int myatoi(char* p);
short bitcnt(unsigned char* data, short len);
unsigned char iszero(unsigned char* data, short len);
unsigned char isequal(unsigned char* data0, unsigned char* data1, short len);
short str2bin(char* str, unsigned char* bin, short maxbinlen);
void bin2str(unsigned char* bin, char* str, short binlen);


