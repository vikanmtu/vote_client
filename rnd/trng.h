        int getSid(unsigned char* data, int len);
        int getSys(unsigned char* data, int len);

        short trng_init(void);
        void trng_get(unsigned char* out, short len);
