#ifndef MINER_H
#define MINER_H
#include "handylib.h"

#define NDEBUG
#define VERSION 2

//maximum number of chips
#define MAXCHIPS 256
//maximum number of alternative banks
#define MAXBANKS 4
//maximum number of chips on alternative bank
#define BANKCHIPS 64
//maximum number of chips
#define MAXBOARDS (MAXCHIPS/16)
//maximum number of wrong nonces a chip can produce in 5 min before downclocking
#define MAXERROR 5
//minimum number of correct results in the evaluation period (5 min) to prevent reprogramming
#define MINGOOD 50
//delete stored getworks older than this
#define MAXWORKAGE 60
//size of putwork queue before stoping loading new tasks
#define MAXPUTWORK 1000
//maximum chip speed available for auto tuner
//speed/nrate/hrate/watt
//   53/   97/  100/  84
//   54/   98/  107/  88
//   55/  101/  115/  93
//   56/   99/  125/  99
#define MAXSPEED 57
#define DEFSPEED 54
#define MINSPEED 52

typedef	uint32_t hasht[8];
typedef uint32_t datat[19];
#pragma pack(1)
typedef struct btc_block {
        uint32_t nVersion; // replaced by hostid
        uint32_t hashPrevBlock[8];
        uint32_t hashMerkleRoot[8];
        uint32_t nTime;
        uint32_t nBits;
        uint32_t nNonce;
} btc_block_t;
#pragma pack()
typedef struct getwork {
        uint32_t mtime; // time obtained, not nTime from data
        uint32_t data[32];
        uint32_t midstate[8];
	unsigned char host; // id of the pool/stratum/client
} getwork_t;
typedef struct putwork {
        uint32_t data[32];
} putwork_t;
typedef struct hosts_s {
        const char* aut;
        const char* url;
	uint32_t target[8];
	void *gwt; // GetworkThread handling download 
	void *pwt; // PutworkThread handling upload 
	unsigned int got;
	unsigned int done;
	unsigned int sent;
} hosts_t;

/*class GetworkThread : public Thread
{
        public:
        std::vector<getwork> getworks;
        unsigned char host;
        virtual void Run();
        virtual void log();
};
class PutworkThread : public Thread
{
        public:
        std::vector<putwork> putworks;
        unsigned char host;
        virtual void Run();
        virtual void log();
};*/

//miner.c
void SHA256_Full(unsigned *state, unsigned *data, const unsigned *st);
void ms3_compute(unsigned *p);
unsigned dec_nonce(unsigned in);
int test_nonce(unsigned tnon,hasht mids,datat data,hasht hash,uint32_t* pwdata,uint32_t* pwhash,int chip,int busy,int x,int y);
int fix_nonce(uint32_t newn,uint32_t old,hasht mids1,datat data1,hasht mids2,datat data2,int change,int chip,int job,int busy,uint32_t* pwdata,uint32_t* pwhash);
void cpu_miner();
void spi_miner(int chips,char* chipconf,char* chipfast);
char* chip_conf(char conf);
char conf_chip(char* conf);
void chip_init(void);
void chip_stat(int chips);

//spidevc.cpp
void spi_init(void);
void spi_close(void);
void spi_reset(int max,int bank);
int spi_txrx(const char *wrbuf, char *rdbuf, int bufsz,const unsigned int* off,const unsigned int* boff);
void spi_emit_break(void);
void spi_emit_fasync(void);
void spi_emit_fsync(void);
void spi_emit_buf_reverse(const char *str, unsigned sz);
void spi_emit_buf(const char *str, unsigned sz);
void spi_emit_data(unsigned addr, const char *buf, unsigned len);
void config_reg(int cfgreg, int ena);
void chip_log(int max,int spinow);
unsigned char* chip_osc(int fast);
int spi_put(hasht mids,datat data,datat* avec,char* chipconf,char* chipfast);
int spi_get(hasht mids,datat data,datat* rvec,char* chipconf);
void spi_programm(char* chipconf,char* chipfast,int bank,int first, int last);
int spi_start(char* chipconf,char* chipfast);

//jobconnect.cpp
uint32_t get_work(uint32_t *midstate, uint32_t *data);
void put_work(uint32_t *data,uint32_t* hash);
void byte_reverse(uint8_t *p);
void get_start(void);
void put_start(void);
int put_queue(void);

#endif
