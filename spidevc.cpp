#include <sys/mman.h>
#include <stdint.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <signal.h>
#include <sys/types.h>
#include <linux/spi/spidev.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <linux/i2c.h>
#include <linux/i2c-dev.h>
#include <sys/stat.h>
#include <math.h>
#include <assert.h>
#include "handylib.h"
#include "miner.h"

using namespace handylib;

#define INP_GPIO(g) *(gpio+((g)/10)) &= ~(7<<(((g)%10)*3))
#define OUT_GPIO(g) *(gpio+((g)/10)) |=  (1<<(((g)%10)*3))
#define SET_GPIO_ALT(g,a) *(gpio+(((g)/10))) |= (((a)<=3?(a)+4:(a)==4?3:2)<<(((g)%10)*3))
#define GPIO_SET *(gpio+7)  // sets   bits which are 1 ignores bits which are 0
#define GPIO_CLR *(gpio+10) // clears bits which are 1 ignores bits which are 0
#define GPIO_LEV *(gpio+13) // pin level, used to read pins

#define SPISPEED 96000 // was 192kHz before
//#define SPIBUF 4096 // default
//#define SPIBUF 2048 // too big for 192kHz
//#define SPIBUF 1024 // small enough for 128kHz, but too big for 100kHz
#define SPIBUF 1024 // small enough for <100kHz
#define SPIMAXSZ MAXCHIPS*512

#define SPIBUF_DONE 0
#define SPIBUF_READY 1
#define SPIBUF_SENDING 2
#define SPIBUF_SENT 3
#define SPIBUF_READING 4

const char counters[16]={64,64,4,4+4,4+2,4+2+16,4,4+1,(61)%65,(61+1)%65,(61+3)%65,(61+3+16)%65,(61+4)%65,(61+4+4)%65,(61+3+3)%65,(61+3+1+3)%65};
const unsigned w1[16]={0,0,0,0xffffffff, 0x80000000,0,0,0, 0,0,0,0, 0,0,0,0x00000280};
const unsigned w2[8]={0x80000000,0,0,0, 0,0,0,0x100};
const unsigned data[20]={0xb0e72d8e,0x1dc5b862,0xe9e7c4a6,0x3050f1f5,0x8a1a6b7e,0x7ec384e8,0x42c1c3fc,0x8ed158a1,0x8a1a6b7e,0x6f484872,
			0x4ff0bb9b,0x12c97f07,0xb0e72d8e,0x55d979bc,0x39403296,0x40f09e84,0x8a0bb7b7,0x33af304f,0x0b290c1a,0xf0c4e61f};

Thread::mutex spmut;

static unsigned int spinow=0; // current buffer page not used for transmission, 0 or 1
static unsigned char spibufst[2]={SPIBUF_DONE,SPIBUF_DONE}; //status of the buffer
static unsigned char spibufwr[2][SPIMAXSZ]; 
static unsigned char spibufrd[2][SPIMAXSZ];
static unsigned int  spibufsz[2];
static datat         spidata[2];
static hasht         spimids[2];
static unsigned int  chipoff[2][MAXCHIPS+1];
static unsigned int  bankoff[2][MAXBANKS+2];
static char          oldfast[MAXCHIPS]; // speed set for each chip
static char          oldconf[MAXCHIPS]; // [AIFDSO] (bits[1:6]) auto,iclk,fast,divide,slow,oclk
       char          chipbank[MAXCHIPS+1]; // bank of the chip (in version 2 chips are on cards on 4 banks (4 cards per bank)
static unsigned int  chipspis[MAXCHIPS+1]; // speed of SPI communication for chips(i) = 1000000000/(100+30*n);
static int spifd=0;
static int maxchips=0;
static volatile unsigned *gpio;

//const unsigned char osc7[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00 };
//const unsigned char osc6[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x00 };
//const unsigned char osc6[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00 };
//const unsigned char osc5[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00 };
//const unsigned char osc4[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00 }; // Thermometer code from left to right - more ones ==> faster clock!
//const unsigned char osc3[8] = { 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00 }; // Thermometer code from left to right - more ones ==> faster clock!
//const unsigned char osc2[8] = { 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // Thermometer code from left to right - more ones ==> faster clock!
//const unsigned char osc1[8] = { 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // Thermometer code from left to right - more ones ==> faster clock!

class SpitalkThread : public Thread
{
        public:
        virtual void Run();
};
void spi_init(void)
{
	int i,mode=0,bits=8,maxspeed=1000000; // 24 000 000;

	if(system("modprobe i2c-dev")){
		fprintf(stderr,"FATAL, modprobe i2c-dev failed (must be root)\n");
		exit(-1);}
	if(system("modprobe i2c-bcm2708")){
		fprintf(stderr,"FATAL, modprobe i2c-bcm2708 failed (must be root)\n");
		exit(-1);}
	if(system("modprobe spidev")){
		fprintf(stderr,"FATAL, modprobe spidev failed (must be root)\n");
		exit(-1);}
	if(system("modprobe spi-bcm2708")){
		fprintf(stderr,"FATAL, modprobe spi-bcm2708 failed (must be root)\n");
		exit(-1);}

	spifd = open("/dev/mem",O_RDWR|O_SYNC);
	if (spifd < 0) { perror("/dev/mem trouble"); exit(1); }
	gpio = (volatile unsigned*)mmap(0,SPIBUF,PROT_READ|PROT_WRITE,MAP_SHARED,spifd,0x20200000);
	if (gpio == MAP_FAILED) { perror("gpio mmap trouble"); exit(1); }
	close(spifd);

        spifd = open("/dev/spidev0.0", O_RDWR);
        if (spifd < 0) { perror("Unable to open SPI device"); exit(1); }
        if (ioctl(spifd, SPI_IOC_WR_MODE, &mode) < 0) { perror("Unable to set WR MODE"); close(spifd); exit(-1); }
        if (ioctl(spifd, SPI_IOC_RD_MODE, &mode) < 0) { perror("Unable to set RD MODE"); close(spifd); exit(-1); }
        if (ioctl(spifd, SPI_IOC_WR_BITS_PER_WORD, &bits) < 0) { perror("Unable to set WR_BITS_PER_WORD"); close(spifd); exit(-1); }
        if (ioctl(spifd, SPI_IOC_RD_BITS_PER_WORD, &bits) < 0) { perror("Unable to set RD_BITS_PER_WORD"); close(spifd); exit(-1); }
        if (ioctl(spifd, SPI_IOC_WR_MAX_SPEED_HZ, &maxspeed) < 0) { perror("Unable to set WR_MAX_SPEED_HZ"); close(spifd); exit(-1); }
        if (ioctl(spifd, SPI_IOC_RD_MAX_SPEED_HZ, &maxspeed) < 0) { perror("Unable to set RD_MAX_SPEED_HZ"); close(spifd); exit(-1); }

	for(i=0;i<=MAXCHIPS;i++){
		//chipspis[i]=int(1000000.0/(200.0+20.0*(i+1)))*1000;} // error around 192
		//chipspis[i]=int(1000000.0/(200.0+25.0*(i+1)))*1000;} // error around 194
		chipspis[i]=int(1000000.0/(100.0+31.0*(i+1)))*1000;}
}

void spi_close()
{	close(spifd);
}

// RESET all chips in async chain, the oposite of emit_break
// Bit-banging reset, to reset more chips in chain - toggle for longer period... Each 3 reset cycles reset first chip in sync chain
void spi_reset(int max,int bank)
{
	const int banks[4]={18,23,24,25}; // GPIO connected to OE of level shifters
	int i;

	INP_GPIO(10); OUT_GPIO(10);
	INP_GPIO(11); OUT_GPIO(11);
	if(bank){ // does not turn off other banks for bank==0 !!!
		for(i=0;i<4;i++){
			INP_GPIO(banks[i]);
			OUT_GPIO(banks[i]);
			if(i+1==bank){
				GPIO_SET = 1 << banks[i];
			} // enable bank
			else{
				GPIO_CLR = 1 << banks[i];
			}
		}
		usleep(4096);
	} // disable bank
	else{
		for(i=0;i<4;i++){
			INP_GPIO(banks[i]);}}
	GPIO_SET = 1 << 11; // Set SCK
	for (i = 0; i < max; i++) { // On standard settings this unoptimized code produces 1 Mhz freq.
		GPIO_SET = 1 << 10;
		usleep(1);
		GPIO_CLR = 1 << 10;
		usleep(1);}
	GPIO_CLR = 1 << 11;
	INP_GPIO(11);
	INP_GPIO(10);
	INP_GPIO(9);
	SET_GPIO_ALT(11,0); // set gpio SCK
	SET_GPIO_ALT(10,0); // set gpio MOSI
	SET_GPIO_ALT(9,0); // set gpio MISO
}

int spi_txrx(const char *wrbuf,char *rdbuf,int bufsz,const unsigned int* off,const unsigned int* boff)
{
	int i=0,bank;
	unsigned int pos=0;
	struct spi_ioc_transfer tr;
	memset(&tr,0,sizeof(tr));
	tr.delay_usecs = 0; // was 1
	tr.speed_hz = SPISPEED; // used for initial programming
	// tr.pad =  ; // :-) how to find this ???
	// http://www.raspberrypi.org/wp-content/uploads/2012/02/BCM2835-ARM-Peripherals.pdf , page 20
/*
Physical addresses range from 0x20000000 to 0x20FFFFFF for peripherals. The bus addresses for peripherals are set up to map onto the periphe ral bus address range starting at 0x7E000000. Thus a peripheral advertised here at bus address 0x7Ennnnnn i s available at physical address 0x20nnnnnn. 
0x7E21 5080 AUX_SPI0_CNTL0_REG	SPI 1 Control register 0 32
0x7E21 5084 AUX_SPI0_CNTL1_REG	SPI 1 Control register 1 8
0x7E21 5088 AUX_SPI0_STAT_REG	SPI 1 Status 32
0x7E21 5090 AUX_SPI0_IO_REG	SPI 1 Data 32
0x7E21 5094 AUX_SPI0_PEEK_REG	SPI 1 Peek 16 
*/

	for(bank=0;bank<=MAXBANKS;bank++){
		if(boff[bank]){
			spi_reset(64,bank);
			break;}}
	assert(bank<=MAXBANKS);
        for(;bufsz>0;bufsz-=tr.len,wrbuf+=tr.len,rdbuf+=tr.len,pos+=tr.len) {
                tr.tx_buf=(uintptr_t)wrbuf;
                tr.rx_buf=(uintptr_t)rdbuf;
		tr.speed_hz = SPISPEED; // used for initial programming
		if(pos==boff[bank]){
			for(;++bank<=MAXBANKS;){
				if(boff[bank]>pos){
					spi_reset(64,bank);
					break;}}}
		if(bufsz<SPIBUF){
			tr.len=bufsz;}
		else{
                	tr.len=SPIBUF;}
		if(pos+tr.len>boff[bank] && boff[bank]>pos){
			tr.len=boff[bank]-pos;}
		for(;i<=maxchips;i++){
			if(!off[i]){
				continue;}
			if(off[i]>=pos+tr.len){
				tr.speed_hz=chipspis[i];
				break;}}
		assert(i<=maxchips);
		assert(chipspis[i]!=SPISPEED);
		assert(tr.speed_hz!=SPISPEED);
                if((int)ioctl(spifd, SPI_IOC_MESSAGE(1), (intptr_t)&tr)<0){
                	perror("WTF!"); return -1; }
        }
	return 0;
}

void spi_emit_break(void) { spi_emit_buf("\x4", 1); } // BREAK CONNECTIONS in each chip AFTER RESET
void spi_emit_fasync(void) { spi_emit_buf("\x5", 1); } // FEED-THROUGH TO NEXT CHIP ASYNCHRONOUSLY (WITHOUT FLIP-FLOP INTERMEDIATE)
void spi_emit_fsync(void) { spi_emit_buf("\x6", 1); } // FEED-THROUGH TO NEXT CHIP SYNCHRONOUSLY (WITH FLIP-FLOP), not used, not working :-(

void spi_emit_buf_reverse(const char *str, unsigned sz) // INTERNAL USE: EMIT REVERSED BYTE SEQUENCE DIRECTLY TO STREAM
{
	unsigned i;
	if (spibufsz[spinow]+sz>= SPIMAXSZ){
                fprintf(stderr,"FATAL: size>SPIMAXSZ [%d+%d>%d]\n",spibufsz[spinow],sz,SPIMAXSZ); exit(-1); }
	for (i = 0; i < sz; i++) { // Reverse bit order in each byte!
		unsigned char p = str[i];
		p = ((p & 0xaa)>>1) | ((p & 0x55) << 1);
		p = ((p & 0xcc)>>2) | ((p & 0x33) << 2);
		p = ((p & 0xf0)>>4) | ((p & 0x0f) << 4);
		spibufwr[spinow][spibufsz[spinow]+i] = p;
	}
	spibufsz[spinow] += sz;
}

void spi_emit_buf(const char *str, unsigned sz) // INTERNAL USE: EMIT BYTE SEQUENCE DIRECTLY TO STREAM
{
	if (spibufsz[spinow]+sz>= SPIMAXSZ){
                fprintf(stderr,"FATAL: size>SPIMAXSZ [%d+%d>%d]\n",spibufsz[spinow],sz,SPIMAXSZ); exit(-1); }
	memcpy(&spibufwr[spinow][spibufsz[spinow]], str, sz);
	spibufsz[spinow] += sz;
}


// TRANSMIT PROGRAMMING SEQUENCE (AND ALSO READ-BACK)
// addr is the destination address in bits (16-bit - 0 to 0xFFFF valid ones)
// buf is buffer to be transmitted, it will go at position spi_getbufsz()+3
// len is length in _bytes_, should be 4 to 128 and be multiple of 4, as smallest
// transmission quantum is 32 bits
void spi_emit_data(unsigned addr, const char *buf, unsigned len)
{
	unsigned char otmp[3];
	if (len < 4 || len > 128){
		perror("len<4 || len>128"); exit(-1); }
	len /= 4;
	otmp[0] = (len - 1) | 0xE0;
	otmp[1] = (addr >> 8)&0xFF; otmp[2] = addr & 0xFF;
	spi_emit_buf((const char*)otmp, 3);
	spi_emit_buf_reverse((const char*)buf, len*4);
}
void config_reg(int cfgreg, int ena)
{
	const unsigned char enaconf[4]={ 0xc1, 0x6a, 0x59, 0xe3 };
	const unsigned char disconf[4]={ 0x00, 0x00, 0x00, 0x00 };
        if (ena) spi_emit_data(0x7000+cfgreg*32, (const char*)enaconf, 4);
        else     spi_emit_data(0x7000+cfgreg*32, (const char*)disconf, 4);
}
void chip_log(int max,int spinow)
{	
	FILE* fp;
	int i,j;
	unsigned buf[18];

	fp=fopen(".chip.log","w");
        for(i=0;i<max;i++){
                memcpy(buf,spibufrd[spinow]+chipoff[spinow][i],sizeof(buf));
                for(j=0;j<18;j++){
                        fprintf(fp,"%08x ",buf[j]);}
                fprintf(fp,"\n");}
        fclose(fp);
}
unsigned char* chip_osc(int fast)
{
	//const unsigned char oscmax[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0x00 }; // valid: 0x01 0x03 0x07 0x0F 0x1F 0x3F 0x7F 0xFF
	//const unsigned char oscmax[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F, 0x00 }; // valid: 0x01 0x03 0x07 0x0F 0x1F 0x3F 0x7F 0xFF
	//const unsigned char oscave[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00 }; // valid: 0x01 0x03 0x07 0x0F 0x1F 0x3F 0x7F 0xFF
	//const unsigned char oscslo[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F, 0x00 }; // valid: 0x01 0x03 0x07 0x0F 0x1F 0x3F 0x7F 0xFF
	//const unsigned char oscmin[8] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // good: 0x1F (97) 0x3F (104) 0x7F (109) // 0xFF (104)
	const unsigned char bits[8]={0x01,0x03,0x07,0x0F,0x1F,0x3F,0x7F,0xFF};
	static unsigned char osc[8];
	int i;

	for(i=0;i<8&&fast>8;i++,fast-=8){
		osc[i]=0xFF;}
	if(i<8 && fast>0 && fast<=8){
		osc[i++]=bits[fast-1];}
	for(;i<8;i++){
		osc[i]=0x00;}
	return osc;
}
int spi_put(hasht mids,datat data,datat* avec,char* chipconf,char* chipfast)
{
	static int fixchip=MAXCHIPS;
	int i,bank=0;

	spinow=-1;
	spmut.lock();
	for(;;){
		if(spibufst[0]==SPIBUF_DONE){
			spinow=0;
			break;}
		if(spibufst[1]==SPIBUF_DONE){
			spinow=1;
			break;}
		if(spibufst[0]==SPIBUF_READY){
			spibufst[0]=SPIBUF_DONE; // overwrite old data with new
			spinow=0;
			break;}
		if(spibufst[1]==SPIBUF_READY){
			spibufst[1]=SPIBUF_DONE; // overwrite old data with new
			spinow=1;
			break;}
		spmut.unlock();
		return 0;} // throw data away
	spmut.unlock();
	spibufsz[spinow] = 0;
	memset(bankoff[spinow],0,sizeof(bankoff)/2);
	memcpy(spimids[spinow],mids,sizeof(hasht));
	memcpy(spidata[spinow],data,sizeof(datat));
	spi_emit_break();
	for(i=0;i<maxchips;i++){ // program all chips
		if(chipbank[i]!=bank){
			assert(bankoff[spinow][bank]==0);
			bankoff[spinow][bank]=spibufsz[spinow];
			bank=chipbank[i];
			spi_emit_break();}
		if(i==fixchip && (chipconf[i] & 0x40 || !chipconf[i])){
			printf("SPI update chip %d \n",i);
			spi_emit_data(0x6000,(const char*)chip_osc((int)chipfast[i]),8); // set speed to minimal
			config_reg(1,(chipconf[i] & 0x02?0:1));  //0 [don't] disable debug step clock [overwrites slow clock]
			config_reg(2,(chipconf[i] & 0x04?1:0));  //0 [don't] enable fast clock [fixed speed]
			config_reg(3,(chipconf[i] & 0x08?0:1));  //0 [don't] disable clock division by 2
			config_reg(4,(chipconf[i] & 0x10?1:0));  //1 [do   ] enable slow clock [???]
			config_reg(6,(chipconf[i] & 0x20?1:0));  //0 [don't] enable clock on OCLK
			config_reg(7,0);  // scan chain disable
			config_reg(8,0);  // scan chain disable
			config_reg(9,0);  // scan chain disable
			config_reg(10,0); // scan chain disable
			config_reg(11,0); // scan chain disable
			if(chipconf[i]){
				spi_emit_data(0x0100,(const char*)counters,16); // program counters
				spi_emit_data(0x1000,(const char*)w1,16*4); // padding for SHA256
				spi_emit_data(0x1400,(const char*)w1,8*4); // padding for SHA256
				spi_emit_data(0x1900,(const char*)w2,8*4); // Prepare MS and W buffers
				chipconf[i] ^= 0x40;}
			oldfast[i]=chipfast[i];
			oldconf[i]=chipconf[i];}
		else{
			if(oldfast[i]!=chipfast[i]){
				//printf("SPI for chip %d: change speed\n",i);
				spi_emit_data(0x6000,(const char*)chip_osc((int)chipfast[i]),8);
				oldfast[i]=chipfast[i];}
			if(oldconf[i]!=chipconf[i]){
				//printf("SPI for chip %d: change config\n",i);
				if((oldconf[i] & 0x02)!=(chipconf[i] & 0x02)) config_reg(1,(chipconf[i] & 0x02?0:1));  //0 [don't] disable debug step clock [overwrites slow clock]
				if((oldconf[i] & 0x04)!=(chipconf[i] & 0x04)) config_reg(2,(chipconf[i] & 0x04?1:0));  //0 [don't] enable fast clock [fixed speed]
				if((oldconf[i] & 0x08)!=(chipconf[i] & 0x08)) config_reg(3,(chipconf[i] & 0x08?0:1));  //0 [don't] disable clock division by 2
				if((oldconf[i] & 0x10)!=(chipconf[i] & 0x10)) config_reg(4,(chipconf[i] & 0x10?1:0));  //1 [do   ] enable slow clock [???]
				if((oldconf[i] & 0x20)!=(chipconf[i] & 0x20)) config_reg(6,(chipconf[i] & 0x20?1:0));  //0 [don't] enable clock on OCLK
				oldconf[i]=chipconf[i];}}
		chipoff[spinow][i]=spibufsz[spinow]+3; // remember position with results
		if(chipconf[i]){ // or completely ignore chip
                	spi_emit_data(0x3000,(const char*)avec[i],19*4);}
                spi_emit_fasync();}
	chipoff[spinow][i]=spibufsz[spinow]; // set last position for speed optimization
	bankoff[spinow][bank]=spibufsz[spinow];
	spmut.lock();
	spibufst[spinow]=SPIBUF_READY;
	spmut.unlock();
	fixchip=(fixchip+1)%maxchips;
	return 1; // data will be uploaded
}
int spi_get(hasht mids,datat data,datat* rvec,char* chipconf)
{
	int i;

        spinow=-1;
	spmut.lock();
        for(;;){
                if(spibufst[0]==SPIBUF_SENT){
			spibufst[1]=SPIBUF_READING;
                        spinow=0;
                        break;}
                if(spibufst[1]==SPIBUF_SENT){
			spibufst[1]=SPIBUF_READING;
                        spinow=1;
                        break;}
                spmut.unlock();
                return 0;} // no new data
        spmut.unlock();
	for(i=0;i<maxchips;i++){
		if(chipconf[i] & 0x7F){ // if not completely ignored
			memcpy(rvec[i],spibufrd[spinow]+chipoff[spinow][i],sizeof(datat));}}
	memcpy(mids,spimids[spinow],sizeof(hasht)); // send back data that was submitted to chips
	memcpy(data,spidata[spinow],sizeof(datat)); // send back data that was submitted to chips
	spmut.lock();
	spibufst[spinow]=SPIBUF_DONE;
	spmut.unlock();
	return 1;
}
void spi_programm(char* chipconf,char* chipfast,int bank,int first, int last)
{
	int i,j;

	spinow=0;
	memset(bankoff[spinow],0,sizeof(bankoff)/2);
	spibufsz[spinow] = 0;
	spi_emit_break();
	for(i=first;i<last && i<MAXCHIPS;i++){ // program all chips
		//spi_emit_data(0x6000,(const char*)oscmax,8); // set speed to minimal
		//spi_emit_data(0x6000,(const char*)oscave,8); // set speed to minimal
		//spi_emit_data(0x6000,(const char*)oscslo,8); // set speed to minimal
		spi_emit_data(0x6000,(const char*)chip_osc((int)chipfast[i]),8); // set speed to minimal
		config_reg(1,(chipconf[i] & 0x02?0:1));  //0 [don't] disable debug step clock [overwrites slow clock]
		config_reg(2,(chipconf[i] & 0x04?1:0));  //0 [don't] enable fast clock [fixed speed]
		config_reg(3,(chipconf[i] & 0x08?0:1));  //0 [don't] disable clock division by 2
		config_reg(4,(chipconf[i] & 0x10?1:0));  //1 [do   ] enable slow clock [???]
		config_reg(6,(chipconf[i] & 0x20?1:0));  //0 [don't] enable clock on OCLK
		config_reg(7,0);  // scan chain disable
		config_reg(8,0);  // scan chain disable
		config_reg(9,0);  // scan chain disable
		config_reg(10,0); // scan chain disable
		config_reg(11,0); // scan chain disable
		spi_emit_data(0x0100,(const char*)counters,16); // program counters
	        spi_emit_data(0x1000,(const char*)w1,16*4); // padding for SHA256
	        spi_emit_data(0x1400,(const char*)w1,8*4); // padding for SHA256
	        spi_emit_data(0x1900,(const char*)w2,8*4); // Prepare MS and W buffers
		chipoff[spinow][i]=spibufsz[spinow]+3; // remember position with results
		spi_emit_data(0x3000,(const char*)data,19*4); //spi_emit_buf("\x0", 4);
		//	spi_emit_fasync(); 
		// reset every time
		printf("set chip %d \r",i+1);
		chipoff[spinow][i+1]=spibufsz[spinow];
		bankoff[spinow][bank]=spibufsz[spinow];
		maxchips=i+1;
		spi_txrx((const char*)spibufwr[spinow],(char*)spibufrd[spinow],spibufsz[spinow],(const unsigned int*)chipoff[spinow],(const unsigned int*)bankoff[spinow]); // must work :-(
		spibufsz[spinow] = 0;
		spi_emit_break();
		for(j=first;j<=i;j++){
			chipoff[spinow][j]=spibufsz[spinow]+3; // remember position with results
			spi_emit_fasync();}
		} // send some data to process
//	chipoff[spinow][i]=spibufsz[spinow];
//	bankoff[spinow][bank]=spibufsz[spinow];
//	maxchips=i;
//	spi_txrx((const char*)spibufwr[spinow],(char*)spibufrd[spinow],spibufsz[spinow],(const unsigned int*)chipoff[spinow],(const unsigned int*)bankoff[spinow]); // must work :-(
	spinow=1;
	memset(bankoff[spinow],0,sizeof(bankoff)/2);
	spibufsz[spinow] = 0;
	spi_emit_break();
	for(i=first;i<last && i<MAXCHIPS;i++){ // check responses from chips
		chipoff[spinow][i]=spibufsz[spinow]+3; // remember position with results
		spi_emit_data(0x3000,(const char*)data,19*4); //spi_emit_buf("\x0", 4);
		spi_emit_fasync();} //spi_emit_buf("\x0", 4);
	chipoff[spinow][i]=spibufsz[spinow];
	bankoff[spinow][bank]=spibufsz[spinow];
	maxchips=i;
	spi_txrx((const char*)spibufwr[spinow],(char*)spibufrd[spinow],spibufsz[spinow],(const unsigned int*)chipoff[spinow],(const unsigned int*)bankoff[spinow]); // check chips now after some work
#ifndef NDEBUG
	chip_log(MAXCHIPS,spinow);
#endif
	maxchips=first;
	for(i=first;i<last && i<MAXCHIPS;i++){ // check responses from chips
		unsigned buf[18];
		memcpy(buf,spibufrd[spinow]+chipoff[spinow][i],sizeof(buf));
		chipoff[0][i]=0; // reset offset
		chipoff[1][i]=0; // reset offset
		for(j=0;j<16;j++){
			if(buf[j]!=0xFFFFFFFF && buf[j]!=0x00000000){
				chipbank[i]=bank;
				maxchips=i+1;
				break;}}}
	for(i=first;i<maxchips;i++){
		chipbank[i]=bank;}

}
int spi_start(char* chipconf,char* chipfast)
{
        Thread *spt=new SpitalkThread();

	//ms3_compute(data);
	spi_init();
#if (VERSION==1)
	spi_programm(chipconf,chipfast,0,0,MAXCHIPS);
#else
	if(!maxchips){
		int b=1;
		for(;b<=MAXBANKS;b++){
			int c,i=0;
			for(c=maxchips;c<maxchips+BANKCHIPS && c<MAXCHIPS;c++,i++){
				//chipspis[c]=int(1000000.0/(100.0*b+50.0*(i+1)))*1000;}
				chipspis[c]=625000;}
			spi_reset(64,b);
			spi_programm(chipconf,chipfast,b,maxchips,maxchips+BANKCHIPS);}
		spi_reset(8,0);}
#endif
	memcpy(oldconf,chipconf,MAXCHIPS);
	memcpy(oldfast,chipfast,MAXCHIPS);
        spt->Start();
	return(maxchips);
}

/* -------------------------------- spitalk -----------------------------------*/

void SpitalkThread::Run()
{	int i,talk,wait;
	static timeval start,stop;

	while(!testCancel()) {
		spmut.lock();
		for(i=0;i<2;i++){
			if(spibufst[i]==SPIBUF_READY){
				spibufst[i]=SPIBUF_SENDING;
				spmut.unlock();
				talk=i;
				gettimeofday(&start,NULL);
				break;}}
		if(i>=2){
			spmut.unlock();
			gettimeofday(&stop,NULL);
			wait=1000000*(stop.tv_sec-start.tv_sec)+stop.tv_usec-start.tv_usec;
			if(start.tv_sec && wait>1600000){
				printf("SPI WAITING %.3f sec\r",(float)wait/1000000.0);}
			threads_sleep(100);
			continue;}
		spi_txrx((const char*)spibufwr[talk],(char*)spibufrd[talk],spibufsz[talk],(const unsigned int*)chipoff[talk],(const unsigned int*)bankoff[talk]);
		gettimeofday(&stop,NULL);
		wait=1000000*(stop.tv_sec-start.tv_sec)+stop.tv_usec-start.tv_usec;
		if(wait<800000){
			threads_sleep((800000-wait)/1000);}
		if(wait>1600000){
			printf("SPI SENDING %.3f sec\n",(float)wait/1000000.0);}
#ifndef NDEBUG
		chip_log(MAXCHIPS,talk);
#endif
		spmut.lock();
		spibufst[talk]=SPIBUF_SENT;
		spmut.unlock();
		}
}
