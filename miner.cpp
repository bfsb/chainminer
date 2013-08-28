#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <miner.h>
#include <math.h>
#include <sys/time.h>
#include <assert.h>

#define rotrFixed(x,y) (((x) >> (y)) | ((x) << (32-(y))))
#define s0(x) (rotrFixed(x,7)^rotrFixed(x,18)^(x>>3))
#define s1(x) (rotrFixed(x,17)^rotrFixed(x,19)^(x>>10))
#define Ch(x,y,z) (z^(x&(y^z)))
#define Maj(x,y,z) (y^((x^y)&(y^z)))
#define S0(x) (rotrFixed(x,2)^rotrFixed(x,13)^rotrFixed(x,22))
#define S1(x) (rotrFixed(x,6)^rotrFixed(x,11)^rotrFixed(x,25))
#define blk0(i) (W[i] = data[i])
#define blk2(i) (W[i&15]+=s1(W[(i-2)&15])+W[(i-7)&15]+s0(W[(i-15)&15]))
#define a(i) T[(0-i)&7]
#define b(i) T[(1-i)&7]
#define c(i) T[(2-i)&7]
#define d(i) T[(3-i)&7]
#define e(i) T[(4-i)&7]
#define f(i) T[(5-i)&7]
#define g(i) T[(6-i)&7]
#define h(i) T[(7-i)&7]
#define R(i) h(i)+=S1(e(i))+Ch(e(i),f(i),g(i))+SHA_K[i+j]+(j?blk2(i):blk0(i));d(i)+=h(i);h(i)+=S0(a(i))+Maj(a(i),b(i),c(i))

static datat avec[MAXCHIPS]; // input data for hashing: midstate[8], ms3[8], data,ntime,bits
static datat rvec[MAXCHIPS]; // returned hashing results: nonce[16], jobsel
static datat ovec[MAXCHIPS]; // perviously returned hashing results (rvec)
static hasht chipmids[MAXCHIPS]; // currently processed midstate on this chip
static datat chipdata[MAXCHIPS]; // currently processed data on this chip: data[19]
static int   chipbusy[MAXCHIPS]; // currently busy retvector slot (0-15)
static int   chipgood[MAXCHIPS][16]; // for each slot correct answers, calculated every 15 min 
static int   chipmiss[MAXCHIPS][16]; // for each slot wrong answers, calculated every 15 min 
static int   chiphash[MAXCHIPS]; // hashing speed based on jobsel toggle
static int   chipespi[MAXCHIPS]; // spi errors, maybe each slot should be reported
static int   chipmiso[MAXCHIPS]; // miso errors
static char  chipfast[MAXCHIPS]; // speed set for each chip
static char  chipconf[MAXCHIPS]; // [AIFDSOX] (bits[1:7]) auto,iclk,fast,divide,slow,oclk,fix , if ==0, no reading of data from chip
static int   chipcoor[MAXCHIPS][21][36]; // nonces found in each core
static int job=0; // number of jobs sent to chips

/* SHA256 CONSTANTS */
const unsigned sha_initial_state[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
const unsigned SHA_K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

void SHA256_Full(unsigned *state, unsigned *data, const unsigned *st)
{
        unsigned W[16];
        unsigned T[8];
        unsigned j;

        T[0] = state[0] = st[0]; T[1] = state[1] = st[1]; T[2] = state[2] = st[2]; T[3] = state[3] = st[3];
        T[4] = state[4] = st[4]; T[5] = state[5] = st[5]; T[6] = state[6] = st[6]; T[7] = state[7] = st[7];
        j = 0;
        for (j = 0; j < 64; j+= 16) { R(0); R(1);  R(2); R(3); R(4); R(5); R(6); R(7); R(8); R(9); R(10); R(11); R(12); R(13); R(14); R(15); }
        state[0] += T[0]; state[1] += T[1]; state[2] += T[2]; state[3] += T[3];
        state[4] += T[4]; state[5] += T[5]; state[6] += T[6]; state[7] += T[7];
}

void ms3_compute(unsigned *p)
{
        unsigned a,b,c,d,e,f,g,h, ne, na,  i;

        a = p[0]; b = p[1]; c = p[2]; d = p[3]; e = p[4]; f = p[5]; g = p[6]; h = p[7];
        for (i = 0; i < 3; i++) {
                ne = p[i+16] + SHA_K[i] + h + Ch(e,f,g) + S1(e) + d;
                na = p[i+16] + SHA_K[i] + h + Ch(e,f,g) + S1(e) + S0(a) + Maj(a,b,c);
                d = c; c = b; b = a; a = na;
                h = g; g = f; f = e; e = ne;
        }
        p[15] = a; p[14] = b; p[13] = c; p[12] = d; p[11] = e; p[10] = f; p[9] = g; p[8] = h;
}
unsigned dec_nonce(unsigned in)
{
        unsigned out;
        /* First part load */
        out = (in & 0xFF) << 24; in >>= 8;
        /* Byte reversal */
        in = (((in & 0xaaaaaaaa) >> 1) | ((in & 0x55555555) << 1));
        in = (((in & 0xcccccccc) >> 2) | ((in & 0x33333333) << 2));
        in = (((in & 0xf0f0f0f0) >> 4) | ((in & 0x0f0f0f0f) << 4));
        out |= (in >> 2)&0x3FFFFF;
        /* Extraction */
        if (in & 1) out |= (1 << 23);
        if (in & 2) out |= (1 << 22);
        out -= 0x800004;
        return out;
}
int test_nonce(unsigned tnon,hasht mids,datat data,hasht hash,uint32_t* pwdata,uint32_t* pwhash,int chip,int busy,int x,int y)
{
	static uint32_t dtmp[32]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0x80000000,0,0,0,0,0,0,0,0,0,0,0x280};
        unsigned int dd[16];

        memset(hash,0,sizeof(hasht));
        memset(dd,0,sizeof(dd));
        dd[0] = data[16]; dd[1] = data[17]; dd[2] = data[18]; dd[3] = tnon; dd[4] = 0x80000000; dd[15] = 0x280;
        SHA256_Full(hash, dd, mids);
        memset(dd, 0, sizeof(dd));
        memcpy(dd, hash, 4*8);
        dd[8] = 0x80000000; dd[15] = 0x100;
        SHA256_Full(hash, dd, sha_initial_state);
	if(hash[7] != 0){
		return(0);}
	memcpy(dtmp,data,sizeof(datat));
	dtmp[19]=tnon;
	memcpy(pwdata,dtmp,sizeof(dtmp));
	memcpy(pwhash,hash,sizeof(hasht));
	if(x>4){
		x-=3;}
	assert(x>=0 && x<21);
	assert(y>=0 && y<36);
	chipcoor[chip][x][y]++;
	chipgood[chip][busy]++;
	//printf("FOUND: %08x (%08x) mod %d chip %d [old] [%d,%d]  \r",tnon,newn,2,chip+1,x,y);
	//fp=fopen("/tmp/good.log","a");
	//fprintf(fp,"%d\t%d\t%d\t2\n",chip+1,x,y);
	//fclose(fp);
	return 1;
}

int fix_nonce(uint32_t newn,uint32_t old,hasht mids1,datat data1,hasht mids2,datat data2,int change,int chip,int job,int busy,uint32_t* pwdata,uint32_t* pwhash)
{
	//FILE *fp;
	//int mod[6]={0,-0x400000,-0x800000,0x2800000,0x2C00000,0x400000};
	//int mod[3]={0,-0x800000,-0x400000};
	hasht hash;
	uint32_t nonce=dec_nonce(newn);
	uint32_t tnon;
	uint32_t coor;
	int x;
	int y;

	if((newn & 0xff)<0x1c){ // was 0x20
		tnon=nonce-0x400000; //+mod[2];
		coor=((tnon>>29) & 0x07)|(((tnon)>>19) & 0x3F8);
		x=coor%24;
		y=coor/24;
		//should test for bad coordinate and return if bad;
		if(y<36){ // 3 out of 24 cases
			if(test_nonce(tnon,mids1,data1,hash,pwdata,pwhash,chip,busy,x,y)){
				return 1;}
			if(change && test_nonce(tnon,mids2,data2,hash,pwdata,pwhash,chip,busy,x,y)){
				return 1;}}}
	else{
		tnon=nonce; // mod[0]
		coor=((tnon>>29) & 0x07)|(((tnon)>>19) & 0x3F8);
		x=coor%24;
		y=coor/24;
		if(x>=17 && y<36){ // this or mod[1] , 7 out of 24 cases
			if(test_nonce(tnon,mids1,data1,hash,pwdata,pwhash,chip,busy,x,y)){
				return 1;}
			if(change && test_nonce(tnon,mids2,data2,hash,pwdata,pwhash,chip,busy,x,y)){
				return 1;}}
		tnon=nonce-0x800000; // +mod[1];
		coor=((tnon>>29) & 0x07)|(((tnon)>>19) & 0x3F8);
		x=coor%24;
		y=coor/24;
		if(((x>=1 && x<=4)||(x>=9 && x<=15)) && y<36){ // 11 out of 24 cases
			if(test_nonce(tnon,mids1,data1,hash,pwdata,pwhash,chip,busy,x,y)){
				return 1;}
			if(change && test_nonce(tnon,mids2,data2,hash,pwdata,pwhash,chip,busy,x,y)){
				return 1;}}}
	chipmiss[chip][busy]++;
#ifndef NDEBUG
	if(chipconf[chip] & 0x10){
		printf("ERROR: nonce %08x=>%08x (old %08x) on chip %d (job:%d,slot:%d) not mapped  \n",newn,nonce,old,chip+1,job,busy);}
	else{
		printf("ERROR: nonce %08x=>%08x (old %08x) on chip %d (job:%d,slot:%d) not mapped  \n",newn,nonce,old,chip+1,job,busy);}
#endif
	//fp=fopen(".error.log","a");
	//fprintf(fp,"%d\t%d\t%08x\t%08x\n",chip,busy,newn,nonce);
	//fclose(fp);
	return 0;
}
void cpu_miner()
{	uint32_t nonce,data[32],hash1[16];
	hasht mids;
	hasht hash;
	int i;

	if(!get_work(mids,data)){
		return;}
	//if(mids[0]==0){ // remove
	//	SHA256_Full(mids,data,sha_initial_state);}
	nonce=rand();
      	for(i=0;i<1000000;i++) {
		data[16+3]= ++nonce;
		memset(hash1,0,64);
		hash1[8]=0x80000000;
		hash1[15]=0x100;
		SHA256_Full(hash1,data+16,mids);
		SHA256_Full(hash,hash1,sha_initial_state);
		if (hash[7] == 0) {
			printf("\nFOUND_NONCE: %08x\n",nonce);
			put_work(data,hash);
			return;}}
}

void spi_miner(int chips,char* chipconf,char* chipfast)
{	
	static hasht midsdo={0,0,0,0,0,0,0,0};
	static datat datado;
	uint32_t otime,ntime,data[32];
	hasht mids={0,0,0,0,0,0,0,0};
	int c,j,wait;
        static timeval start,stop;

	if(!get_work(mids,data)){
		return;}
	//if(mids[0]==0){ // remove
	//	SHA256_Full(mids,data,sha_initial_state);}
	
	gettimeofday(&start,NULL);
	// prepare submission
	otime=data[17];
	ntime=data[17];
	byte_reverse((uint8_t*)&ntime);
	for(c=0;c<chips;c++,ntime++){ // ntime roll
		if(c){
			data[17]=ntime;
			byte_reverse((uint8_t*)(data+17));}
		memcpy(avec[c],mids,sizeof(hasht));
		memcpy(avec[c]+16,data+16,sizeof(uint32_t)*3);
		ms3_compute(avec[c]);} // input ready
	data[17]=otime;
	spi_put(mids,data,avec,chipconf,chipfast); // put chip input data in spi communication buffer
	if(spi_get(mids,data,rvec,chipconf)){ // get midstate and data sent to chips and results from chips
		int non=0,err=0,spi=0,mis=0,miso=0;
		ntime=datado[17];
		byte_reverse((uint8_t*)&ntime);
		for(c=0;c<chips;c++,ntime++){ // ntime roll
			int match=0;
			int change=0;
			int busy=chipbusy[c];
			int newbusy=chipbusy[c];

			if(!chipconf[c]){ // prevent resetting miso
				continue;}
			for(j=1;j<16;j++){
				if(rvec[c][(busy+j)%16]!=ovec[c][(busy+j)%16]){
					newbusy=(busy+j)%16;}
				else{
					match++;}}
			if(!match){
				if(!miso){
					mis++;
					chipmiso[c]++;}
				miso=1; // remember last chips miso error state
				continue;}
			miso=0;
			if(rvec[c][17]!=0xFFFFFFFF && rvec[c][17]!=0x00000000){//log communication error
				spi++;
				chipespi[c]++;
#ifndef NDEBUG
				printf("SPI ERROR on chip %d (%08x)  \n",c+1,rvec[c][17]);
#endif
				}
			if(rvec[c][17]!=ovec[c][17]){ //job changed, need to check data for old and "datado"
				if(c){
					datado[17]=ntime;
					byte_reverse((uint8_t*)(datado+17));}
				chiphash[c]++;
				change=1;}
			for(;newbusy!=busy;busy=(busy+1)%16){ // got nonce (!)
				uint32_t pwdata[32];
				hasht pwhash;
				if(chipmids[c][0]==0 && chipdata[c][0]==0){
					continue;}
				if(rvec[c][busy]==0xFFFFFFFF || rvec[c][busy]==0x00000000){ // probably a wrong nonce
					rvec[c][busy]=ovec[c][busy];
					spi=1;
					continue;}
				if(rvec[c][busy]==ovec[c][busy]){ // already tested
					spi=1;
					continue;}
				if(fix_nonce(rvec[c][busy],ovec[c][busy],chipmids[c],chipdata[c],midsdo,datado,change,c,job,busy,pwdata,pwhash)){
					non++;
					put_work(pwdata,pwhash);}
				else{
					err++;}}
			mis+=miso;
			chipmiso[c]+=miso;
			chipbusy[c]=busy;
			if(change){ // set new processed data for the chip
				memcpy(chipmids[c],midsdo,sizeof(hasht));
				memcpy(chipdata[c],datado,sizeof(datat));}}
		// data form buffer was sent to chips
		memcpy(midsdo,mids,sizeof(hasht));
		memcpy(datado,data,sizeof(datat));
		memcpy(ovec,rvec,sizeof(datat)*chips);
		gettimeofday(&stop,NULL);
		wait=1000000*(stop.tv_sec-start.tv_sec)+stop.tv_usec-start.tv_usec;
		job++;
		printf("JOB %d PROCESSED %.3f sec [nonces:%d, errors:%d, spi:%d miso:%d] (queue:%d)  \n",job,(float)wait/1000000.0,non,err,spi,mis,put_queue());}
}
char* chip_conf(char conf)
{
	static char str[6];
	str[0]=(conf & 0x01?'A':'a');
	str[1]=(conf & 0x02?'I':'i');
	str[2]=(conf & 0x04?'F':'f');
	str[3]=(conf & 0x08?'D':'d');
	str[4]=(conf & 0x10?'S':'s');
	str[5]=(conf & 0x20?'O':'o');
	return str;
}
char conf_chip(char* conf)
{
	return
		(conf[0]=='A'?0x01:0x00) |
		(conf[1]=='I'?0x02:0x00) |
		(conf[2]=='F'?0x04:0x00) |
		(conf[3]=='D'?0x08:0x00) |
		(conf[4]=='S'?0x10:0x00) |
		(conf[5]=='O'?0x20:0x00);
}
void chip_init()
{	FILE* fp=fopen(".chip.cnf","r");
	char buf[256],conf[6];
	int c,num,fast;

	if(fp==NULL){
		for(c=0;c<MAXCHIPS;c++){
			chipconf[c]=0x01 | 0x02 | 0x08 | 0x10; // auto adjust, iclk (conf bug), no fast clock, divide by 2, slow clock, no oclk
			chipfast[c]=DEFSPEED;}
		return;}
	for(c=0;c<MAXCHIPS && fgets(buf,256,fp)!=NULL;c++){
		if(buf[0]>57){ //hashrate line
			break;}
		sscanf(buf,"%d%*c%6c%d",&num,conf,&fast);
		if(!num){
			break;}
		if(num!=c+1){
			fprintf(stderr,"FATAL, format error in line %d:\n%s",c+1,buf);
			exit(-1);}
		chipconf[c]=conf_chip(conf);
		chipfast[c]=fast;}
		//printf("SET CHIP: %d\t%6.6s\t%d [%d,%6.6s,%d]\n",c+1,chip_conf(chipconf[c]),chipfast[c],num,conf,fast);}
	for(;c<MAXCHIPS;c++){
		chipconf[c]=0x01 | 0x02 | 0x08 | 0x10; // auto adjust, iclk (conf bug), no fast clock, divide by 2, slow clock, no oclk
		chipfast[c]=DEFSPEED;}
}
void chip_stat(int chips)
{	static uint32_t ctime=0;
	static int first=0;
	static int last=0;
	int speed=0;
	int nrate=0;
	int hrate=0;
	int error=0;
	int espi=0;
	int miso=0;
	int wait=0;
	static float record=0.0;
	extern char chipbank[MAXCHIPS+1];
	char chipchange[MAXCHIPS]; // 1=up,2=down,3=to0,4=shut,5=off

	memset(chipchange,0,sizeof(chipchange));
	if(!ctime){
		first=1;
		ctime=time(NULL);
		return;}
	wait=time(NULL)-ctime;
	if(first || wait>=5*60){
		float ok,total,nr,hr;
		FILE* fp=fopen(".stat.log","w");
		
		int c,j,b=0,lb=0,x,y;
		const char board[MAXBOARDS+1]="0123456789ABCDEF";
		int b_speed[MAXBOARDS]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		int b_nrate[MAXBOARDS]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		int b_hrate[MAXBOARDS]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		int b_error[MAXBOARDS]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		int b_espi[MAXBOARDS]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		int b_miso[MAXBOARDS]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
		for(c=0;c<chips;c++){
			int good=0,miss=0,badc=0;
			for(j=0;j<16;j++){
				good+=chipgood[c][j];
				miss+=chipmiss[c][j];}
			speed+=chipfast[c];
			nrate+=good;
			hrate+=chiphash[c];
			error+=miss;
			espi+=chipespi[c];
			miso+=chipmiso[c];
			if(!chipbank[c]){
				b=c/16;}
			else{
				if(chipbank[c]!=chipbank[lb]){
					lb=c;}
				b=4*(chipbank[lb]-1)+(c-lb)/16;}
			b_speed[b]+=chipfast[c];
			b_nrate[b]+=good;
			b_hrate[b]+=chiphash[c];
			b_error[b]+=miss;
			b_espi[b]+=chipespi[c];
			b_miso[b]+=chipmiso[c];
			ok=(double)0xFFFFFFFF/1000000000.0*(double)good/(double)wait;
			total=(double)0xFFFFFFFF/1000000000.0*(double)chiphash[c]/(double)wait*(double)756/(double)1024;
			for(x=0;x<21;x++){
				for(y=0;y<36;y++){
					if(!chipcoor[c][x][y]){ // bad core calculation
						badc++;}}}
			fprintf(fp,"%d\t%6.6s\t%d\t%.3f\t%.3f\t%d\t%d\t%d\t%d\t%d\t[%c:%c]\t%d\t",
				c+1,chip_conf(chipconf[c]),chipfast[c],ok,total,good,miss,chipespi[c],chipmiso[c],chiphash[c],board[b],board[(c-lb)%16],badc);
			for(j=0;j<16;j++){
				fprintf(fp,"%d ",chipgood[c][j]);}
			fprintf(fp,"\t");
			for(j=0;j<16;j++){
				fprintf(fp,"%d ",chipmiss[c][j]);}
			if(!first && chipconf[c]){
				if(good<MINGOOD || miss>MAXERROR*2 || (chipconf[c] & 0x80)){ // fix chip
					chipconf[c] = 0xc0|(chipconf[c] & 0x3F);} // toggle fix signal
				else{
					chipconf[c] &= 0x7F;}} // toggle fix signal
			if(!first && (chipconf[c] & 0x01) && (chipconf[c] != 0x01)){ // tune chips
				if(miss>good || good==0){
					if(chipfast[c]>DEFSPEED){ // set speed to 0
						chipchange[c]=2;
						//fprintf(hp,"TUNE chip %d: slow down to %d  \n",c+1,chipfast[c]-1);
						fprintf(fp,"\tspeed down\n");
						chipfast[c]--;
						continue;}
					if(chipfast[c] && good<=chiphash[c]*0.5){ // set speed to 0
						chipchange[c]=3;
						//fprintf(hp,"TUNE chip %d: set speed to 0  \n",c+1);
						fprintf(fp,"\tspeed->0\n");
						chipfast[c]=0;
						continue;}
					if(miss>100 && !good && (chipconf[c]&0x3E)){ // chut down chip
						chipchange[c]=4;
						//fprintf(hp,"TUNE chip %d: shut down  \n",c+1);
						fprintf(fp,"\tshut down\n");
						chipconf[c]&=0x01;
						continue;}
					if((chipmiso[c]>10 && !good) || badc==756){
						chipchange[c]=5;
						//fprintf(hp,"TUNE chip %d: turn off  \n",c+1);
						fprintf(fp,"\tturn off\n");
						chipconf[c]=0;
						continue;}
					fprintf(fp,"\n");
					continue;}
				if(!miss && ok>total && chipfast[c]<MAXSPEED){
					chipchange[c]=1;
					//fprintf(hp,"TUNE chip %d: speed up to %d  \n",c+1,chipfast[c]+1);
					fprintf(fp,"\tspeed up\n");
					if(chipfast[c]<MINSPEED){
						chipfast[c]=MINSPEED;}
					else{
						chipfast[c]++;}
					continue;}
				if(miss>MAXERROR && chipfast[c]>MINSPEED && good<chiphash[c]){
					chipchange[c]=2;
					//fprintf(hp,"TUNE chip %d: slow down to %d  \n",c+1,chipfast[c]-1);
					fprintf(fp,"\tspeed down\n");
					chipfast[c]--;
					continue;}}
			fprintf(fp,"\n");}
		nr=(double)0xFFFFFFFF/1000000000.0*(double)nrate/(double)wait;
		hr=(double)0xFFFFFFFF/1000000000.0*(double)hrate/(double)wait*(double)756/(double)1024;
		fprintf(fp,"speed:%d noncerate[GH/s]:%.3f (%.3f/chip) hashrate[GH/s]:%.3f good:%d errors:%d spi-errors:%d miso-errors:%d jobs:%d (record[GH/s]:%.3f)\n",
			speed,nr,(nr/chips),hr,nrate,error,espi,miso,job-last,record);
		for(b=0;b<MAXBOARDS;b++){
			if(b_speed[b]){
				fprintf(fp,"%c:\t%d\t%.3f\t%.3f\t%d\t%d\t%d\t%d\n",board[b],b_speed[b],
					(double)0xFFFFFFFF/1000000000.0*(double)b_nrate[b]/(double)wait,
					(double)0xFFFFFFFF/1000000000.0*(double)b_hrate[b]/(double)wait*(double)756/(double)1024,
					b_nrate[b],b_error[b],b_espi[b],b_miso[b]);}}
		fclose(fp);


		FILE* fp_json=fopen("stat.json","w");
		fprintf(fp_json,"{ \"stats\": \n {");
		fprintf(fp_json,"\"speed\": %d, \"noncerate\": %.3f, \"noncerateperchip\":%.3f, \"hashrate\":%.3f, \"good\":%d, \"errors\":%d, \"spi-errors\":%d, \"miso-errors\":%d, \"jobs\":%d, \"record\":%.3f\n",
			speed,nr,(nr/chips),hr,nrate,error,espi,miso,job-last,record);
		fprintf(fp_json,",\"boards\": [");
		int firstboard = 0;
		for(b=0;b<MAXBOARDS;b++){
			if(b_speed[b]){
				if (firstboard > 0)
					fprintf(fp_json,",");
				fprintf(fp_json,"\n{ ");
				fprintf(fp_json,"\"slot\": \"%c\", \"speed\": %d, \"noncerate\":%.3f, \"hashrate\": %.3f, \"good\": %d, \"errors\": %d, \"spi-errors\": %d, \"miso-errors\":%d",board[b],b_speed[b],
						(double)0xFFFFFFFF/1000000000.0*(double)b_nrate[b]/(double)wait,
						(double)0xFFFFFFFF/1000000000.0*(double)b_hrate[b]/(double)wait*(double)756/(double)1024,
						b_nrate[b],b_error[b],b_espi[b],b_miso[b]);
				fprintf(fp_json," }\n");
				firstboard = 1;
			}
		}
		fprintf(fp_json,"\n ]");			
		fprintf(fp_json,"\n } }");
		fclose(fp_json);

		if(!first){
			int c,d=0,x,y;
			FILE* hp=fopen("/tmp/.hash.log","a");
			fprintf(hp,"speed:%d noncerate[GH/s]:%.3f (%.3f/chip) hashrate[GH/s]:%.3f good:%d errors:%d spi-errors:%d miso-errors:%d jobs:%d (record[GH/s]:%.3f)\n",
				speed,nr,(nr/chips),hr,nrate,error,espi,miso,job-last,record);
			for(c=0;c<chips;c++){
				switch(chipchange[c]){
					case 1: fprintf(hp,"%d:up ",c+1); d++; break;
					case 2: fprintf(hp,"%d:down ",c+1); d++; break;
					case 3: fprintf(hp,"%d:to0 ",c+1); d++; break;
					case 4: fprintf(hp,"%d:shut ",c+1); d++; break;
					case 5: fprintf(hp,"%d:off ",c+1); d++; break;
					default: break;}}
			if(d){
				fprintf(hp,"\n");}
			fclose(hp);
			hp=fopen("/tmp/.core.log","w");
			for(c=0;c<chips;c++){
				d=0;
				for(y=35;y>=0;y--){
					fprintf(hp,"%d\t",c+1);
					for(x=0;x<21;x++){
						if(!chipcoor[c][x][y]){
							d++;}
						fprintf(hp," %3d",chipcoor[c][x][y]);}
					fprintf(hp,"\n");}
				fprintf(hp,"%d\t%d\n\n",c+1,d);}
			fclose(hp);
			if(record<nr){
				record=nr;
				system("/bin/cp -f .stat.log /tmp/.best.log");}}
		if(wait>=5*60){
			ctime=time(NULL);
			memset(chipgood,0,sizeof(chipgood));
			memset(chipmiss,0,sizeof(chipmiss));
			memset(chiphash,0,sizeof(chiphash));
			memset(chipespi,0,sizeof(chipespi));
			memset(chipmiso,0,sizeof(chipmiso));
			last=job;
			first=0;}}
}
int main()
{	int chips=0;

	get_start();
	put_start();
	chip_init();
	chips=spi_start(chipconf,chipfast);
	printf("INIT: %d chips detected\n",chips);

	for (;;) {
		spi_miner(chips,chipconf,chipfast); // same as cpu_miner();
		chip_stat(chips);
	}

	spi_close();
	return 0;
}

