#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <ctime>
#include <string>
#include <iostream>
#include <netinet/tcp.h>
// #include <thread>
using namespace std;
const int keyLen=512;
struct HEXnum{		//定义大数为0到2的keyLen次方-1 
	bool num[keyLen];
};
HEXnum p;
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
void sendHEX(int client_socket,HEXnum x,char c){		//传送大整数 
	char buffer[keyLen+2];
	printf("\n传送字符串："); 
	buffer[0]=c;
	for(int i=0;i<keyLen;i++)
	{
		buffer[i+1]=x.num[i]+'0';
		putchar(buffer[i+1]);
	}
	printf("\n"); 
	buffer[keyLen+1]='\0';
	send(client_socket,buffer,keyLen+1,MSG_DONTWAIT);
	usleep(200000);
	return;
}

HEXnum recvHEX(int client_socket){		//接收大整数 
	
	char buffer[keyLen+1];
	int r=recv(client_socket,buffer,keyLen+1,0);
	if(r<=0) printf("error!!\n");
	HEXnum ret;
	printf("\n接收字符串："); 
	for(int i=0;i<keyLen;i++)
	{
		ret.num[i]=buffer[i+1]-'0';
		putchar(buffer[i+1]);
	}
	printf("\n");
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
	cout<<"消息验证码:\n"<<numToString(mac)<<endl; 
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
	cout<<ret<<endl;
	for(int i=0;i<4;i++) for(int j=0;j<4;j++) mac[j][i]^=h[j][i];
	int mac_[4][4];
	hexToNum(mac_,s+strlen(s)-32);		//取出尾部MAC进行消息验证 
	for(int i=0;i<4;i++) for(int j=0;j<4;j++)	
		if(mac[j][i]!=mac_[j][i])
			return "";	//返回空表示消息被篡改 
	return ret;
	
}



void serverAffair(int client_socket){
    // unsigned long long prime_list[5]={9223372036855430071ull,9223372037701984247ull} ;
	srand(time(0));
	
	// while(1){		//每进行5次通话周期性更换密钥
		HEXnum g=recvHEX(client_socket);
		p=recvHEX(client_socket);
		HEXnum X=recvHEX(client_socket);

		HEXnum y=randHEX(toHEX(2),p-toHEX(2));
		HEXnum Y=hpow(g,y);
		sendHEX(client_socket,Y,'Y');
		
		HEXnum k1,k2=hpow(X,y);
		sendHEX(client_socket,k2,'K');
		k1=recvHEX(client_socket);
		
		if(k1==k2) printf("对称密钥正确，身份验证成功!!\n");
		else printf("对称密钥错误，身份验证失败!!\n");
		for(int i=0;i<16;i++)for(int j=0;j<16;j++) xobS[Sbox[i][j]>>4][Sbox[i][j]&15]=i*16+j;
		for(int i=1;i<=5;i++){
			char buffer[4096]={0};
			recv(client_socket,buffer,4096,0);
			printf("接收到密文:%s\n",buffer);
			string ret=decoding(buffer,k1);
			if(ret==""){
				printf("消息被篡改！！\n");
			}
			cout<<ret<<endl;
			if(ret=="exit"){
				close(client_socket);
				return;
			}
		}	
	// }
	
	
	close(client_socket);

}
int main()
{

	//创建套接字
	int server_socket = socket(AF_INET, SOCK_STREAM, 0);
	int flag = 1;
	setsockopt(server_socket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));
    printf("%d\n",server_socket);
	if (server_socket == -1)
	{
		printf("套接字创建失败！\n");
		exit(-1);
	}

    // 绑定端口
	struct sockaddr_in local= { 0 };
	local.sin_family = AF_INET;
	local.sin_port = htons(8080);
	local.sin_addr.s_addr = htonl(INADDR_ANY);

	// 绑定socket和端口
	if (bind(server_socket, (struct sockaddr*)&local, sizeof(struct sockaddr_in)) == -1)
	{
		printf("socket绑定失败！\n");
		exit(-1);
	}

	// 监听这个端口
	if (listen(server_socket, 10) == -1)
	{
		printf("socket监听失败!\n");
		exit(-1);
	}
    
	printf("套接字创建成功，等待客户端连接...\n");
    

	while (1)
	{
		int client_socket = accept(server_socket, NULL, NULL);
		setsockopt(client_socket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));
        if(client_socket==-1)
        {
            printf("客户端连接失败!\n");
            continue;
        }
        else printf("%d号客户端成功连接!\n",client_socket);
		// thread t(serverAffair, client_socket);
        serverAffair(client_socket);
       
       
		
	}
	return 0;
}
