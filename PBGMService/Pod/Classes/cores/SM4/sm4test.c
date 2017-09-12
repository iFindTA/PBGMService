/*
 * SM4/SMS4 algorithm test programme
 * 2012-4-21
 */

#include <string.h>
#include <stdio.h>
#include "sm4.h"
#include "sm4test.h"
int mainTest4()//mainTest4
{
    unsigned char key[16] ;//= {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    unsigned char input[16] ;//= {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
	unsigned char output[16];
	sm4_context ctx;
	unsigned long i;

	//encrypt standard testing vector
	sm4_setkey_enc(&ctx,key);
	sm4_crypt_ecb(&ctx,1,16,input,output);
	for(i=0;i<16;i++)
		printf("%02x ", output[i]);
	printf("\n");

	//decrypt testing
	sm4_setkey_dec(&ctx,key);
	sm4_crypt_ecb(&ctx,0,16,output,output);
	for(i=0;i<16;i++)
		printf("%02x ", output[i]);
	printf("\n");

	//decrypt 1M times testing vector based on standards.
	i = 0;
	sm4_setkey_enc(&ctx,key);
	while (i<1000000) 
    {
		sm4_crypt_ecb(&ctx,1,16,input,input);
		i++;
    }
	for(i=0;i<16;i++)
		printf("%02x ", input[i]);
	printf("\n");
	
    return 0;
}
void testEncodejiami(unsigned long lenght,unsigned char in[], unsigned char output[]){
    
    // 1   10进制
    //043  8进制
    //0x45  16进制
    unsigned char iv[16]   = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    //unsigned char key[16]   = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    unsigned char key[16] = "1234567890abcdef";
    sm4_context ctx;
    //设置上下文和密钥
    sm4_setkey_enc(&ctx,key);
    //加密
    //sm4_crypt_ecb(&ctx,1,lenght,in,output);
    sm4_crypt_cbc(&ctx, 1, lenght, iv, in, output);
}
void testDecodejiemi(unsigned long lenght, unsigned char in[], unsigned char output[]){
    unsigned char iv[16]   = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    //unsigned char key[16]   = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    unsigned char key[16] = "1234567890abcdef";
    sm4_context ctx;
    //设置上下文和密钥
    sm4_setkey_dec(&ctx,key);
    //解密
    //sm4_crypt_ecb(&ctx,0,lenght,in,output);
    sm4_crypt_cbc(&ctx, 0, lenght, iv, in, output);
}

