/*
 * test proj for sm2lib
 * simon pang 2012
 *
 */

#include "sm2.h"
#include "tommath.h"


int test_Ecc_Intrfs_sig_veri()
{
	printf("\n********\n* Ecc interface signature and verify test\n********\n");
	printf("...you can check the route on \"Public Key Cryptographic Algorithm SM2 Based on Elliptic Curves\" page [57]...\n");
	printf("...to check, please make sure that the sm2lib is a debug version, make it under \'-D_DEBUG\' when compile...\n\n\n");
	char rand_k[] = "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F";
	char dgst[]   = "B524F552CD82B8B028476E005C377FB19A87E6FC682D48BB5D42E3D9B9EFFE76";
	char pri_dA[] = "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263";

	mp_int mp_Xg, mp_Yg, mp_rx, mp_ry, mp_p, mp_a, mp_rand_k;
	mp_int mp_r,  mp_s, mp_dgst,  mp_Pri_dA,  mp_n;
	mp_int mp_XA,  mp_YA;

	int ret = 0;
	mp_init_multi(&mp_Xg, &mp_Yg, &mp_rx, &mp_ry, &mp_p, &mp_a, 
		&mp_rand_k, &mp_r, &mp_s, &mp_dgst, &mp_Pri_dA, &mp_n, &mp_XA, &mp_YA,NULL);

	ret = mp_read_radix(&mp_Xg, (char *) Xg, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_Yg, (char *) Yg, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_p, (char *) param_p, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_a, (char *) param_a, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_n, (char *) param_n, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_dgst, (char *) dgst, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_Pri_dA, (char *) pri_dA, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_rand_k, (char *) rand_k, 16);
	CHECK_RET(ret);

	printf("...params are...\n");
	printf("p=");
	MP_print(&mp_p);
	printf("a=");
	MP_print(&mp_a);
	printf("n=");
	MP_print(&mp_n);
	printf("Xg=");
	MP_print(&mp_Xg);
	printf("Yg=");
	MP_print(&mp_Yg);
	printf("dA=");
	MP_print(&mp_Pri_dA);
	printf("rand=");
	MP_print(&mp_rand_k);
	
	ret = Ecc_Sm2_sign(&mp_r, &mp_s, &mp_dgst, &mp_rand_k, &mp_Pri_dA, &mp_Xg, &mp_Yg, 
				 &mp_a, &mp_p, &mp_n);	
	if (ret == 0)
	{
		printf("...signature ok...\n");
	}
	else
	{
		printf("...signature failed!\n");
		CHECK_RET(ret);
	}

	printf("...signature data:\n");
	printf("r=");
	MP_print(&mp_r);
	printf("s=");
	MP_print(&mp_s);
	
	// compute public key
	ret = Ecc_points_mul(&mp_XA, &mp_YA, &mp_Xg, &mp_Yg, &mp_Pri_dA, &mp_a, &mp_p);
	CHECK_RET(ret);

	printf("...public key:\n");
	printf("XA=");
	MP_print(&mp_XA);
	printf("YA=");
	MP_print(&mp_YA);

	printf("......verify signature...\n");
	ret = Ecc_Sm2_verifySig(&mp_r, &mp_s, &mp_dgst, &mp_XA, 
		&mp_YA, &mp_Xg, &mp_Yg, &mp_a, &mp_p, &mp_n);
	if (ret == 0)
	{
		printf("\nverify ok!\n");
	}
	else
	{
		printf("\nverify failed!\n");
		CHECK_RET(ret);
	}

	
END:
    mp_clear_multi(&mp_Xg, &mp_Yg, &mp_rx, &mp_ry, &mp_p, &mp_a, 
		&mp_rand_k, &mp_r, &mp_s, &mp_dgst, &mp_Pri_dA, &mp_n, &mp_XA, &mp_YA,NULL);
	printf("********\n* test end\n********\n");
	return ret;
}



int test_SM3_withZ_value_process()
{
	printf("\n********\n* Z value process test\n********\n");
	printf("...you can check the route on \"Public Key Cryptographic Algorithm SM2 Based on Elliptic Curves\" page [57]...\n");
	printf("...to check, please make sure that the sm2lib is a debug version, make it under \'-D_DEBUG\' when compile...\n\n\n");
	unsigned char XA[]     = "0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A";
	unsigned char YA[]     = "7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857";

	mp_int mp_a, mp_b, mp_Xg, mp_Yg, mp_XA, mp_YA;
	mp_init_multi(&mp_a, &mp_b, &mp_Xg, &mp_Yg, &mp_XA, &mp_YA, NULL);
	int ret = 0;
	char *uid = "ALICE123@YAHOO.COM";
	int lenUid = strlen(uid);
	char *src = "message digest";
	int  lenSrc = strlen(src);
	unsigned char tar[32] = {0};
	unsigned long ii = 32;

	ret = mp_read_radix(&mp_a, (char *) param_a, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_b, (char *) param_b, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_Xg, (char *) Xg, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_Yg, (char *) Yg, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_XA, (char *) XA, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_YA, (char *) YA, 16);
	CHECK_RET(ret);
	
	printf("IDA:%s\n", uid);
	printf("src:%s\n",src);

	ret = Sm3WithPreprocess(tar , &ii,  
		(unsigned char * )src, (unsigned long )lenSrc, 
		(unsigned char * )uid, (unsigned long) lenUid, &mp_a, &mp_b, &mp_Xg, &mp_Yg, &mp_XA, &mp_YA);
	CHECK_RET(ret);
	printf("M value=\n");
	BYTE_print(tar, ii);

END:
	mp_clear_multi(&mp_a, &mp_b, &mp_Xg, &mp_Yg, &mp_XA, &mp_YA, NULL);
	printf("********\n* test end\n********\n");
	return ret;
}


int test_GM_encryption_and_decryption()
{
	printf("\n********\n* GM sm2 asym encryption and decryption test\n********\n");
	printf("...you can check the route on \"Public Key Cryptographic Algorithm SM2 Based on Elliptic Curves\" page [90]...\n");
	printf("...to check, please make sure that the sm2lib is a debug version, make it under \'-D_DEBUG\' when compile...\n\n\n");
	unsigned char buff[64] = {0};unsigned long buffLen = 64;
	unsigned char prikeyBuff[200] = {0};unsigned long priLen = 200;
	int ret = 0;
	char * plain = "encryption standard";
	unsigned char encData[1000] = {0};
	unsigned long encLen = 1000;
	unsigned char decData[1000] = {0};
	unsigned long decLen = 1000;
#ifdef _DEBUG
	char * pubkey_B_XY = "435B39CCA8F3B508C1488AFC67BE491A0F7BA07E581A0E4849A5CF70628A7E0A75DDBA78F15FEECB4C7895E2C1CDF5FE01DEBB2CDBADF45399CCF77BBA076A42";
	char * prikey = "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0";
	ret = hexCharStr2unsignedCharStr(pubkey_B_XY, strlen(pubkey_B_XY), 0, buff, &buffLen);
	CHECK_RET(ret);
	ret = hexCharStr2unsignedCharStr(prikey, strlen(prikey),0, prikeyBuff, &priLen);
	CHECK_RET(ret);
#else
	ret = GM_GenSM2keypair(prikeyBuff, &priLen, buff);
	CHECK_RET(ret);
#endif

	printf("...public key\n");
	printf("XB=");
	BYTE_print(buff, 32);
	printf("YB=");
	BYTE_print(buff+32, 32);

	printf("...plain text:\n%s\n", plain);
	ret = GM_SM2Encrypt(encData, &encLen, (unsigned char *)plain, strlen(plain), buff, buffLen);
	CHECK_RET(ret);
	ret = GM_SM2Decrypt(decData, &decLen, encData, encLen, prikeyBuff, priLen);
	CHECK_RET(ret);
	printf("\n...decdata:%s\n", decData);
END:

	printf("********\n* test end\n********\n");
	return ret;
}


int test_GM_signature_and_verify()
{
	printf("\n********\n* GM sm2 asym signature and verification test\n********\n");
	printf("...you can check the route on \"Public Key Cryptographic Algorithm SM2 Based on Elliptic Curves\" page [57]...\n");
	printf("...to check, please make sure that the sm2lib is a debug version, make it under \'-D_DEBUG\' when compile...\n\n\n");

	unsigned char buff[64] = {0};unsigned long buffLen = 64;
	unsigned char prikeyBuff[200] = {0};unsigned long priLen = 200;
	int ret = 0;int i = 0;
	unsigned char encData[1000] = {0};
	unsigned long encLen = 1000;
	unsigned char decData[1000] = {0};
	unsigned long decLen = 1000;
	char *uid = "ALICE123@YAHOO.COM";
	int lenUid = strlen(uid);	
	char *src = "message digest";
	int  lenSrc = strlen(src);
	unsigned char sig[200] = {0};
	unsigned long ulSigLen = 200;
#ifdef _DEBUG
	char * pubkey_A_XY = "0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857";
	char * prikey = "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263";
	ret = hexCharStr2unsignedCharStr(pubkey_A_XY, strlen(pubkey_A_XY), 0, buff, &buffLen);
	CHECK_RET(ret);
	ret = hexCharStr2unsignedCharStr(prikey, strlen(prikey),0, prikeyBuff, &priLen);
	CHECK_RET(ret);
#else
	ret = GM_GenSM2keypair(prikeyBuff, &priLen, buff);
	CHECK_RET(ret);
#endif

#ifdef _DEBUG
	printf("...pubkey (XA,YA):\n");
	printf("XA=");
	BYTE_print(buff, 32);
	printf("YA=");
	BYTE_print(buff+32, 32);
	printf("...prikey dA:\n");
	BYTE_print(prikeyBuff, priLen);
#endif
	ret = GM_SM2Sign(sig, &ulSigLen, (unsigned char *)src, lenSrc, (unsigned char *)uid, lenUid, prikeyBuff, priLen);
	if (ret == 0)
	{
		printf("\n...signature ok...\n");
	}
	else
	{
		printf("\n...signature failed!\n");
		CHECK_RET(ret);
	}

	for (i =0; i<10; i++)
	{
		ret = GM_SM2VerifySig(sig, ulSigLen, (unsigned char *)src, lenSrc, (unsigned char *)uid, lenUid, buff, 64);
		if (ret == 0)
		{
			printf("\n...verify ok...\n");
		}
		else
		{
			printf("\n...verify failed!\n");
			CHECK_RET(ret);
		}	
	}
	


END:
	printf("********\n* test end\n********\n");
	return ret;

}




int alloctest()
{
	unsigned char * p = new unsigned char [1000];
	if (NULL == p)
	{
		return ERR_MEM_ALLOC;
	}
	memset(p, 0x00, 1000);
	if (NULL != p)
	{
		delete p;
	}
	return 0;
}



int testPointOnCurve()
{
	mp_int mp_rand_k;
	mp_init_set(&mp_rand_k, 1);
	//#ifdef _DEBUG
	unsigned char rand_k[] = "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F";
	//#endif
	/////////////////////////////////////////////////////////////////////////
	
	unsigned char XA_buf[100] = {0};
	unsigned char YA_buf[100] = {0};
	unsigned long XA_len = 100;
	unsigned long YA_len = 100;
	
	unsigned char XA_YA_buf[200] = {0};
	mp_int mp_a, mp_b, mp_n, mp_p, mp_Xg, mp_Yg, mp_XA, mp_YA, mp_pri_dA, mp_r, mp_s, mp_dgst;
	mp_int mp_inf_X, mp_inf_Y;
	mp_init_multi(&mp_a, &mp_b, &mp_n, &mp_p, &mp_Xg, &mp_Yg, 
		&mp_XA, &mp_YA, &mp_pri_dA, &mp_r, &mp_s, &mp_dgst, &mp_inf_X, &mp_inf_Y, NULL);
	
	int ret = 0;	
	ret = mp_read_radix(&mp_a, (char *) param_a, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_b, (char *) param_b, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_n, (char *) param_n, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_p, (char *) param_p, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_Xg, (char *) Xg, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_Yg, (char *) Yg, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_rand_k, (char *) rand_k, 16);
	CHECK_RET(ret);
	
#ifdef _DEBUG
	///  get rand num
	ret = mp_read_radix(&mp_rand_k, (char *) rand_k, 16);
	CHECK_RET(ret);
	ret = mp_submod(&mp_rand_k, &mp_n, &mp_n, &mp_rand_k);
	CHECK_RET(ret);
	MP_print_Space;
	printf("rand_k=");
	MP_print(&mp_rand_k);
#else
	ret = genRand_k(&mp_rand_k, &mp_n);
	CHECK_RET(ret);
#endif // _DEBUG
	
	//	ret = genRand_k(&mp_rand_k, &mp_n);
	// compute public key
	ret = Ecc_points_mul(&mp_XA, &mp_YA, &mp_Xg, &mp_Yg, &mp_rand_k, &mp_a, &mp_p);
	CHECK_RET(ret);
	
	ret = Ecc_points_mul(&mp_inf_X, &mp_inf_Y, &mp_XA, &mp_YA, &mp_n, &mp_a, &mp_p);
	CHECK_RET(ret);
	MP_print_Space;
	printf("Xg=");
	MP_print(&mp_Xg);
	printf("Yg=");
	MP_print(&mp_Yg);
	printf("XA=");
	MP_print(&mp_XA);
	printf("YA=");
	MP_print(&mp_YA);
	printf("inf_X=");
	MP_print(&mp_inf_X);
	printf("inf_Y=");
	MP_print(&mp_inf_Y);
	ret = Mp_Int2Byte(XA_buf, &XA_len, &mp_XA);
	ret = Mp_Int2Byte(YA_buf, &YA_len, &mp_YA);
	memcpy(XA_YA_buf, XA_buf, XA_len);
	memcpy(XA_YA_buf+XA_len, YA_buf, YA_len);
	
#ifdef _DEBUG
	MP_print_Space;
	printf("XA=");
	MP_print(&mp_XA);
	printf("YA=");
	MP_print(&mp_YA);
#endif
	printf("XA_YA_buf=");
	BYTE_print(XA_YA_buf, XA_len+YA_len);MP_print_Space;MP_print_Space;
	//	ret = MP_POINT_is_on_curve(&mp_XA, &mp_YA, &mp_a, &mp_b, &mp_p);
	ret = BYTE_POINT_is_on_sm2_curve(XA_YA_buf, XA_len+YA_len);
	
	
END:
	
	return ret;
}


int test_gen_SM2_GM_keypair()
{
	printf("\n********\n* GM sm2 keypair generation test\n********\n\n");

	unsigned char buff[64] = {0};unsigned long buffLen = 64;
	unsigned char prikeyBuff[200] = {0};unsigned long priLen = 200;
	int ret = 0;
	ret = GM_GenSM2keypair(prikeyBuff, &priLen, buff);
	CHECK_RET(ret);

	printf("...pubkey (XA,YA):\n");
	printf("XA=");
	BYTE_print(buff, 32);
	printf("YA=");
	BYTE_print(buff+32, 32);
	printf("...prikey dA:\n");
	BYTE_print(prikeyBuff, priLen);
	
END:
	printf("********\n* test end\n********\n");
	return ret;

}

int testKDF_SM3()
{
	unsigned char buff[200] = {0};
	unsigned long buffLen = 200;
	unsigned char outBuff[1000];
	unsigned long outLen = 152/8;
	char * src2kdf = "64D20D27D0632957F8028C1E024F6B02EDF23102A566C932AE8BD613A8E865FE58D225ECA784AE300A81A2D48281A828E1CEDF11C4219099840265375077BF78";
	int ret = hexCharStr2unsignedCharStr(src2kdf, strlen(src2kdf), 0, buff, &buffLen);
	ret = KDFwithSm3(outBuff, buff, buffLen, outLen);
	return 0;
	
}


char * getVersion()
{
	return (char *)"\nVersion:2012-6-30\nAuthor:SimonPang of CATT 2009\nEmail:steven.psm@gmail.com\n";
}