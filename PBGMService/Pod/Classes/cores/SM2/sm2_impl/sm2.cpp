

/*
 * sm2 implimentation based upon libTomMath library and goldbar's sm3 project
 *
 * Author : Simon Pang of catt2009 / steven.psm@gmail.com 
 * 2012-6-22
 *
 * reference : 
 * 1. Public Key Cryptographic Algorithm SM2 Based on Elliptic Curves 
 * [Part 1: General] page 18/93 (or page 12 of part one)  and 28/93(page 22 of part one); 57/93(page 7 of part two)
 * 2. bn.pdf of LibTomMath User Manual
 * 3. Guide to Elliptic Curve Cryptography
 *
 */


/*
 * GM curve params
 */

#define SM2_P     "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"
#define SM2_A     "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"
#define SM2_B     "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"
#define SM2_N     "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"
#define SM2_G_X   "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
#define SM2_G_Y   "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"

#if 0 //def _DEBUG
const char * param_a= "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498";
const char * param_b= "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A";
const char * param_n= "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7";
const char * param_p= "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3";
const char * Xg     = "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D";
const char * Yg     = "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2";
#else
const char * param_a= SM2_A;
const char * param_b= SM2_B;
const char * param_n= SM2_N;
const char * param_p= SM2_P;
const char * Xg     = SM2_G_X;
const char * Yg     = SM2_G_Y;
#endif //_DEBUG

#include "sm2.h"
#include "sm3.h"
#include "tommath.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "GM_define.h"
#include "time.h"


int myrng(unsigned char *dst, int len, void *dat)
{
	int x;
	for (x = 0; x < len; x++) dst[x] = rand() & 0xFF;
	return len;
}

int MP_print(mp_int * mp_num)
{
	char buff[1000] = {0};
	mp_toradix(mp_num, buff, 16);
	int i = 0;
	for (;i<strlen(buff);i++)
	{
		if (0 == i%8)
		{
			printf(" ");
		}
		printf("%c", buff[i]);
	}
	printf("\n");
	return 0;
}

void BYTE_print(unsigned char * tar, unsigned long l)
{
	for (int i = 0; i<l; i++)
	{
		if (i %4 ==0)
		{
			printf(" ");
		}
		printf("%02x", tar[i]);
	}
	printf("\n");
}


/*
 * instruction : sm2 signature (r,s) for curve  y^2 = x^3 + ax + b;
 *               r = (e+ x1) (mod n)
 *               s = [(1 + dA)^-1]*(k-r*dA) (mod n)
 * param:
 * @mp_r ,@mp_s : [out] : result signature data (r,s) 
 * @mp_dgst : [in] : source digest data to signature
 * @mp_rand_k : [in] : random number
 * @mp_Pri_dA : [in] : private key 
 * @mp_Xg, @mp_Yg : [in] : predefined base point of the curve
 * @param_a : [in] : param a of curve  y^2 = x^3 + ax + b;
 * @param_p : [in] : modulo p of finite field Fp.
 * @param_n : [in] : order of the curve.
 */
int Ecc_Sm2_sign(mp_int * mp_r, mp_int * mp_s, 
				 mp_int * mp_dgst, mp_int * mp_rand_k, mp_int * mp_Pri_dA, 
				 mp_int * mp_Xg, mp_int * mp_Yg, 
				 mp_int * param_a, mp_int * param_p, mp_int * param_n)
{
	mp_int mp_x1,mp_y1, tmp1, tmp2,s_left;
	int ret = 0; 
	ret = mp_init_multi(&mp_x1, &mp_y1, &tmp1, &tmp2, &s_left, NULL);
	CHECK_RET(ret);
	ret = Ecc_points_mul(&mp_x1, &mp_y1, mp_Xg, mp_Yg, mp_rand_k, param_a, param_p);
	CHECK_RET(ret);
	ret = mp_addmod(mp_dgst, &mp_x1, param_n, mp_r);// r = (e+ x1) (mod n)
	CHECK_RET(ret);

#ifdef _DEBUG
	MP_print_Space;
	printf("r=");
	MP_print(mp_r);
#endif

	ret = mp_addmod(mp_r,mp_rand_k, param_n, &tmp1);
	CHECK_RET(ret);
	if (MP_EQ == mp_cmp_d(mp_r, 0) || MP_EQ == mp_cmp_d(&tmp1, 0))// check r ;
	{
		ret = ERR_NEED_RAND_REGEN;
		goto END;
	}
	ret = mp_add_d(mp_Pri_dA, 1, &tmp1);
	CHECK_RET(ret);
	ret = mp_invmod(&tmp1, param_n, &tmp2);// (1 + dA)^-1
	CHECK_RET(ret);
	ret = mp_copy(&tmp2, &s_left);//s_left = (1 + dA)^-1
	CHECK_RET(ret);
	

	ret = mp_mul(mp_r, mp_Pri_dA, &tmp1);// r*dA
	CHECK_RET(ret);
	ret = mp_submod(mp_rand_k,  &tmp1, param_n, &tmp2);//(k-r*dA) (mod n)
	CHECK_RET(ret);
	
	ret = mp_mulmod(&s_left, &tmp2, param_n, mp_s);//s = [(1 + dA)^-1]*(k-r*dA) (mod n)
	CHECK_RET(ret);
	if (MP_EQ == mp_cmp_d(mp_s, 0))// check s;
	{
		ret = ERR_NEED_RAND_REGEN;
		goto END;
	}
#ifdef _DEBUG
	printf("s=");
	MP_print(mp_s);
#endif
	

END:
	mp_clear_multi(&mp_x1, &mp_y1, &tmp1, &tmp2, &s_left, NULL);
	return ret ;

}




/*
 * instruction : sm2 verify signature (r,s) for curve  y^2 = x^3 + ax + b;
 * param:
 * @mp_r ,@mp_s : [in] : input signature data (r,s) 
 * @mp_dgst : [in] : source digest data to signature
 * @mp_XA, @mp_YA:  [in] : public key point (XA, YA)
 * @mp_Xg, @mp_Yg : [in] : predefined base point (Xg, Yg) of the curve
 * @param_a : [in] : param a of curve  y^2 = x^3 + ax + b;
 * @param_p : [in] : modulo p of finite field Fp.
 * @param_n : [in] : order of the curve.
 */
int Ecc_Sm2_verifySig(mp_int * mp_r, mp_int * mp_s, 
					  mp_int * mp_dgst, 
					  mp_int * mp_XA, mp_int * mp_YA, 
					  mp_int * mp_Xg, mp_int * mp_Yg, 
				      mp_int * param_a, mp_int * param_p, mp_int * param_n)
{
	int ret = 0;
	mp_int mp_t, mp_x0, mp_y0, mp_x00, mp_y00, mp_x1, mp_y1, mp_R;
	ret = mp_init_multi(&mp_t, &mp_x0, &mp_y0, &mp_x00, &mp_y00, &mp_x1, &mp_y1, &mp_R, NULL);
	CHECK_RET(ret);

	if (MP_GT != mp_cmp(param_n, mp_r)  || MP_GT != mp_cmp(param_n, mp_s))
	{
		ret = ERR_SIG_VER_R_OR_S_LARGER_THAN_N; // failed
		goto END;
	}
	
	// t = (r+s) mod n
	ret = mp_addmod(mp_r, mp_s, param_n, &mp_t);
	CHECK_RET(ret);

#ifdef _DEBUG
	MP_print_Space;
	printf("t=");
	MP_print(&mp_t);
#endif

	// if t == 0 ? failed
	if (MP_EQ == mp_cmp_d(&mp_t, 0))
	{
		ret = ERR_SIG_VER_T_EQUL_ZERO; // failed
		goto END;
	}

	//-- compute : (x0,y0) = [s]G
	ret = Ecc_points_mul(&mp_x0, &mp_y0, mp_Xg, mp_Yg, mp_s, param_a, param_p);
	CHECK_RET(ret);

#ifdef _DEBUG
	MP_print_Space;
	printf("x0=");
	MP_print(&mp_x0);
	printf("y0=");
	MP_print(&mp_y0);
#endif

	//-- (x00,y00) = [t]PA
	ret = Ecc_points_mul(&mp_x00, &mp_y00, mp_XA, mp_YA, &mp_t, param_a, param_p);
	CHECK_RET(ret);

#ifdef _DEBUG
	MP_print_Space;
	printf("x00=");
	MP_print(&mp_x00);
	printf("y00=");
	MP_print(&mp_y00);
#endif

	// (x1,y1) = [s]G + [t]PA
	ret = Ecc_points_add(&mp_x1, &mp_y1, &mp_x0, &mp_y0, &mp_x00, &mp_y00, param_a, param_p);
	CHECK_RET(ret);

#ifdef _DEBUG
	MP_print_Space;
	printf("x1=");
	MP_print(&mp_x1);
	printf("y1=");
	MP_print(&mp_y1);
#endif

	// R = (e + x1) mod n
	ret = mp_addmod(mp_dgst, &mp_x1, param_n, &mp_R);
	CHECK_RET(ret);

#ifdef _DEBUG
	MP_print_Space;
	printf("mp_r=");
	MP_print(mp_r);
	printf("mp_R=");
	MP_print(&mp_R);
#endif // _DEBUG
	
	// if R == r  success
	if(MP_EQ != mp_cmp(mp_r, &mp_R))
	{
		ret = ERR_SIG_VER_R_NOT_EQUL;
		goto END;
	}

END:
	mp_clear_multi(&mp_t, &mp_x0, &mp_y0, &mp_x00, &mp_y00, &mp_x1, &mp_y1, &mp_R, NULL);
	return ret;

}


int GetPrime(mp_int *m,int lon)
{
	int ret = 0;
	ret = mp_prime_random_ex(m, 10, lon, 
		(rand()&1)?LTM_PRIME_2MSB_OFF:LTM_PRIME_2MSB_ON, myrng, NULL);
	return ret;
}

/*
 * instruction : point multiplication  (result_x, result_y) = (px, py) * d
 * param:
 * @result_x ,@result_y : [out] : result point(result_x, result_y) of point multiplication
 * @px, @py : [in] : source point to multiply
 * @d : [in] : large number --  multiplier 
 * @param_a : [in] : param a of curve  y^2 = x^3 + ax + b;
 * @param_p : [in] : modulo p of finite field Fp. 
 */
int Ecc_points_mul(mp_int *result_x,mp_int *result_y, mp_int *px, mp_int *py,mp_int *d,mp_int *param_a,mp_int *param_p)
{
	int ret = 0;
	mp_int mp_A, mp_P; 
	mp_int mp_Qx, mp_Qy;
	mp_int tmp_Qx, tmp_Qy;

	char Bt_array[800]={0};
	int i;
	int Bt_array_len = 0;
	ret = mp_init_copy(&mp_A, param_a);
	CHECK_RET(ret);
	ret = mp_init_copy(&mp_P, param_p);
	CHECK_RET(ret);

	
	ret = mp_init_set(& mp_Qx, 0); // Q: infinite point , or say :Zero point 
	CHECK_RET(ret);
	ret = mp_init_set(& mp_Qy, 0);
	CHECK_RET(ret);

	ret = mp_init_set(& tmp_Qx, 0); 
	CHECK_RET(ret);
	ret = mp_init_set(& tmp_Qy, 0);
	CHECK_RET(ret);

	// binary presentation of d 
    ret = mp_toradix(d,Bt_array,2); 
	CHECK_RET(ret);
	Bt_array_len = strlen (Bt_array);
	CHECK_RET(ret);
	
	for(i=0; i<=Bt_array_len-1; i++)
	{
		// Q = [2]Q;
		ret = Ecc_points_add(&tmp_Qx, &tmp_Qy, &mp_Qx, &mp_Qy, &mp_Qx, &mp_Qy, &mp_A , &mp_P);  
		CHECK_RET(ret);
		/////////////
		if( '1' == Bt_array[i])
		{// Q = Q + P	
			ret = Ecc_points_add(&mp_Qx, &mp_Qy, &tmp_Qx, &tmp_Qy, px, py, &mp_A , &mp_P);
			CHECK_RET(ret);
			/////////////
			ret = mp_copy(&mp_Qx, &tmp_Qx);
			CHECK_RET(ret);
			ret = mp_copy(&mp_Qy, &tmp_Qy);
			CHECK_RET(ret);
		}
		ret = mp_copy(&tmp_Qx, &mp_Qx);
		CHECK_RET(ret);
		ret = mp_copy(&tmp_Qy, &mp_Qy);
		CHECK_RET(ret);
	}
	
	ret = mp_copy(&tmp_Qx, result_x);
	CHECK_RET(ret);
	ret = mp_copy(&tmp_Qy, result_y);
	CHECK_RET(ret);
	
END:	

	mp_clear_multi(&mp_A, &mp_P, &mp_Qx, &mp_Qy, &tmp_Qx, &tmp_Qy, NULL);
	return ret;
}

/*
 * instruction : addition of points (result_x, result_y) = (x1, y1) + (x2, y2)
 * param:
 * @result_x ,@result_y : [out] : result point(result_x, result_y) of point addition
 * @x1, @y1 : [in] : source point (x1,y1) to add
 * @x2, @y2 : [in] : another point (x2,y2) to add
 * @param_a : [in] : param a of curve  y^2 = x^3 + ax + b;
 * @param_p : [in] : modulo p of finite field Fp. 
 */
int Ecc_points_add(mp_int *result_x,mp_int *result_y,
				   mp_int *x1,mp_int *y1,mp_int *x2,mp_int *y2,
				   mp_int *param_a, mp_int *param_p)
{

	mp_int mp_tmp_r;
	mp_int tmp1, tmp2;
	mp_int Lambda;
	mp_int top, bottom;

	int ret = 0;
	// p(x1,y1); Q(x2,y2); x1=y1=x2=y2=0; so: P+Q==0
	if ((MP_EQ == mp_cmp_d(x1, 0)  && MP_EQ == mp_cmp_d(y1, 0))  &&
		(MP_EQ == mp_cmp_d(x2, 0)  && MP_EQ == mp_cmp_d(y2, 0)))
	{
		mp_zero(result_x);
		mp_zero(result_y);
		return 0;//success
	}

	if (MP_EQ == mp_cmp_d(x1, 0)  && MP_EQ == mp_cmp_d(y1, 0)) 
	{
		ret = mp_copy(x2, result_x);
		CHECK_RET(ret);
		ret = mp_copy(y2, result_y);
		CHECK_RET(ret);
		return 0;//success
	}

	if (MP_EQ == mp_cmp_d(x2, 0)  && MP_EQ == mp_cmp_d(y2, 0)) 
	{
		ret = mp_copy(x1, result_x);
		CHECK_RET(ret);
		ret = mp_copy(y1, result_y);
		CHECK_RET(ret);
		return 0;//success
	}
	
	// P(x,y); Q(x,-y); P+Q==0
	ret = mp_init_set(&mp_tmp_r, 0);
	CHECK_RET(ret);
	ret = mp_add(y1, y2, &mp_tmp_r);
	CHECK_RET(ret);

	if ((MP_EQ == mp_cmp(x1, x2)) && (MP_EQ == mp_cmp_d(&mp_tmp_r, 0)))
	{
		mp_zero(result_x);
		mp_zero(result_y);
		return 0;//success
	}
	
	ret = mp_init_set(&tmp1, 0);
	CHECK_RET(ret);
	ret = mp_init_set(&tmp2, 0);
	CHECK_RET(ret);

	// P+Q!=0 : compute Lambda
	ret = mp_init_set(&Lambda, 0);
	CHECK_RET(ret);
	{
		ret = mp_init_set(&top, 0);
		CHECK_RET(ret);
		ret = mp_init_set(&bottom, 0);
		CHECK_RET(ret);

		if (MP_EQ == mp_cmp(x1, x2))//x1==x2 and P+Q != 0 : lambda=(3*x1^2+a)/2*y1
		{    
			ret = mp_sqr(x1, &tmp1);
			CHECK_RET(ret);
			ret = mp_mul_d(&tmp1, 3, &tmp2);
			CHECK_RET(ret);
			ret = mp_addmod(&tmp2, param_a, param_p, &top); //top = 3*x1^2+a
			CHECK_RET(ret);

			ret = mp_mul_d(y1, 2, &tmp1);
			CHECK_RET(ret);
			ret = mp_invmod(&tmp1,param_p, &bottom); //bottom = 1/2*y1
			CHECK_RET(ret);

			ret = mp_mulmod(& top, & bottom, param_p, & Lambda);//top*bottom
			CHECK_RET(ret);
		}
		else // x1 != x2   :lambda=(y2-y1)/(x2-x1)
		{
			ret = mp_submod(y2, y1, param_p, &top);
			CHECK_RET(ret);
			ret = mp_submod(x2, x1, param_p, &tmp1);
			CHECK_RET(ret);

			ret = mp_invmod(&tmp1, param_p, &bottom); // bottom = 1/(x2-x1)
			CHECK_RET(ret);
			ret = mp_mulmod(& top, & bottom, param_p, & Lambda);
			CHECK_RET(ret);
		}
		mp_clear(&top);
		mp_clear(&bottom);
	}

	// x3 = lambda^2-x1-x2
	ret = mp_sqr(&Lambda, &tmp1);
	CHECK_RET(ret);
	ret = mp_sub(&tmp1, x1, &tmp2);
	CHECK_RET(ret);
	ret = mp_submod(&tmp2, x2, param_p, result_x);
	CHECK_RET(ret);

	// y3 = lambda*(x1-x3) - y1
	ret = mp_sub(x1, result_x, &tmp1);
	CHECK_RET(ret);
	ret = mp_mul(&Lambda, &tmp1, &tmp2);
	CHECK_RET(ret);
	ret = mp_submod(&tmp2, y1, param_p, result_y);
	CHECK_RET(ret);

	
END:
	
	mp_clear_multi(&tmp1, &tmp2, &Lambda, &mp_tmp_r, NULL);
	
	return ret;
	
}

/*
 *  change a string of Ascii(0--f) to BYTE str 
 *  Eg:"1A2B3C4D" (length of 8) will be trasform to byte string 0x1A2B3C4D  (length will be 4)
 *  to use it : hexCharStr2unsignedCharStr("1A2B3C4D", strlen("1A2B3C4D"), 0 , buff, &ulBuffLen);
 *　params:
 *  @src, @lsrc : [in] source string
 *  @flag [in] : just input 0
 *  @out, @lout : [out] : output BYTE str
 *  return :
 *  0 -- ok; other : failed
 */
int hexCharStr2unsignedCharStr(char *src, unsigned long lsrc, int flag, unsigned char * out, unsigned long * lout)
{
	if((0 == flag && 0 !=lsrc%2) || (0 != flag && 0 !=lsrc%3) ||NULL == src || NULL == out )
	{
		return ERR_HEX2BYTE_PARAM_ERROR;//param err
	}
	
	int j = 0;//index of out buff
	if(0 == flag)
	{
		for (int i=0; i<lsrc; i += 2)
		{
			int tmp = 0;
			int HIGH_HALF_BYTE = 0;
			int LOW_HALF_BYTE = 0;
			if (src[i]>= 0x30 && src[i]<=0x39)
			{
				HIGH_HALF_BYTE = src[i] - 0x30;
			}
			else if (src[i]>= 0x41 && src[i]<=0x46)
			{
				HIGH_HALF_BYTE = src[i] - 0x37;
			}
			else if( src[i]>= 0x61 && src[i]<=0x66)
			{
				HIGH_HALF_BYTE = src[i] - 0x57;
			}
			else if( src[i] == 0x20)
			{
				HIGH_HALF_BYTE = 0x00;
			}
			else
			{
				return ERR_HEX2BYTE_INVALID_DATA;
			}
			
			if (src[i+1]>= 0x30 && src[i+1]<=0x39)
			{
				LOW_HALF_BYTE = src[i+1] - 0x30;
			}
			else if (src[i+1]>= 0x41 && src[i+1]<=0x46)
			{
				LOW_HALF_BYTE = src[i+1] - 0x37;
			}
			else if( src[i+1]>= 0x61 && src[i+1]<=0x66)
			{
				LOW_HALF_BYTE = src[i+1] - 0x57;
			}
			else if( src[i+1] == 0x20)
			{
				LOW_HALF_BYTE = 0x00;
			}
			else
			{
				return ERR_HEX2BYTE_INVALID_DATA;
			}
			
			tmp = (HIGH_HALF_BYTE<<4) + LOW_HALF_BYTE;
			out [j] = tmp;
			j++;
		}
	}
	else
	{
		for (int i=0; i<lsrc; i += 3)
		{
			int tmp = 0;
			int HIGH_HALF_BYTE = 0;
			int LOW_HALF_BYTE = 0;
			if ((i+2<= lsrc) && (src[i+2] != flag))
			{
				return ERR_HEX2BYTE_BEYOND_RANGE;
			}

			if (src[i]>= 0x30 && src[i]<=0x39 )
			{
				HIGH_HALF_BYTE = src[i] - 0x30;
			}
			else if (src[i]>= 0x41 && src[i]<=0x46)
			{
				HIGH_HALF_BYTE = src[i] - 0x37;
			}
			else if( src[i]>= 0x61 && src[i]<=0x66)
			{
				HIGH_HALF_BYTE = src[i] - 0x57;
			}
			else
			{
				return ERR_HEX2BYTE_INVALID_DATA;
			}
			
			if (src[i+1]>= 0x30 && src[i+1]<=0x39)
			{
				LOW_HALF_BYTE = src[i+1] - 0x30;
			}
			else if (src[i+1]>= 0x41 && src[i+1]<=0x46)
			{
				LOW_HALF_BYTE = src[i+1] - 0x37;
			}
			else if( src[i+1]>= 0x61 && src[i+1]<=0x66)
			{
				LOW_HALF_BYTE = src[i+1] - 0x57;
			}
			else
			{
				return ERR_HEX2BYTE_INVALID_DATA;
			}

			tmp = (HIGH_HALF_BYTE<<4) + LOW_HALF_BYTE;
			out [j] = tmp;
			j++;
		}
	}

	* lout = j;
	return 0;
	
}

int Mp_Int2Byte(unsigned char *tar, unsigned long *lenTar, mp_int * mp_src)
{
	int ret = 0;
	char buff[MAX_STRLEN] = {0};
	char tmp[MAX_STRLEN] = {0};
	int  lenBuff = MAX_STRLEN;
	ret = mp_toradix(mp_src, buff, 16);
	CHECK_RET(ret);
	lenBuff = strlen(buff);
	if (0 != lenBuff%2) //if mp_toradix deleted the leading 0, add it(0) here!
	{
		tmp[0] = 0x30;
		memcpy(tmp+1, buff, lenBuff);
		memset(buff, 0x00, sizeof(buff));
		memcpy(buff, tmp, lenBuff+1);
		lenBuff += 1;
	}
	ret = hexCharStr2unsignedCharStr(buff, lenBuff, 0, tar, lenTar);

END:
	return ret;
}


/*
 * instruction : sm3 hash with preProcess 
 *               ZA=sm3(ENTL || ID || a || b || xG || yG || xA || yA)
 *               M = sm3(ZA || M)
 * param:
 * @dgst ,@LenDgst : [out] : output hashed data *LenDgst will always return 32
 * @Src ,@lenSrc: [in] : source data to digest
 * @UserID, @lenUID :  [in] : user id
 * @param_a : [in] : param a of curve  y^2 = x^3 + ax + b;
 * @param_b : [in] : param b of curve  y^2 = x^3 + ax + b;
 * @mp_Xg, @mp_Yg : [in] : predefined base point (Xg, Yg) of the curve
 * @mp_XA, @mp_YA : [in] : public key point (XA, YA)
 * return :
 * 0 : success
 * other errcode : operation failed
 */
int Sm3WithPreprocess(unsigned char * dgst, unsigned long * LenDgst, 
					  unsigned char * Src, unsigned long lenSrc, 
					  unsigned char * UserID, unsigned long lenUID, 
					  mp_int * mp_a, mp_int * mp_b, 
					  mp_int * mp_Xg, mp_int * mp_Yg,
					  mp_int * mp_XA, mp_int * mp_YA)
{
	int ret = 0;
	if (NULL == Src || 0 == lenSrc || NULL == UserID || 0 == lenUID || 8000 < lenUID)
	{
		return ERR_PARAM;
	}
	if (NULL == dgst)
	{
		* LenDgst = 32;
		return 0;
	}

#ifdef _DEBUG
	MP_print_Space;
	printf("...params are...\n");
	printf("a=");
	MP_print(mp_a);
	printf("b=");
	MP_print(mp_b);
	printf("Xg=");
	MP_print(mp_Xg);
	printf("Yg=");
	MP_print(mp_Yg);
	printf("XA=");
	MP_print(mp_XA);
	printf("YA=");
	MP_print(mp_YA);
#endif
	unsigned char ZA[32] = {0};
	unsigned char * pM_A = NULL;
	unsigned char * ZA_SRC_Buff = NULL;
	unsigned long lenZA_SRC = 0;
	unsigned char ENTL_buf[10] = {0};
	unsigned long Len_ENTL_buf = 0;
	char tmp[10] = {0};
	int tmplen = 0;
	unsigned char uzParam_A [MAX_STRLEN] = {0};unsigned long lenParamA  = MAX_STRLEN;
	unsigned char uzParam_B [MAX_STRLEN] = {0};unsigned long lenParamB  = MAX_STRLEN;
	unsigned char uzParam_Xg[MAX_STRLEN] = {0};unsigned long lenParamXg = MAX_STRLEN;
	unsigned char uzParam_Yg[MAX_STRLEN] = {0};unsigned long lenParamYg = MAX_STRLEN;
	unsigned char uzParam_XA[MAX_STRLEN] = {0};unsigned long lenParamXA = MAX_STRLEN;
	unsigned char uzParam_YA[MAX_STRLEN] = {0};unsigned long lenParamYA = MAX_STRLEN;

	Mp_Int2Byte(uzParam_A, &lenParamA, mp_a);
	Mp_Int2Byte(uzParam_B, &lenParamB, mp_b);
	Mp_Int2Byte(uzParam_Xg, &lenParamXg, mp_Xg);
	Mp_Int2Byte(uzParam_Yg, &lenParamYg, mp_Yg);
	Mp_Int2Byte(uzParam_XA, &lenParamXA, mp_XA);
	Mp_Int2Byte(uzParam_YA, &lenParamYA, mp_YA);

	sprintf(tmp, "%4x",lenUID*8);
	tmplen = strlen(tmp);
	ret = hexCharStr2unsignedCharStr(tmp, tmplen, 0, ENTL_buf, &Len_ENTL_buf);
	if (ret) goto END;
	
	lenZA_SRC = Len_ENTL_buf + lenUID + lenParamA + lenParamB + lenParamXg + lenParamYg + lenParamXA + lenParamYA;
	ZA_SRC_Buff = new unsigned char [lenZA_SRC + MAX_STRLEN] ;
	if (NULL == ZA_SRC_Buff)
	{
		ret =  ERR_MEM_ALLOC;
		goto END;
	}
	memset(ZA_SRC_Buff, 0x00 ,sizeof(ZA_SRC_Buff));
	memcpy(ZA_SRC_Buff, ENTL_buf, Len_ENTL_buf);
	memcpy(ZA_SRC_Buff+Len_ENTL_buf, UserID, lenUID );
	memcpy(ZA_SRC_Buff+Len_ENTL_buf+lenUID, uzParam_A, lenParamA);
	memcpy(ZA_SRC_Buff+Len_ENTL_buf+lenUID+lenParamA, uzParam_B,lenParamB );
	memcpy(ZA_SRC_Buff+Len_ENTL_buf+lenUID+lenParamA+lenParamB, uzParam_Xg, lenParamXg);
	memcpy(ZA_SRC_Buff+Len_ENTL_buf+lenUID+lenParamA+lenParamB+lenParamXg, uzParam_Yg, lenParamYg);
	memcpy(ZA_SRC_Buff+Len_ENTL_buf+lenUID+lenParamA+lenParamB+lenParamXg+lenParamYg, uzParam_XA, lenParamXA);
	memcpy(ZA_SRC_Buff+Len_ENTL_buf+lenUID+lenParamA+lenParamB+lenParamXg+lenParamYg+lenParamXA, uzParam_YA, lenParamYA);

	sm3(ZA_SRC_Buff, lenZA_SRC, ZA);
	pM_A = new unsigned char[32+lenSrc+MAX_STRLEN];
	if (NULL == pM_A)
	{
		ret =  ERR_MEM_ALLOC;
		goto END;
	}
#ifdef _DEBUG
	printf("...Z value is:\n");
	BYTE_print(ZA, 32);
#endif
	memset(pM_A, 0x00, 32+lenSrc+MAX_STRLEN );
	memcpy(pM_A, ZA, 32);
	memcpy(pM_A+32, Src, lenSrc);
	sm3(pM_A, 32+lenSrc, dgst);
	* LenDgst = 32;
	ret = 0;
#ifdef _DEBUG
	printf("...M value is:\n");
	BYTE_print(dgst, 32);
#endif
	
END:
	if (NULL != pM_A)
	{
		delete []pM_A;
	}
	if (NULL != ZA_SRC_Buff)
	{
		delete []ZA_SRC_Buff;
	}
	return ret;
}

/*
 * trans an BYTE string into a mp_int  
 * param:
 * @mp_tar : [out] : output mp_int target
 * @src_byte, @lenSrc : [in] : input BYTE need to transform
 * return :
 * 0 -- ok
 */
int Byte2Mp_Int(mp_int * mp_tar, unsigned char *src_byte, unsigned long lenSrc)
{
	char *src_strbuff = NULL;
	src_strbuff = new char [lenSrc*2 + MAX_STRLEN];
	if (NULL == src_strbuff)
	{
		return ERR_MEM_ALLOC;
	}
	memset(src_strbuff, 0x00, lenSrc*2 + MAX_STRLEN);
	int j = 0, ret = 0;
	for (int i=0 ; i<lenSrc; i++)
	{
		char tmp = src_byte[i]>>4;
		if (tmp>=0 && tmp <= 9)
		{
			src_strbuff[j] = tmp + 0x30; 
		}
		else
		{
			src_strbuff[j] = tmp + 0x37;
		}
		tmp = src_byte[i] & 0x0f;
		if (tmp>=0 && tmp <= 9)
		{
			src_strbuff[j+1] = tmp + 0x30; 
		}
		else
		{
			src_strbuff[j+1] = tmp + 0x37;
		}
		j += 2;
	}
	src_strbuff[j] = 0;
	ret = mp_read_radix(mp_tar, src_strbuff, 16);

	if (NULL != src_strbuff)
	{
		delete src_strbuff;
	}
	return ret ;
}


/*
 * instruction : sm2 signature verify with GM predefined curve params 
 * param:
 * @signedData ,@ulSigLen : [in] : sig data to verify , ulSigLen should be 64
 *    ###signedData's structure: [r,s] = [---32 bytes of r ---][---32 bytes of s ---]
 * @Src ,@SrcLen: [in] : source data to digest and signature
 * @UserID, @lenUID :  [in] : user id
 * @szPubkey_XY, @ulPubkey_XYLen : [in] : public key of a (XA,YA),ulPubkey_XYLen should be 64
 *    ###structure of pubkey should be : [---32 byte of X coordinate---][---32 byte of Y coordinate---]
 * return :
 * 0 : success
 * other errcode : operation failed
 *
 * #define SM2_P     "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"
 * #define SM2_A     "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"
 * #define SM2_B     "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"
 * #define SM2_N     "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"
 * #define SM2_G_X   "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
 * #define SM2_G_Y   "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
 */
int GM_SM2VerifySig(unsigned char * signedData, unsigned long ulSigLen,
				 unsigned char * Src, unsigned long SrcLen, 
				 unsigned char * UserID, unsigned long lenUID,
				 unsigned char * szPubkey_XY, unsigned long ulPubkey_XYLen)
{
	if (NULL == Src || 0 == SrcLen || NULL == UserID || 0 == lenUID || 
		NULL == szPubkey_XY || 64 != ulPubkey_XYLen || 0 == ulSigLen || NULL == signedData || 64 != ulSigLen)
	{
		return ERR_PARAM;
	}
	int ret = 0;	
	unsigned char dgst[32] = {0};
	unsigned long dgstLen = 32;
	unsigned long ulTmp = 32;
// 	ECCSIGNATUREBLOB signature;
// 	memset(&signature, 0x00, sizeof(ECCSIGNATUREBLOB));
//	unsigned char signature[100] = {0};//actually should be 64, in case of mem flew
	
	mp_int mp_a, mp_b, mp_n, mp_p, mp_Xg, mp_Yg, mp_XA, mp_YA, mp_r, mp_s, mp_dgst;
	mp_init_multi(&mp_a, &mp_b, &mp_n, &mp_p, &mp_Xg, &mp_Yg, 
		&mp_XA, &mp_YA, &mp_r, &mp_s, &mp_dgst, NULL);	

	ret = Byte2Mp_Int(&mp_XA, szPubkey_XY, 32);
	CHECK_RET(ret);
	ret = Byte2Mp_Int(&mp_YA, szPubkey_XY+32, 32);
	CHECK_RET(ret);

	ret = Byte2Mp_Int(&mp_r, signedData, 32);
	CHECK_RET(ret);
	ret = Byte2Mp_Int(&mp_s, signedData+32, 32);
	CHECK_RET(ret);

	ret = mp_read_radix(&mp_a, (char *) param_a, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_b, (char *) param_b, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_n, (char *) param_n, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_p, (char *) param_p, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_Xg, (char *) Xg, 16);
	ret = mp_read_radix(&mp_Yg, (char *) Yg, 16);
	CHECK_RET(ret);
	CHECK_RET(ret);
	
	ret = Sm3WithPreprocess(dgst, &dgstLen, Src, SrcLen, UserID, lenUID, 
		&mp_a, &mp_b, &mp_Xg, &mp_Yg, &mp_XA, &mp_YA);
	CHECK_RET(ret);
	
	ret = Byte2Mp_Int(&mp_dgst, dgst, dgstLen);
	CHECK_RET(ret);

	ret = Ecc_Sm2_verifySig(&mp_r, &mp_s, 
		&mp_dgst, &mp_XA, &mp_YA, &mp_Xg, &mp_Yg, &mp_a, &mp_p, &mp_n);
	CHECK_RET(ret);
END:
	mp_clear_multi(&mp_a, &mp_b, &mp_n, &mp_p, &mp_Xg, &mp_Yg, 
		&mp_XA, &mp_YA, &mp_r, &mp_s, &mp_dgst, NULL);
	return ret;

}


/*
 * instruction : sm2 signature with GM predefined curve params 
 * param:
 * @signedData ,@pulSigLen : [out] : output sig data *LenDgst will always return 64, 
 *      ###signedData = [r,s] = [---32 bytes of r ---][---32 bytes of s ---]
 * @Src ,@SrcLen: [in] : source data to digest and signature
 * @UserID, @lenUID :  [in] : user id
 * @prikey, @ulPrikeyLen : [in] : private key (Byte Stream) of a random number
 * return :
 * 0 : success
 * other errcode : operation failed
 *
 * #define SM2_P     "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"
 * #define SM2_A     "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"
 * #define SM2_B     "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"
 * #define SM2_N     "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"
 * #define SM2_G_X   "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
 * #define SM2_G_Y   "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
 */
int GM_SM2Sign(unsigned char * signedData, unsigned long * pulSigLen,
					unsigned char * Src, unsigned long SrcLen, 
					unsigned char * UserID, unsigned long lenUID,
					unsigned char * prikey, unsigned long ulPrikeyLen)
{	

	if (NULL == Src || 0 == SrcLen || NULL == UserID || 0 == lenUID || 
		NULL == prikey || 0 == ulPrikeyLen || NULL == pulSigLen)
	{
		return ERR_PARAM;
	}
	if (NULL == signedData)
	{
		* pulSigLen = 64;
		return 0;
	}

	//////////////////////////////////////////////////////////////////////////
	mp_int mp_rand_k;
	mp_init_set(&mp_rand_k, 1);
#ifdef _DEBUG
	unsigned char rand_k[] = "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F";
#endif
	//////////////////////////////////////////////////////////////////////////

	unsigned char dgst[32] = {0};
	unsigned long dgstLen = 32;
	unsigned long ulTmp = 32;
// 	ECCSIGNATUREBLOB signature;
// 	memset(&signature, 0x00, sizeof(ECCSIGNATUREBLOB));
	unsigned char signature[100] = {0};//actually should be 64, in case of mem flew

	mp_int mp_a, mp_b, mp_n, mp_p, mp_Xg, mp_Yg, mp_XA, mp_YA, mp_pri_dA, mp_r, mp_s, mp_dgst;
	mp_init_multi(&mp_a, &mp_b, &mp_n, &mp_p, &mp_Xg, &mp_Yg, 
		&mp_XA, &mp_YA, &mp_pri_dA, &mp_r, &mp_s, &mp_dgst, NULL);

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

	ret = Byte2Mp_Int(&mp_pri_dA, prikey, ulPrikeyLen);
	CHECK_RET(ret);
	// compute public key
	ret = Ecc_points_mul(&mp_XA, &mp_YA, &mp_Xg, &mp_Yg, &mp_pri_dA, &mp_a, &mp_p);
	CHECK_RET(ret);

#ifdef _DEBUG
	MP_print_Space;
	printf("XA=");
	MP_print(&mp_XA);
	printf("YA=");
	MP_print(&mp_YA);
#endif
	
	ret = Sm3WithPreprocess(dgst, &dgstLen, Src, SrcLen, UserID, 
		lenUID, &mp_a, &mp_b, &mp_Xg, &mp_Yg, &mp_XA, &mp_YA);
	CHECK_RET(ret);

	ret = Byte2Mp_Int(&mp_dgst, dgst, dgstLen);
	CHECK_RET(ret);
#ifdef _DEBUG
	MP_print_Space;
	printf("digest=");
	MP_print(&mp_dgst);
#endif

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
	ret = Ecc_Sm2_sign(&mp_r, &mp_s, &mp_dgst, &mp_rand_k, 
		&mp_pri_dA, &mp_Xg, &mp_Yg, &mp_a, &mp_p, &mp_n);
	CHECK_RET(ret);
	ret = Mp_Int2Byte(signature, &ulTmp, &mp_r);
	CHECK_RET(ret);
	if (ulTmp > 32)
	{
		ret = ERR_UNKNOWN;
		CHECK_RET(ret);
	}
	ret = Mp_Int2Byte(signature+32, &ulTmp, &mp_s);
	CHECK_RET(ret);
	if (ulTmp > 32)
	{
		ret = ERR_UNKNOWN;
		CHECK_RET(ret);
	}

	memcpy(signedData, signature, 64);
	* pulSigLen = 64;

END:
	////
	mp_clear_multi(&mp_a, &mp_b, &mp_n, &mp_p, &mp_Xg, &mp_Yg, 
		&mp_XA, &mp_YA, &mp_pri_dA, &mp_r, &mp_s, &mp_dgst, &mp_rand_k, NULL);
	return ret;
}

/*
 * generate a random k < n
 */
int genRand_k(mp_int * rand_k, mp_int * mp_n)
{
	int ret = 0;
	srand( (unsigned)time( NULL ) );
	mp_set(rand_k, 1);
	ret = mp_mul_d(rand_k, rand(), rand_k);
	CHECK_RET(ret);
	ret = mp_mul_d(rand_k, rand(), rand_k);
	CHECK_RET(ret);
	ret = mp_mul_d(rand_k, rand(), rand_k);
	CHECK_RET(ret);
	ret = mp_submod(rand_k, mp_n, mp_n, rand_k);
	CHECK_RET(ret);

END:
    return ret;
}
		


int KDFwithSm3(unsigned char * kdfOutBuff, unsigned char * Z_in, unsigned long ulZlen, unsigned long klen )
{
	int ret = 0;
	if (NULL == Z_in || 0 == ulZlen || 0 == klen)
	{
		return ERR_PARAM;
	}
	
	unsigned char * pZandCt = new unsigned char [ulZlen + 4 + 10];
	if (NULL == pZandCt)
	{
		return ERR_MEM_ALLOC;
	}
	unsigned char * pZ = pZandCt;
	memset(pZ, 0x00 , ulZlen + 4 + 10 );


	unsigned long ct = 1;
	unsigned long mod = (klen)%32;// 32 = output byte length of sm3 
	int max_iter = (klen)/32;

	char ct_str[10] = {0};
	int  ct_len = 0;
	unsigned char ct_un_buff[10] = {0};
	unsigned long len_ct_unbuff = 0;
	unsigned char tmp_buff[32];

	for (ct = 1; ct <= max_iter ; ct++)
	{	
		sprintf(ct_str, "%8x",ct);
		ct_len = strlen(ct_str);
		ret = hexCharStr2unsignedCharStr(ct_str, ct_len, 0, ct_un_buff, &len_ct_unbuff);
		if (ret) 
		{
			if (NULL != pZandCt)
			{
				delete []pZandCt;
			}
			return ret;
		}
		pZ = pZandCt;
		memset(pZ, 0x00 , ulZlen + 4 + 10 );
		memcpy(pZ, Z_in, ulZlen);
		memcpy(pZ+ulZlen, ct_un_buff, len_ct_unbuff);
		sm3(pZ, ulZlen + 4, kdfOutBuff + (ct-1)*32);
	}
	sprintf(ct_str, "%8x",ct);
	ct_len = strlen(ct_str);
	ret = hexCharStr2unsignedCharStr(ct_str, ct_len, 0, ct_un_buff, &len_ct_unbuff);
	if (ret) 
	{
		if (NULL != pZandCt)
		{
			delete []pZandCt;
		}
		return ret;
	}
	pZ = pZandCt;
	memset(pZ, 0x00 , ulZlen + 4 +10 );//??
	memcpy(pZ, Z_in, ulZlen);
	memcpy(pZ+ulZlen, ct_un_buff, len_ct_unbuff);
	sm3(pZ, ulZlen + 4, tmp_buff);
	memcpy(kdfOutBuff + (ct-1)*32, tmp_buff, mod);
	ret = 0;

	if (NULL != pZandCt)
	{
		delete []pZandCt;
	}

	
	return ret ;
}
			

/*
 * instruction : check if the point is on curve
 * param:
 * @pubkey_XY, @ulPubXYLen : [in] : private key data, need to be generated by the library
 * return :
 * 0 : success
 * other errcode : operation failed
 */
int BYTE_POINT_is_on_sm2_curve(unsigned char * pubkey_XY, unsigned long ulPubXYLen)
{
	if (NULL == pubkey_XY || 64 != ulPubXYLen)
	{
		return ERR_PARAM;
	}
	
	mp_int mp_a, mp_b, mp_n, mp_p, mp_x, mp_y;
	mp_init_multi(&mp_a, &mp_b, &mp_n, &mp_p, &mp_x, &mp_y, NULL);
	unsigned char X[32] = {0};
	unsigned char Y[32] = {0};
	
	int ret = 0;	
	ret = mp_read_radix(&mp_a, (char *) param_a, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_b, (char *) param_b, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_n, (char *) param_n, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_p, (char *) param_p, 16);
	CHECK_RET(ret);
	
	memcpy(X, pubkey_XY, 32);
	memcpy(Y, pubkey_XY+32, 32);
	ret = Byte2Mp_Int(&mp_x, X, 32);
	CHECK_RET(ret);
	ret = Byte2Mp_Int(&mp_y, Y, 32);
	CHECK_RET(ret);


#ifdef _DEBUG
	MP_print_Space;
	MP_print(&mp_x);
	MP_print(&mp_y);
#endif
	
	ret = MP_POINT_is_on_curve(&mp_x, &mp_y, &mp_a, &mp_b, &mp_p);

END:
	mp_clear_multi(&mp_a, &mp_b, &mp_n, &mp_p, &mp_x, &mp_y, NULL);
	return ret;

}

int MP_POINT_is_on_curve(mp_int * mp_X, mp_int * mp_Y, mp_int * mp_a, mp_int * mp_b, mp_int * mp_p)
{
	if (MP_EQ == mp_cmp_d(mp_X, 0) && MP_EQ == mp_cmp_d(mp_Y, 0) )// (x,y) != (0,0)
	{
		return ERR_INFINITE_POINT;
	}
	if (!( ((MP_GT == mp_cmp_d(mp_X, 0) || MP_EQ == mp_cmp_d(mp_X, 0)) && MP_LT == mp_cmp(mp_X, mp_p) ) &&
		((MP_GT == mp_cmp_d(mp_Y, 0) || MP_EQ == mp_cmp_d(mp_Y, 0)) && MP_LT == mp_cmp(mp_Y, mp_p) ) ) )
	{
		return ERR_POINT_NOT_ON_CURVE;
	}

	mp_int left,  right, mp_tmp, mp_tmp2;
	int ret = 0;
	ret = mp_init_multi(&left, &right, &mp_tmp, &mp_tmp2, NULL);
	CHECK_RET(ret);
	
	ret = mp_sqrmod(mp_Y, mp_p, &left); // y^2
	CHECK_RET(ret);

	ret = mp_sqr(mp_X, &mp_tmp);
	CHECK_RET(ret);

	ret = mp_mul(mp_X, &mp_tmp, &mp_tmp); // x^3
	CHECK_RET(ret);

	ret = mp_mul(mp_X, mp_a, &mp_tmp2); // a*x
	CHECK_RET(ret);

	ret = mp_add(&mp_tmp, &mp_tmp2, &mp_tmp); 
	CHECK_RET(ret);

	ret = mp_addmod(&mp_tmp, mp_b, mp_p, &right); // x^3 + a*x + b (mod p) 
	CHECK_RET(ret);

	if (MP_EQ == mp_cmp(&left, &right))
	{
		ret = 0;
	}
	else{
		ret = ERR_POINT_NOT_ON_CURVE;
	}

END:
	mp_clear_multi(&left, &right, &mp_tmp, &mp_tmp2, NULL);
	return ret;
}


/*
 * instruction : GM sm2 decryption
 * param:
 * @DecData, @ulDecDataLen: [out] : decrypted data to output
 * @input, @inlen : [in] : input data to proceed
 * @pri_dA, @ulPri_dALen : [in] : private key data
 * return :
 * 0 : success
 * other errcode : operation failed
 */
int GM_SM2Decrypt(unsigned char * DecData, unsigned long * ulDecDataLen, unsigned char * input, unsigned long inlen, 
				   unsigned char * pri_dA, unsigned long ulPri_dALen)
{
	//presume the input data : [C1(65 Byte)][C2(unknown length)][C3(32 Byte)]
	if (NULL == input || 98 > inlen || NULL == pri_dA || 0 == ulPri_dALen)
	{
		return ERR_PARAM;
	}
//	unsigned char C1[65] = {0};
	unsigned char C3[32] = {0};
	unsigned char dgstC3[32] = {0};
	unsigned char * pC2  = NULL;
	unsigned char * pout = NULL;

	unsigned char tmpX2Buff[100] = {0};unsigned long tmpX2Len = 100;
	unsigned char tmpY2Buff[100] = {0};unsigned long tmpY2Len = 100;
	unsigned char * ptmp = NULL;unsigned char * p = NULL;
	int C2_len = inlen - 65 - 32;
	int ret = 0;
	int iter = 0;

	memcpy(C3, input+65+C2_len, 32);

	mp_int mp_pri_dA, mp_x1, mp_y1, mp_x2, mp_y2, mp_Xg, mp_Yg, mp_a, mp_b, mp_n, mp_p;
	mp_init_multi(&mp_pri_dA, &mp_x1, &mp_y1, &mp_x2, &mp_y2, &mp_Xg, &mp_Yg, &mp_a, &mp_b, &mp_n, &mp_p, NULL);

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
	

	pC2 = new unsigned char[C2_len+10];
	if (NULL == pC2)
	{
		return ERR_MEM_ALLOC;
	}
	memset(pC2, 0x00, C2_len+10);

	ret = BYTE_POINT_is_on_sm2_curve(input+1, 64);
	if (ret)
	{
		return ret;
	}

	ret = Byte2Mp_Int(&mp_pri_dA, pri_dA, ulPri_dALen);
	CHECK_RET(ret);

	ret = Byte2Mp_Int(&mp_x1, input+1, 32);
	CHECK_RET(ret);
	ret = Byte2Mp_Int(&mp_y1, input+33, 32);
	CHECK_RET(ret);
	
	// dA*C1 = dA*(x2,y2) = dA*[k]*(Xg,Yg)
	ret = Ecc_points_mul(&mp_x2, &mp_y2, &mp_x1, &mp_y1, &mp_pri_dA, &mp_a, &mp_p);
	CHECK_RET(ret);

	ret = Mp_Int2Byte(tmpX2Buff, &tmpX2Len, &mp_x2);
	CHECK_RET(ret);
	ret = Mp_Int2Byte(tmpY2Buff, &tmpY2Len, &mp_y2);
	CHECK_RET(ret);

#ifdef _DEBUG
	printf("(x2,y2):\n");
	printf("x2=");
	BYTE_print(tmpX2Buff, tmpX2Len);
	printf("y2=");
	BYTE_print(tmpY2Buff, tmpY2Len);
#endif
	ptmp = new unsigned char [tmpX2Len * 3];
	if (NULL == ptmp)
	{
		ret = ERR_MEM_ALLOC;
		goto END;
	}
	
	memset(ptmp, 0x00 , tmpX2Len * 3);
	memcpy(ptmp, tmpX2Buff, tmpX2Len);
	memcpy(ptmp+tmpX2Len, tmpY2Buff, tmpY2Len);
	pout = new unsigned char [C2_len + 10];
	if(NULL == pout)
	{
		ret = ERR_MEM_ALLOC;
		goto END;
	}
	memset(pout, 0x00 , C2_len + 10);
	
	// t= KDF(x2||y2, klen)
	ret = KDFwithSm3(pout, ptmp, tmpX2Len+tmpY2Len, C2_len);// t = pout
	CHECK_RET(ret);

#ifdef _DEBUG
	MP_print_Space;
	printf("KDF t=");
	BYTE_print(pout, C2_len);
#endif	
	for (iter = 0; iter<C2_len; iter++)
	{
		if(pout[iter] != 0)
			break;
	}
	if (C2_len == iter)
	{
		ret = ERR_DECRYPTION_FAILED;
		goto END;
	}

	p = pC2;
	// store the XOR result to pC2
	for (iter = 0; iter < C2_len; iter++)
	{
		*p++ = pout[iter] ^ (*(input+65+iter));
	}
	
#ifdef _DEBUG
	printf("M_ =");
	BYTE_print(pC2, C2_len);
#endif
	//  compute C3 = HASH(x2|| M || y2)
	if (ptmp)
	{
		delete []ptmp;
	}
	ptmp = new unsigned char[C2_len + tmpX2Len + tmpY2Len + 100];
	if (NULL == ptmp)
	{
		ret = ERR_MEM_ALLOC;
		goto END;
	}
	memset(ptmp, 0x00 , C2_len + tmpX2Len + tmpY2Len + 100);
	memcpy(ptmp, tmpX2Buff, tmpX2Len);
	memcpy(ptmp+tmpX2Len, pC2, C2_len);
	memcpy(ptmp+tmpX2Len+C2_len, tmpY2Buff, tmpY2Len);
	
	sm3(ptmp, tmpX2Len+C2_len+tmpY2Len, dgstC3);
	if (0 != memcmp(C3, dgstC3, 32))
	{
		ret = ERR_DECRYPTION_FAILED;
		goto END;
	}

	if (NULL == DecData)
	{
		* ulDecDataLen = C2_len;
		ret = 0;
		goto END;
	}

	if (* ulDecDataLen < C2_len)
	{
		* ulDecDataLen = C2_len;
		ret = ERR_MEM_LOW;
		goto END;
	}
	* ulDecDataLen = C2_len;
	memcpy(DecData, pC2, C2_len);
	ret = 0;

#ifdef _DEBUG
	printf("U =");
	BYTE_print(dgstC3, 32);
#endif

END:
	if (ptmp)
	{
		delete []ptmp;
	}
	if (pC2)
	{
		delete []pC2;
	}
	if (pout)
	{
		delete []pout;
	}

	mp_clear_multi(&mp_pri_dA, &mp_x1, &mp_y1, &mp_x2, &mp_y2, &mp_Xg, &mp_Yg, &mp_a, &mp_b, &mp_n, &mp_p, NULL);
	return ret;

}


/*
 * instruction : GM sm2 encryption
 * param:
 * @encData, @ulEncDataLen: [out] : encrypted data to output
 * @plain, @plainLen : [in] : input data to proceed
 * @szPubkey_XY, @ul_PubkXY_len : [in] : pubkey point (XA,YA) -> [X||Y] --total 64 byte
 * return :
 * 0 : success
 * other errcode : operation failed
 */
int GM_SM2Encrypt(unsigned char * encData, unsigned long * ulEncDataLen, unsigned char * plain, unsigned long plainLen,
				unsigned char * szPubkey_XY, unsigned long ul_PubkXY_len)
{
	
	if (NULL == plain || 0 == plainLen || NULL == szPubkey_XY || 64 != ul_PubkXY_len )
	{
		return ERR_PARAM;
	}

	unsigned char tmpX2Buff[100] = {0};unsigned long tmpX2Len = 100;
	unsigned char tmpY2Buff[100] = {0};unsigned long tmpY2Len = 100;
	unsigned char * ptmp = NULL;
	unsigned char * pout = NULL;
	unsigned char C1_buf[100] = {0};unsigned long C1_len = 100;
	unsigned char * C2_buf = NULL;unsigned long C2_len = 100;
	unsigned char C3_buf[32] = {0};
	unsigned char tmpBuff[100]  = {0}; unsigned long ulTmpBuffLen = 100;unsigned long ulTmpBuffLen2 = 100; 

	//////////////////////////////////////////////////////////////////////////
	mp_int mp_rand_k;
	mp_init_set(&mp_rand_k, 1);
#ifdef _DEBUG
	unsigned char rand_k[] = "4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F";
#endif
	
	mp_int mp_a, mp_b, mp_n, mp_p, 
		mp_Xg, mp_Yg, mp_XB, mp_YB, 
		mp_dgst, mp_x1, mp_y1, mp_x2, mp_y2;
	mp_init_multi(&mp_a, &mp_b, &mp_n, &mp_p, 
		&mp_Xg, &mp_Yg, &mp_XB, &mp_YB, 
		&mp_dgst, &mp_x1, &mp_y1, &mp_x2, &mp_y2, NULL);
	
	int ret = 0;
	int iter = 0;
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

	do 
	{
		// gen rand k < n
#ifdef _DEBUG	
		///  get rand num
		ret = mp_read_radix(&mp_rand_k, (char *) rand_k, 16);
		CHECK_RET(ret);
		ret = mp_submod(&mp_rand_k, &mp_n, &mp_n, &mp_rand_k);
		CHECK_RET(ret);
#else
		ret = genRand_k(&mp_rand_k, &mp_n);
		CHECK_RET(ret);
#endif // _DEBUG	

#ifdef _DEBUG
		MP_print_Space;
		printf("...params are...\n");
		printf("a=");
		MP_print(&mp_a);
		printf("b=");
		MP_print(&mp_b);
		printf("n=");
		MP_print(&mp_n);
		printf("p=");
		MP_print(&mp_p);
		printf("Xg=");
		MP_print(&mp_Xg);
		printf("Yg=");
		MP_print(&mp_Yg);
		printf("rand_k=");
		MP_print(&mp_rand_k);
#endif
		
		ret = Byte2Mp_Int(&mp_XB, szPubkey_XY, 32);
		CHECK_RET(ret);
		ret = Byte2Mp_Int(&mp_YB, szPubkey_XY+32, 32);
		CHECK_RET(ret);
		
		// compute C1=[k]G = (x1,y1)
		ret = Ecc_points_mul(&mp_x1, &mp_y1, &mp_Xg, &mp_Yg, &mp_rand_k, &mp_a, &mp_p);
		CHECK_RET(ret);
#ifdef _DEBUG
		MP_print_Space;
		printf("x1=");
		MP_print(&mp_x1);
		printf("y1=");
		MP_print(&mp_y1);
#endif
		C1_buf[0] = 0x04;// uncompressed curve!
		Mp_Int2Byte(tmpBuff, &ulTmpBuffLen, &mp_x1);
		memcpy(C1_buf+1, tmpBuff, ulTmpBuffLen);
		Mp_Int2Byte(tmpBuff, &ulTmpBuffLen2, &mp_y1);
		memcpy(C1_buf+1+ulTmpBuffLen, tmpBuff, ulTmpBuffLen2);
		C1_len = 1+ ulTmpBuffLen + ulTmpBuffLen2;

#ifdef _DEBUG
		MP_print_Space;
		printf("C1=");
		BYTE_print(C1_buf, C1_len);
#endif

		// compute [k]PukeyB = [k](XB,YB) = (x2,y2)
		ret = Ecc_points_mul(&mp_x2, &mp_y2, &mp_XB, &mp_YB, &mp_rand_k, &mp_a, &mp_p);
		CHECK_RET(ret);
#ifdef _DEBUG
		MP_print_Space;
		printf("x2=");
		MP_print(&mp_x2);
		printf("y2=");
		MP_print(&mp_y2);
#endif
		
		ret = Mp_Int2Byte(tmpX2Buff, &tmpX2Len, &mp_x2);
		CHECK_RET(ret);
		ret = Mp_Int2Byte(tmpY2Buff, &tmpY2Len, &mp_y2);
		CHECK_RET(ret);
		ptmp = new unsigned char [tmpX2Len * 3];
		if (NULL == ptmp)
		{
			ret = ERR_MEM_ALLOC;
			goto END;
		}

		memset(ptmp, 0x00 , tmpX2Len * 3);
		memcpy(ptmp, tmpX2Buff, tmpX2Len);
		memcpy(ptmp+tmpX2Len, tmpY2Buff, tmpY2Len);
		pout = new unsigned char [plainLen + 10];
		if(NULL == pout)
		{
			ret = ERR_MEM_ALLOC;
			goto END;
		}
		memset(pout, 0x00 , plainLen + 10);

		// t= KDF(x2||y2, klen)
		ret = KDFwithSm3(pout, ptmp, tmpX2Len+tmpY2Len, plainLen);// t = pout
		CHECK_RET(ret);
#ifdef _DEBUG
		MP_print_Space;
		printf("KDF t=");
		BYTE_print(pout, plainLen);
#endif	
		// check :if(t == 0) -> return to 1st step
		for (iter = 0; iter<plainLen; iter++)
		{
			if(pout[iter] != 0)
				break;
		}
		if (plainLen == iter)
			continue;
		else
			break;

	} while (1);

	// C2 = M XOR t
	C2_buf = new unsigned char [plainLen + 10];
	if (NULL == C2_buf)
	{
		//delete [] C2_buf;
		ret = ERR_MEM_ALLOC;
		goto END;
	}
	memset(C2_buf, 0x00, plainLen + 10);

	for (iter=0; iter<plainLen; iter++ )
	{
		C2_buf[iter] = plain[iter]^pout[iter];
	}
	C2_len = plainLen;

#ifdef _DEBUG
	MP_print_Space;
	printf("C2=");
	BYTE_print(C2_buf, C2_len);
#endif

	//  compute C3 = HASH(x2|| M || y2)
	if (ptmp)
	{
		delete []ptmp;
	}
	ptmp = new unsigned char[plainLen + tmpX2Len + tmpY2Len + 100];
	if (NULL == ptmp)
	{
		ret = ERR_MEM_ALLOC;
		goto END;
	}
	memset(ptmp, 0x00 , plainLen + tmpX2Len + tmpY2Len + 100);
	memcpy(ptmp, tmpX2Buff, tmpX2Len);
	memcpy(ptmp+tmpX2Len, plain, plainLen);
	memcpy(ptmp+tmpX2Len+plainLen, tmpY2Buff, tmpY2Len);

	sm3(ptmp, tmpX2Len+plainLen+tmpY2Len, C3_buf);


#ifdef _DEBUG
	MP_print_Space;
	printf("C3=");
	BYTE_print(C3_buf, 32);
#endif
	// output C = C1 || C2 || C3
	if (NULL == encData)
	{
		* ulEncDataLen = 32 + C2_len + C1_len;
		ret = 0;
		goto END;
	}

	if (* ulEncDataLen < 32 + C2_len + C1_len)
	{
		* ulEncDataLen = 32 + C2_len + C1_len;
		ret = ERR_MEM_LOW;
		goto END;
	}

	memcpy(encData, C1_buf, C1_len);
	memcpy(encData+C1_len, C2_buf, C2_len);
	memcpy(encData+C1_len+C2_len, C3_buf, 32);
	* ulEncDataLen = 32 + C2_len + C1_len;
#ifdef _DEBUG
	MP_print_Space;
	printf("C=");
	BYTE_print(encData, * ulEncDataLen);
#endif

	ret = 0;
END:
	if (ptmp)
	{
		delete []ptmp;
	}
	if (pout)
	{
		delete []pout;
	}
	if (C2_buf)
	{
		delete []C2_buf;
	}
	
	mp_clear_multi(&mp_a, &mp_b, &mp_n, &mp_p, 
		&mp_Xg, &mp_Yg, &mp_XB, &mp_YB, 
		&mp_dgst, &mp_x1, &mp_y1, &mp_x2, &mp_y2, &mp_rand_k, NULL);
	return ret;
}





/*
 * instruction : sm2 generate key pair
 * param:
 * @mp_pri_dA : [out] : output private key
 * @mp_XA, @mp_YA : [out] : output public key (XA,YA)
 * @mp_Xg, @mp_Yg : [in] : base point
 * @mp_a, @mp_b : [in] : curve params
 * @mp_n, @mp_p : [in] : order(n)  and field modulo(p) of Fp
 * return :
 * 0 : success
 * other errcode : operation failed
 */
int Ecc_sm2_genKeypair(mp_int * mp_pri_dA, 
					   mp_int * mp_XA, mp_int * mp_YA, 
					   mp_int * mp_Xg, mp_int * mp_Yg, 
					   mp_int * mp_a, mp_int * mp_b, mp_int * mp_n, mp_int * mp_p)
{
	int ret = 0;int iter = 0;
	mp_int mp_rand_k, mp_inf_X, mp_inf_Y;

	do 
	{
		ret = mp_init_multi(&mp_rand_k, &mp_inf_X, &mp_inf_Y, NULL);
		CHECK_RET(ret);
		ret = genRand_k(&mp_rand_k, mp_n);
		CHECK_RET(ret);

#ifdef _DEBUG
		MP_print_Space;
		printf("rand_k=");
		MP_print(&mp_rand_k);
#endif
		ret = mp_copy(&mp_rand_k, mp_pri_dA);
		CHECK_RET(ret);
		// compute public key
		ret = Ecc_points_mul(mp_XA, mp_YA, mp_Xg, mp_Yg, &mp_rand_k, mp_a, mp_p);
		CHECK_RET(ret);
		ret = MP_POINT_is_on_curve(mp_XA, mp_YA, mp_a, mp_b, mp_p);
		CHECK_RET(ret);
		
		// test//
/*#ifdef _DEBUG*/
		break;//有问题，暂时不做无穷远点检查
		// have probloms to met infinite point condition!!! ??? break!!
/*#endif*/
		
		ret = Ecc_points_mul(&mp_inf_X, &mp_inf_Y, mp_XA, mp_YA, mp_n, mp_a, mp_p);
		CHECK_RET(ret);
#ifdef _DEBUG
		MP_print_Space;
		printf("n=");
		MP_print(mp_n);
		printf("inf_X=");
		MP_print(&mp_inf_X);
		printf("inf_Y=");
		MP_print(&mp_inf_Y);
#endif
		if (MP_EQ == mp_cmp_d(&mp_inf_X, 0) && MP_EQ == mp_cmp_d(&mp_inf_Y, 0))
		{
			ret = 0;
			break;
		}
		iter ++;
	} while (iter < MAX_TRY_TIMES);
	if (MAX_TRY_TIMES == iter)
	{
		ret = ERR_GENKEY_FAILED;
		goto END;
	}
	

END:
	mp_clear_multi(&mp_rand_k, &mp_inf_X, &mp_inf_Y, NULL);
	return ret;

}

/*
 * instruction : GM sm2 generate key pair
 * param:
 * @prikey, @pulPriLen : [out] : output private key
 * @pubkey_XY : [out] : output public key [---32 bytes of X coordinate---][---32bytes of Y coordinate ---]
 * return :
 * 0 : success
 * other errcode : operation failed
 */
int GM_GenSM2keypair(unsigned char * prikey, unsigned long * pulPriLen,
					 unsigned char pubkey_XY[64])
{
	if (NULL == prikey || * pulPriLen < 32)
	{
		return ERR_PARAM;
	}

	int ret = 0;
	mp_int mp_a, mp_b, mp_n, mp_p, mp_Xg, mp_Yg, mp_pri_dA, mp_XA, mp_YA;
	mp_init_multi(&mp_a, &mp_b, &mp_n, &mp_p, &mp_Xg, &mp_Yg, &mp_pri_dA, &mp_XA, &mp_YA, NULL);
	unsigned char X[100] = {0};
	unsigned long X_len = 100;
	unsigned char Y[100] = {0};
	unsigned long Y_len = 100;
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

	ret = Ecc_sm2_genKeypair(&mp_pri_dA, &mp_XA, &mp_YA, &mp_Xg, &mp_Yg, &mp_a, &mp_b, &mp_n, &mp_p);
	CHECK_RET(ret);

	ret = Mp_Int2Byte(prikey, pulPriLen, &mp_pri_dA);
	CHECK_RET(ret);

	ret = Mp_Int2Byte(X, &X_len, &mp_XA);
	CHECK_RET(ret);

	ret = Mp_Int2Byte(Y, &Y_len, &mp_YA);
	CHECK_RET(ret);

	if (X_len+Y_len != 64)
	{
		ret = ERR_UNKNOWN;
		goto END;
	}

	memcpy(pubkey_XY, X, 32);
	memcpy(pubkey_XY+32, Y, 32);

END:
	mp_clear_multi(&mp_a, &mp_b, &mp_n, &mp_p, &mp_Xg, &mp_Yg, &mp_pri_dA, &mp_XA, &mp_YA, NULL);
	return ret;
}



/*
 * instruction : get a new point coordinate of newPoint--(x,y) = k*G
 * param:
 * @k : [in] : rand k
 * @newPoint: [in/out] new point coordinate
 * return :
 * 0 : success
 * other errcode : operation failed
 */
int BYTE_Point_mul(unsigned char k[32], unsigned char newPoint[64])
{
	int ret = 0;

	unsigned char ret_X[32] = {0};
	unsigned long l_ret_X = 32;
	unsigned char ret_Y[32] = {0};
	unsigned long l_ret_Y = 32;

	mp_int mp_a, mp_p, mp_Xg, mp_Yg, mp_k, mp_ret_x, mp_ret_y;
	mp_init_multi(&mp_a, &mp_p, &mp_Xg, &mp_Yg, &mp_k, &mp_ret_x, &mp_ret_y, NULL);
	
	ret = mp_read_radix(&mp_a, (char *) param_a, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_p, (char *) param_p, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_Xg, (char *) Xg, 16);
	CHECK_RET(ret);
	ret = mp_read_radix(&mp_Yg, (char *) Yg, 16);
	CHECK_RET(ret);
	
	ret = Byte2Mp_Int(&mp_k, k, 32);
	CHECK_RET(ret);
	// compute k*G
	ret = Ecc_points_mul(&mp_ret_x, &mp_ret_y, &mp_Xg, &mp_Yg, &mp_k, &mp_a, &mp_p);
	CHECK_RET(ret);
	
	ret = Mp_Int2Byte(ret_X, &l_ret_X, &mp_ret_x);
	CHECK_RET(ret);
	ret = Mp_Int2Byte(ret_Y, &l_ret_Y, &mp_ret_y);
	CHECK_RET(ret);

	memcpy(newPoint, ret_X, 32);
	memcpy(newPoint+32, ret_Y, 32);
END:
	mp_clear_multi(&mp_a, &mp_p, &mp_Xg, &mp_Yg, &mp_k, &mp_ret_x, &mp_ret_y, NULL);
	return ret;
}
