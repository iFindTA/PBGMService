#ifndef ____SM_2__H__45AE147B_76D4_4DB9_8FBB_00FE54E5EA79__
#define ____SM_2__H__45AE147B_76D4_4DB9_8FBB_00FE54E5EA79__

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
// #ifdef WIN32
// #ifdef SM2_DLL_EXPORTS
// #define SM2_DLL_API __declspec(dllexport)
// #else
// #define SM2_DLL_API __declspec(dllimport)
// #endif
// #else //linux or android
#ifndef SM2_DLL_API
#define SM2_DLL_API
#endif
// #endif //WIn32 -- linux -- define -- end

#include "tommath.h"


//err
#define ERR_PARAM  -2
#define ERR_MEM_ALLOC -3
#define ERR_NEED_RAND_REGEN -4
#define ERR_MEM_LOW    -5
#define ERR_DECRYPTION_FAILED -6
#define ERR_UNKNOWN     -7
#define ERR_GENKEY_FAILED  -8

#define ERR_INFINITE_POINT -10
#define ERR_POINT_NOT_ON_CURVE  -11

#define ERR_SIG_VER_R_OR_S_LARGER_THAN_N	10
#define ERR_SIG_VER_T_EQUL_ZERO				11
#define ERR_SIG_VER_R_NOT_EQUL				12
#define ERR_HEX2BYTE_PARAM_ERROR			13
#define ERR_HEX2BYTE_INVALID_DATA			14
#define ERR_HEX2BYTE_BEYOND_RANGE			15


//define 
// #define SM2_P     "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"
// #define SM2_A     "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"
// #define SM2_B     "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"
// #define SM2_N     "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"
// #define SM2_G_X   "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
// #define SM2_G_Y   "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"
extern const char * param_a;
extern const char * param_b;
extern const char * param_n;
extern const char * param_p;
extern const char * Xg;
extern const char * Yg;

//#define KEY_LONG  256
#define MAX_STRLEN  256
#define MAX_TRY_TIMES 100
#define MP_print_Space  printf("\n\n");
#define CHECK_RET(x) if (x != MP_OKAY){ret = x; \
fprintf(stderr, "%s(%d):err:%04x;desr:%s;\n", __FILE__, __LINE__, x,  mp_error_to_string(ret)); \
goto END; }



#ifdef __cplusplus
extern "C"{
#endif
/*
 * instruction : GM sm2 generate key pair
 * param:
 * @prikey, @pulPriLen : [out] : output private key
 * @pubkey_XY : [out] : output public key [---32 bytes of X coordinate---][---32bytes of Y coordinate ---]
 * return :
 * 0 : success
 * other errcode : operation failed
 */
SM2_DLL_API int GM_GenSM2keypair(unsigned char * prikey, unsigned long * pulPriLen,
					 unsigned char pubkey_XY[64]);




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
SM2_DLL_API int GM_SM2Sign(unsigned char * signedData, unsigned long * pulSigLen,
					unsigned char * Src, unsigned long SrcLen, 
					unsigned char * UserID, unsigned long lenUID,
					unsigned char * prikey, unsigned long ulPrikeyLen);



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
SM2_DLL_API int GM_SM2VerifySig(unsigned char * signedData, unsigned long ulSigLen,
				 unsigned char * Src, unsigned long SrcLen, 
				 unsigned char * UserID, unsigned long lenUID,
				 unsigned char * szPubkey_XY, unsigned long ulPubkey_XYLen);

/*
 * instruction : sm3 kdf
 * param:
 * @kdfOutBuff : [out] : output
 * @Z_in, @ulZlen : [in] : input data to proceed
 * @klen : [in] : output kdf data length 
 * return :
 * 0 : success
 * other errcode : operation failed
 */
SM2_DLL_API int KDFwithSm3(unsigned char * kdfOutBuff, unsigned char * Z_in, unsigned long ulZlen, unsigned long klen );

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
SM2_DLL_API int GM_SM2Encrypt(unsigned char * encData, unsigned long * ulEncDataLen, unsigned char * plain, unsigned long plainLen,
				  unsigned char * szPubkey_XY, unsigned long ul_PubkXY_len);
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
SM2_DLL_API int GM_SM2Decrypt(unsigned char * DecData, unsigned long * ulDecDataLen, unsigned char * input, unsigned long inlen, 
				  unsigned char * pri_dA, unsigned long ulPri_dALen);



/*
 * instruction : check if the point is on curve
 * param:
 * @pubkey_XY, @ulPubXYLen : [in] : private key data, need to be generated by the library
 * return :
 * 0 : success
 * other errcode : operation failed
 */
SM2_DLL_API int BYTE_POINT_is_on_sm2_curve(unsigned char * pubkey_XY, unsigned long ulPubXYLen);



/*
 * instruction : get a new point coordinate of newPoint--(x,y) = k*G
 * param:
 * @k : [in] : rand k
 * @newPoint: [in/out] new point coordinate [---X--32byte---][---Y--32byte---]
 * return :
 * 0 : success
 * other errcode : operation failed
 */
SM2_DLL_API int BYTE_Point_mul(unsigned char k[32], unsigned char newPoint[64]);


#ifdef __cplusplus
};
#endif


/*
 * interfaces containing mp_int params
 */


/*
 * instruction : get a large prime m of length (lon)
 * param:
 * @m : [out] : prime output
 * @lon : [in] : length input
 */
int GetPrime(mp_int *m,int lon);



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
					   mp_int * mp_a, mp_int * mp_b, mp_int * mp_n, mp_int * mp_p);

/*
 * instruction : point multiplication (result_x, result_y) = (px, py) * d
 * param:
 * @result_x ,@result_y : [out] : result point(result_x, result_y) of point multiplication
 * @px, @py : [in] : source point to multiply
 * @d : [in] : large number --  multiplier 
 * @param_a : [in] : param a of curve  y^2 = x^3 + ax + b;
 * @param_p : [in] : modulo p of finite field Fp. 
 * return :
 * 0 : success
 * other errcode : operation failed
 */
int Ecc_points_mul( mp_int *result_x,mp_int *result_y, 
					mp_int *px, mp_int *py,
					mp_int *d,
					mp_int *param_a,mp_int *param_p);

/*
 * instruction : addition of points (result_x, result_y) = (x1, y1) + (x2, y2)
 * param:
 * @result_x ,@result_y : [out] : result point(result_x, result_y) of point addition
 * @x1, @y1 : [in] : source point (x1,y1) to add
 * @x2, @y2 : [in] : another point (x2,y2) to add
 * @param_a : [in] : param a of curve  y^2 = x^3 + ax + b;
 * @param_p : [in] : modulo p of finite field Fp. 
 * return :
 * 0 : success
 * other errcode : operation failed
 */
int Ecc_points_add(mp_int *result_x,mp_int *result_y,
				   mp_int *x1,mp_int *y1,mp_int *x2,mp_int *y2,
				   mp_int *param_a, mp_int *param_p);

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
 * return :
 * 0 : success
 * other errcode : operation failed
 */
int Ecc_Sm2_sign(mp_int * mp_r, mp_int * mp_s, 
				 mp_int * mp_dgst, 
				 mp_int * mp_rand_k, mp_int * mp_Pri_dA, 
				 mp_int * mp_Xg, mp_int * mp_Yg, 
				 mp_int * param_a, mp_int * param_p, mp_int * param_n);



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
 * return :
 * 0 : success
 * other errcode : operation failed
 */
int Ecc_Sm2_verifySig(mp_int * mp_r, mp_int * mp_s, 
					  mp_int * mp_dgst, 
					  mp_int * mp_XA, mp_int * mp_YA, 
					  mp_int * mp_Xg, mp_int * mp_Yg, 
				      mp_int * param_a, mp_int * param_p, mp_int * param_n);


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
					  mp_int * mp_XA, mp_int * mp_YA);

/*
 * instruction : check if point (X,Y) is on curve  y^2 = x^3 + ax + b;
 * param:
 * @mp_X ,@mp_Y : [in] : point(X,Y) need to check 
 * @param_a : [in] : param a of curve  y^2 = x^3 + ax + b;
 * @param_b : [in] : param b of curve  y^2 = x^3 + ax + b;
 * @param_p : [in] : modulo p of finite field Fp.
 * return :
 * 0 : yes,it is on the curve
 * other errcode : the point is not on curve
 */
int MP_POINT_is_on_curve(mp_int * mp_X, mp_int * mp_Y, mp_int * mp_a, mp_int * mp_b, mp_int * mp_p);


/*
 * inner functions, don't use !
 */

/*
 * generate a random k < n
 */
int genRand_k(mp_int * rand_k, mp_int * mp_n);

/*
 * trans a mp_int into an BYTE string
 * param:
 * @tar, @lenTar : [out] : target BYTE output
 * @mp_src : [in] : input mp_int number 
 * return :
 * 0 -- ok
 */
int Mp_Int2Byte(unsigned char *tar, unsigned long *lenTar, mp_int * mp_src);

/*
 * trans an BYTE string into a mp_int  
 * param:
 * @mp_tar : [out] : output mp_int target
 * @src_byte, @lenSrc : [in] : input BYTE need to transform
 * return :
 * 0 -- ok
 */
int Byte2Mp_Int(mp_int * mp_tar, unsigned char *src_byte, unsigned long lenSrc);

/*
 *  change a string of Ascii(0--f) to BYTE str 
 *  Eg:"1A2B3C4D" (length of 8) will be trasform to byte string 0x1A2B3C4D  (length will be 4)
 *  to use it : hexCharStr2unsignedCharStr("1A2B3C4D", strlen("1A2B3C4D"), 0 , buff, &ulBuffLen);
 *¡¡params:
 *  @src, @lsrc : [in] source string
 *  @flag [in] : just input 0
 *  @out, @lout : [out] : output BYTE str
 *  return :
 *  0 -- ok; other : failed
 */
int hexCharStr2unsignedCharStr(char *src, unsigned long lsrc, int flag, unsigned char * out, unsigned long * lout);



/*
 * just for test
 */

#ifdef __cplusplus
extern "C"{
#endif


SM2_DLL_API char * getVersion();
SM2_DLL_API int testKDF_SM3();
SM2_DLL_API int testPointOnCurve();
SM2_DLL_API int alloctest();
SM2_DLL_API int test_Ecc_Intrfs_sig_veri();
SM2_DLL_API int test_SM3_withZ_value_process();
SM2_DLL_API int test_GM_encryption_and_decryption();
SM2_DLL_API int test_GM_signature_and_verify();
SM2_DLL_API int test_gen_SM2_GM_keypair();

#ifdef __cplusplus
};
#endif

int MP_print(mp_int * mp_num);
void BYTE_print(unsigned char * tar, unsigned long l);


#endif   //____SM_2__H__45AE147B_76D4_4DB9_8FBB_00FE54E5EA79__