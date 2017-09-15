#ifndef   _____GM_DEFINE___H____
#define   _____GM_DEFINE___H____


#define ECC_MAX_XCOORDINATE_BITS_LEN 512	//ECC算法X座标的最大长度
#define ECC_MAX_YCOORDINATE_BITS_LEN 512	//ECC算法Y座标的最大长度
#define ECC_MAX_MODULUS_BITS_LEN 512		//ECC算法模数的最大长度

typedef  unsigned long ULONG;
typedef  char          CHAR;
typedef  unsigned char BYTE;


#define MAX_IV_LEN			32		//初始化向量的最大长度


#pragma pack(1)


/*
 *ECC公钥交换数据块
 */
typedef struct Struct_ECCPUBLICKEYBLOB{
	ULONG	BitLen;
	BYTE	XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
	BYTE	YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN/8];
}ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;

/*
 *ECC私钥交换数据块
 */
typedef struct Struct_ECCPRIVATEKEYBLOB{
	ULONG	BitLen;
	BYTE	PrivateKey[ECC_MAX_MODULUS_BITS_LEN/8];
}ECCPRIVATEKEYBLOB, *PECCPRIVATEKEYBLOB;

/*
 *ECC密文数据结构
 */
typedef struct Struct_ECCCIPHERBLOB{
	BYTE	XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8]; 
	BYTE	YCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8]; 
	BYTE	HASH[32]; 
	ULONG	CipherLen;
	BYTE	Cipher[65]; //国密规范中定义的Ciper只有一个字节，实际中至少64字节
} ECCCIPHERBLOB, *PECCCIPHERBLOB;


typedef struct Struct_ECCSIGNATUREBLOB{
	BYTE	r[ECC_MAX_XCOORDINATE_BITS_LEN/8];
	BYTE	s[ECC_MAX_YCOORDINATE_BITS_LEN/8];
} ECCSIGNATUREBLOB, *PECCSIGNATUREBLOB;

//　ECC加密密钥对保护结构
typedef struct SKF_ENVELOPEDKEYBLOB{
	ULONG Version;                  // 当前版本为 1
	ULONG ulSymmAlgID;              // 对称算法标识，限定ECB模式
	ULONG ulBits;					// 加密密钥对的密钥位长度
	BYTE cbEncryptedPriKey[64];     // 加密密钥对私钥的密文
	ECCPUBLICKEYBLOB PubKey;        // 加密密钥对的公钥
	ECCCIPHERBLOB ECCCipherBlob;    // 用保护公钥加密的对称密钥密文。
}ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;

/*
 *分组密码参数
 */
typedef struct Struct_BLOCKCIPHERPARAM{
	BYTE	IV[MAX_IV_LEN];			//初始向量，MAX_IV_LEN为初始向量的最大长度
	ULONG	IVLen;					//初始向量实际长度，按字节计算
	ULONG	PaddingType;			//填充方式，0表示不填充，1表示按照PKCS#5方式进行填充
	ULONG	FeedBitLen;				//反馈值的位长度，按字节计算，只针对OFB、CFB模式
} BLOCKCIPHERPARAM, *PBLOCKCIPHERPARAM;

/*
 *文件属性
 */
typedef struct Struct_FILEATTRIBUTE{
	CHAR	FileName[32];			//文件名
	ULONG	FileSize;				//文件大小
	ULONG	ReadRights;				//读权限
	ULONG	WriteRights;			//写权限
} FILEATTRIBUTE, *PFILEATTRIBUTE;

#pragma pack()


#endif //_____GM_DEFINE___H____