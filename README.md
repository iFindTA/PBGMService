# PBGMService
国密 SM2/SM3/SM4 Objective-C2.0封装！目前仅有iOS平台，更多平台请稍后...

### 前言
	鉴于目前网上关于国密算法资料都是零散不完整的现状，作者近两天整理了一下相关的算法并公布出来，以期望大家能够方便的在iOS平台更方便的使用国密算法
	作者观点：算法不是重点！重点是如何提高密钥的安全性（譬如动态白盒）！！！
	觉得有用就亮个Star！
### Usage
#### 关键类：PBGMService
```Objective-C
#pragma mark --- SM2 Algorithm ---

/**
 random key-pairs for sm2

 @return [0][1] for public-key, [2] for private-key
 */
- (NSArray <NSString *>*)randomSM2KeyPairs;

/**
 encrypt plain string with sm2

 @param str for plain string
 @param key for public
 @return cipher string
 */
- (NSString * _Nullable)sm2_encryptPlainString:(NSString *)str withPublicKey:(NSString *)key;

/**
 decrypt cipher string with sm2

 @param str for cipher string
 @param key for private
 @return plain string
 */
- (NSString * _Nullable)sm2_decryptCipherString:(NSString *)str withPrivateKey:(NSString *)key;

/**
 sign plain string for sm2

 @param str for plain string
 @param uid user-identifier
 @param key for private
 @return signed string
 */
- (NSString * _Nullable)sm2_signPlainString:(NSString *)str withUID:(NSString *)uid withPrivateKey:(NSString *)key;

/**
 verify sign with plain string for sm2

 @param str for plain string
 @param sign for signed string
 @param uid user-identifier
 @param key for public
 @return whether equal origin
 */
- (BOOL)sm2_verifyWithPlainString:(NSString *)str withSigned:(NSString *)sign withUID:(NSString *)uid withPublicKey:(NSString *)key;

#pragma mark --- SM3 Algorithm ---

/**
 hash data for sm3

 @param plainData for input plain data
 @return hash result, null for error
 */
- (NSData * _Nullable)sm3_hashWithPainData:(NSData *)plainData;

/**
 hash file for sm3

 @param path for plain data file path
 @param completion callback for hash result
 */
- (void)sm3_hashWithFilePath:(NSString *)path withCompletion:(void(^_Nullable)(NSError*_Nullable err, NSData *_Nullable hash))completion;

#pragma mark --- SM4 Algorithm ---

/**
 random iv for sm4
 */
- (NSString *)randomSM4IV __attribute((deprecated(("not use anymore!"))));

/**
 random key for sm4
 */
- (NSString *)randomSM4Key;

/**
 encrypt plain data for sm4

 @param plainData to be encrypted
 @param key for sm4 cbc-mode
 @return encrypt result, null for error
 */
- (NSData * _Nullable)sm4_encryptData:(NSData *)plainData withCipherKey:(NSString *)key NS_AVAILABLE_IOS(8_0);

/**
 decrypt cipher data for sm4

 @param cipherData to be decrypted
 @param key for sm4 cbc-mode
 @return decrypt result, null for error
 */
- (NSData * _Nullable)sm4_decryptData:(NSData *)cipherData withCipherKey:(NSString *)key NS_AVAILABLE_IOS(8_0);

/**
 encrypt plain file for sm4-ecb

 @param srcPath for origin file path
 @param desPath for destnation file path
 @param key for sm4-ecb
 @param completion for call back, null error if success
 */
- (void)sm4_encryptFile:(NSString *)srcPath withDestFilePath:(NSString *)desPath withCipherKey:(NSString *)key withCompletion:(void(^_Nullable)(NSError*_Nullable err))completion;

/**
 decrypt cipher file for sm4-ecb

 @param srcPath for cipher file path
 @param desPath for plain file path
 @param key fir sm4-ecb
 @param completion for call back, null error if success
 */
- (void)sm4_decryptFile:(NSString *)srcPath withDestFilePath:(NSString *)desPath withCipherKey:(NSString *)key withCompletion:(void(^_Nullable)(NSError*_Nullable err))completion;
```

#### 引入步骤：
##### step 1:引入framework（不到3M大小）
	工程根文件夹-->PBSMx-->framework-->PBSMx.framework
	PBSMx.framework（支持i386/x86_64/armv7/arm64）是已经编译好的静态库，可以直接使用，引入工程即可（target-->build phase-->link binary with libraries）
##### step2:pod install --OpenSSL
	framework依赖于OpenSSL运行，因为SM2算法的实现依赖于OpenSSL，直接用Pod引入方式即可：
	pod 'OpenSSL', '~> 1.0.210'
##### step3:Other link flags
	SM2算法C++部分编译需要。设置Other Linker Flags添加：
	"-lstdc++"
#### 编译即可，enjoy it！

#### 参考资料：在此一并感谢资料提供者！
1，[sm2算法参考](https://github.com/dishibolei/SM2)，此算法中作者实现了SM2密钥生成和加解密，未实现签名和验证签名，作者补气了签名和验签的方法

2，[sm3/sm4参考](http://www.cnblogs.com/TaiYangXiManYouZhe/p/4317519.html)

#### TODO List:
* 1，密钥安全性（动态白盒、静态白盒），作者觉得这才是重点！

* 2，SM9算法的引入及使用

* 3，AES的GCM模式、NI模式等的引入

* 4，android、golang、java等更多平台的支持！

#### feedback
	nanhujiaju@gmail.com