//
//  PBGMService.h
//  PBGMService
//
//  Created by nanhujiaju on 2017/9/11.
//  Copyright © 2017年 nanhujiaju. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PBBase64.h"

@interface PBGMService : NSObject

NS_ASSUME_NONNULL_BEGIN

/**
 singletone mode
 */
+ (instancetype)shared;

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

/**
 encrypt plain stream byte for sm4-ecb

 @param inBytes plain bytes
 @param inLen plain byte len
 @param outBytes out cipher bytes
 @param outLen out length
 @param key cipher key
 */
- (void)sm4_encryptStream:(const Byte *)inBytes inLength:(unsigned int)inLen withOutput:(Byte *)outBytes outLength:(unsigned int *)outLen withCipherKey:(NSString *)key;

/**
 decrypt cipher stream byte for sm4-ecb

 @param inBytes cipher bytes
 @param inLen cipher byte len
 @param outBytes out plain bytes
 @param outLen out plain byte len
 @param key cipher key
 */
- (void)sm4_decryptStream:(const Byte *)inBytes  inLength:(unsigned int)inLen withOutput:(Byte *)outBytes outLength:(unsigned int *)outLen withCipherKey:(NSString *)key;

#pragma mark --- TODO:SM9 Algprithm ---

#pragma mark --- AES-GCM-128 Algorithm ---

/**
 random key for gcm128-aes
 */
- (NSString *)randomAESGCM128Key;

/**
 AES-GCM-128 encrypt method

 @param plainData for plain-input
 @param key for aes-gcm
 @return cipher data
 */
- (NSData * _Nullable)aes_gcm128EncryptData:(NSData *)plainData withKey:(NSString *)key;

/**
 AES-GCM-128 decrypt method

 @param cipherData for cipher-input
 @param key for aes-gcm
 @return plain data
 */
- (NSData * _Nullable)aes_gcm128DEcryptData:(NSData *)cipherData withKey:(NSString *)key;

@end

NS_ASSUME_NONNULL_END
