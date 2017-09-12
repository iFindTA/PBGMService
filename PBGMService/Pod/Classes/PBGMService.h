//
//  PBGMService.h
//  PBGMService
//
//  Created by nanhujiaju on 2017/9/11.
//  Copyright © 2017年 nanhujiaju. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface PBGMService : NSObject

NS_ASSUME_NONNULL_BEGIN

/**
 singletone mode
 */
+ (instancetype)shared;

#pragma mark --- SM2 Algorithm ---

#pragma mark --- SM3 Algorithm ---

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
- (NSData * _Nullable)sm4_encryptData:(NSData *)plainData withCipherKey:(NSString *)key;

/**
 decrypt cipher data for sm4

 @param cipherData to be decrypted
 @param key for sm4 cbc-mode
 @return decrypt result, null for error
 */
- (NSData * _Nullable)sm4_decryptData:(NSData *)cipherData withCipherKey:(NSString *)key;

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

@end

NS_ASSUME_NONNULL_END
