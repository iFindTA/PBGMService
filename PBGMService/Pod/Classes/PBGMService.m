//
//  PBGMService.m
//  PBGMService
//
//  Created by nanhujiaju on 2017/9/11.
//  Copyright © 2017年 nanhujiaju. All rights reserved.
//

#import "PBGMService.h"
#import "sm2.h"
#import "sm3.h"
#import "sm4.h"
#import "aes-gcm.h"
#import <CommonCrypto/CommonCrypto.h>

//static unsigned int const CURRENT_VERSION   =   23;
static unsigned int const SM4_BLOCK_SIZE    =   16;
//static unsigned int const AES_BLOCK_SIZE    =   16;
static unsigned int const BLOCK_SIZE_CRYPTO         =   1024;
/** vector for aes/sm4 **/
static NSString * const IV_SM4              =   @"sm4ivectorcodec1";
// SM4 singed encrypt count
static unsigned int const SM4_ENCRYPT_SIZE = 32;

@interface PBGMService ()

@end

static PBGMService * instance = nil;

@implementation PBGMService

+ (instancetype)shared {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[[self class] alloc] init];
    });
    return instance;
}

#pragma mark --- util kit methods ---

- (NSString *)randomString4Length:(unsigned int)len {
    if (len<=0) {
        return nil;
    }
    NSString *sourceString = @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    NSMutableString *result = [[NSMutableString alloc] init];
    //srand((unsigned)time(0));
    unsigned c_len = (unsigned)sourceString.length;
    for (int i = 0; i < len; i++){
        //unsigned index = rand() % [sourceString length];
        unsigned index = arc4random() % c_len;
        NSString *s = [sourceString substringWithRange:NSMakeRange(index, 1)];
        [result appendString:s];
    }
    return result.copy;
}

- (NSString *)string2Hex:(NSString *)plain {
    NSData *myD = [plain dataUsingEncoding:NSUTF8StringEncoding];
    Byte *bytes = (Byte *)[myD bytes];
    //下面是Byte 转换为16进制。
    NSString *hexStr=@"";
    for(int i=0;i<[myD length];i++) {
        NSString *newHexStr = [NSString stringWithFormat:@"%x",bytes[i]&0xff];///16进制数
        
        if([newHexStr length]==1){
            hexStr = [NSString stringWithFormat:@"%@0%@",hexStr,newHexStr];
        } else {
            hexStr = [NSString stringWithFormat:@"%@%@",hexStr,newHexStr];
        }
    }
    return hexStr;
}

#pragma mark --- SM4 Algorithm ---

- (NSString *)randomSM4IV {
    return [self randomString4Length:SM4_BLOCK_SIZE];
}

- (NSString *)randomSM4Key {
    return [self randomString4Length:SM4_BLOCK_SIZE];//32bit for 256-mode
}

- (NSData *)sm4_encryptAndWorkplatform:(NSData *)plainData keyData:(NSData *)keyData ivData:(NSData *)ivData
{
    if (plainData == nil) {
        NSLog(@"got an empty data!");
        return nil;
    }
    if (keyData.length != SM4_BLOCK_SIZE) {
        NSLog(@"got a bad sm4 key!");
        return nil;
    }
    
    // - 获取明文字节数据
    int plainInDataLength = (int)plainData.length;
    // - 根据余数计算填充的位数，默认为0，p是需要填充的数据也是填充的位数
    int p = 0;
    int diff = SM4_BLOCK_SIZE/2;
    if (plainInDataLength < diff) {
        // 例如明文数据：12，需要补4
        p = SM4_BLOCK_SIZE - plainInDataLength;
        diff = SM4_BLOCK_SIZE;
    } else {
        if (plainInDataLength%diff != 0) {
            p = diff - plainInDataLength % diff;
        } else {
            diff = SM4_BLOCK_SIZE;
        }
    }
    // - 声明输出字节，长度为明文字节+补位长度
    int dataLength = plainInDataLength + p;
    
    unsigned char cipherOutChar[dataLength];
    const char *utf8Key = (const char *)keyData.bytes;
    size_t len = keyData.length;
    unsigned char sm4Key[len];
    memcpy(sm4Key, utf8Key, len);
    
    // - 声明输入字节，缺省位自动补 0x00
    unsigned char plainInChar[dataLength];
    memcpy(plainInChar, plainData.bytes, plainInDataLength);
    for (int i = 0; i<p; i++) {
        plainInChar[plainInDataLength+i] = 0x00;
    }
    sm4_context ctx;
    // - 设置上下文和密钥
    sm4_setkey_enc(&ctx,sm4Key);
    // - 加密
    if (ivData.length > 0) {
        // cbc模式，加密
        const char *vector = (const char *)ivData.bytes;
        for (int i = 0; i<dataLength; i++) {
            plainInChar[i] = (unsigned char) (plainInChar[i] ^ vector[i%16]);
        }
        sm4_crypt_iterator(&ctx, SM4_ENCRYPT, dataLength, plainInChar, cipherOutChar, SM4_ENCRYPT_SIZE);
    } else {
        // ecb模式，加密
        sm4_crypt_iterator(&ctx, SM4_ENCRYPT, dataLength, plainInChar, cipherOutChar, SM4_ENCRYPT_SIZE);
    }
    // - 获取加密结果
    NSData *cipherTextData =  [[NSData alloc]initWithBytes:cipherOutChar length:dataLength];
    return cipherTextData;
}

- (NSData *)sm4_decryptAndWorkplatform:(NSData *)cihperData keyData:(NSData *)keyData ivData:(NSData *)ivData
{
    if (cihperData == nil) {
        NSLog(@"got an empty data!");
        return nil;
    }
    if (keyData.length != SM4_BLOCK_SIZE) {
        NSLog(@"got a bad sm4 key!");
        return nil;
    }
    // - 将密文转换为字节
    unsigned char cipherTextChar[cihperData.length];
    memcpy(cipherTextChar, cihperData.bytes, cihperData.length);
    
    // - 将密钥转换为字节
    const char* utf8Key = (const char *)[keyData bytes];
    size_t len = keyData.length;
    unsigned char sm4Key[len];
    memcpy(sm4Key, utf8Key, len);
    
    // - 声明输出是明文字节plainOutChar
    unsigned char plainOutChar[cihperData.length];
    int dataLength = (int)cihperData.length;
    // 执行sm4解密
    sm4_context ctx;
    sm4_setkey_dec(&ctx,sm4Key);
    
    if (ivData.length > 0) {
        // 先进行解密迭代
        sm4_crypt_iterator(&ctx, SM4_DECRYPT, dataLength, cipherTextChar, plainOutChar, SM4_ENCRYPT_SIZE);
        // cbc模式，解密运算
        const char *vector = (const char *)ivData.bytes;
        // 对整数倍的密文，进行分块处理，异或运算
        for (int i = 0; i<dataLength; i++) {
            plainOutChar[i] = (unsigned char) (plainOutChar[i] ^ vector[i%16]);
        }
    } else {
        // ecb模式，加密
        sm4_crypt_iterator(&ctx, SM4_DECRYPT, (int)cihperData.length, cipherTextChar, plainOutChar, SM4_ENCRYPT_SIZE);
    }
    
    
    // - 获取解密结果
    NSData *plainTextData =  [[NSData alloc]initWithBytes:plainOutChar length:dataLength];
    return plainTextData;
}

- (NSData * _Nullable)sm4_encryptData:(NSData *)plainInData withCipherKey:(NSString *)key {
    if (plainInData == nil) {
        NSLog(@"got an empty data!");
        return plainInData;
    }
    if (key.length != SM4_BLOCK_SIZE) {
        NSLog(@"got a bad sm4 key!");
        return nil;
    }
    
    //a.对明文数据进行填充来保证位数是16的倍数
    int plainInDataLength = (int)plainInData.length;
    //  p是需要填充的数据也是填充的位数
    int p = SM4_BLOCK_SIZE - plainInDataLength % SM4_BLOCK_SIZE;
    unsigned char plainInChar[plainInDataLength + p];
    memcpy(plainInChar, plainInData.bytes, plainInDataLength);
    //  进行数据填充
    for (int i = 0; i < p; i++) {
        plainInChar[plainInDataLength + i] =  p;
    }
    
    //b.验证一下填充后的char[]是不是最开始的明文数据
    //    NSLog(@"plainInData=%@",plainInData);
    //    NSData *data = [[NSData alloc]initWithBytes:plainInChar length:sizeof(plainInChar)-p];
    //    NSLog(@"data=%@",data);
    //    NSLog(@"填充后的char[]转成NSString=%@",[[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding]);
    
    
    //4.对plainInChar加密，由于源代码中加解密是放在一起的，现在在sm4test.c中新添加两个方法把加密和解密分开,由于计算length总出问题，所以直接把length作为参数传进去
    
    //5.调用刚才添加的方法加密
    //定义输出密文的变量
    unsigned char cipherOutChar[plainInDataLength + p];
    unsigned char iv[16]   = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    //unsigned char key[16]   = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    //const unsigned char * key_char = [key UTF8String];
    const char* utf8Key = [key UTF8String];
    size_t len = strlen(utf8Key) + 1;
    unsigned char sm4Key[len];
    memcpy(sm4Key, utf8Key, len);
    sm4_context ctx;
    //设置上下文和密钥
    sm4_setkey_enc(&ctx,sm4Key);
    //加密
    //sm4_crypt_ecb(&ctx,1,lenght,in,output);
    sm4_crypt_cbc(&ctx, SM4_ENCRYPT, plainInDataLength + p, iv, plainInChar, cipherOutChar);
    //testEncodejiami(plainInDataLength + p, plainInChar, cipherOutChar);
    //对加密的数据输出
    NSData *cipherTextData =  [[NSData alloc]initWithBytes:cipherOutChar length:sizeof(cipherOutChar)];
    //    NSLog(@"密文NSData=%@",cipherTextData);
    //    NSLog(@"密文转成NSString=%@",[[NSString alloc]initWithData:cipherTextData encoding:NSUTF8StringEncoding]);
    return cipherTextData;
}

- (NSData * _Nullable)sm4_decryptData:(NSData *)cipherData withCipherKey:(NSString *)key {
    if (cipherData == nil) {
        NSLog(@"got an empty data!");
        return cipherData;
    }
    if (key.length != SM4_BLOCK_SIZE) {
        NSLog(@"got a bad sm4 key!");
        return nil;
    }
    unsigned char iv[16]   = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    const char* utf8Key = [key UTF8String];
    size_t len = strlen(utf8Key) + 1;
    unsigned char sm4Key[len];
    memcpy(sm4Key, utf8Key, len);
    
    //6将cipherTextData作为输入，调用第4步的解密方法，进行解密
    //将data拷贝到字符数组中
    unsigned char cipherTextChar[cipherData.length];
    memcpy(cipherTextChar, cipherData.bytes, cipherData.length);
    //调用解密方法，输出是明文plainOutChar
    unsigned char plainOutChar[cipherData.length];
    //testDecodejiemi(cipherTextData.length, cipherTextChar, plainOutChar);
    //设置上下文和密钥
    sm4_context ctx;
    sm4_setkey_dec(&ctx,sm4Key);
    sm4_crypt_cbc(&ctx, SM4_DECRYPT, (int)cipherData.length, iv, cipherTextChar, plainOutChar);
    
    //由于明文是填充过的，解密时候要去填充，去填充要在解密后才可以，在解密前是去不了的
    int p2 = plainOutChar[sizeof(plainOutChar) - 1];//p2是填充的数据，也是填充的长度
    int outLength = (int)cipherData.length-p2;//明文的长度
    //去掉填充得到明文
    unsigned char plainOutWithoutPadding[outLength];
    memcpy(plainOutWithoutPadding, plainOutChar, outLength);
    //明文转成NSData 再转成NSString打印
    NSData *outData = [[NSData alloc]initWithBytes:plainOutWithoutPadding length:sizeof(plainOutWithoutPadding)];
    
    return outData;
}

static inline NSError * assembleErrorWithDomain(NSString *domain) {
    return [NSError errorWithDomain:domain code:-1 userInfo:nil];
}

long file_len(FILE *file) {
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    return size;
}

#define FILE_MAX_CRYPTO_SIZE 1024 * 1024 * 10 //10M
#define FILE_BLOCK_SIZE 128 //16K
#define VERSION_PREFIX_LEN 4 //前四个字节 携带版本信息
- (void)sm4_encryptFile:(NSString *)srcPath withDestFilePath:(NSString *)desPath withCipherKey:(NSString *)key withCompletion:(void (^ _Nullable)(NSError * _Nullable))completion {
    NSAssert(srcPath.length != 0, @"could not read an empty path!");
    NSAssert(desPath.length != 0, @"could not open an empty path!");
    NSAssert(key.length == SM4_BLOCK_SIZE, @"got a bad key for sm4-ecb!");
    //whether file exist
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if (![fileManager fileExistsAtPath:srcPath]) {
        if (completion) {
            NSError *err = assembleErrorWithDomain(@"could not read an empty file!");
            completion(err);
        }
        return;
    }
    //Byte version[VERSION_PREFIX_LEN] = {1,1,1,1};
    NSError *err = nil;
    FILE *in_f = NULL, *out_f = NULL;
    long in_len = 0, file_length = 0;
    
    const char* utf8Key = [key UTF8String];
    size_t utf_len = strlen(utf8Key) + 1;
    unsigned char sm4Key[utf_len];
    memcpy(sm4Key, utf8Key, utf_len);
    
    //open in_file and out_file
    const char * in_file = [srcPath UTF8String];
    const char * out_file = [desPath UTF8String];
    in_f = fopen(in_file, "rb");
    if (in_f == NULL) {
        err = assembleErrorWithDomain(@"failed to open in file!");
        goto encrypt_file_end;
    }
    out_f = fopen(out_file, "wb");
    if (out_f == NULL) {
        err = assembleErrorWithDomain(@"failed to open out file!");
        goto encrypt_file_end;
    }
    //detect file length
    file_length = file_len(in_f);
    if (file_length < 0) {
        err = assembleErrorWithDomain([NSString stringWithFormat:@"failed to detect file length:%ld", file_length]);
        goto encrypt_file_end;
    }
    //read block caches
    Byte in[FILE_BLOCK_SIZE + SM4_BLOCK_SIZE];
    Byte out[FILE_BLOCK_SIZE + SM4_BLOCK_SIZE];
    size_t count = 0, read_len = 0;
    size_t len, w;
    int block_size = SM4_BLOCK_SIZE;
    
    //write version to dest file
    //    w = fwrite(version, sizeof(Byte), VERSION_PREFIX_LEN, out_f);
    //    if (w != VERSION_PREFIX_LEN) {
    //        err = assembleErrorWithDomain(@"write version to dest file error!");
    //        goto encrypt_file_end;
    //    }
    
    //read cycle
    in_len = file_length < FILE_MAX_CRYPTO_SIZE ? file_length : FILE_MAX_CRYPTO_SIZE;//最多加密定义的大小
    while (1) {
        len = fread(in, sizeof(Byte), FILE_BLOCK_SIZE, in_f);
        read_len += len;
        
        //if block size not divide by SM4_BLOCK_SIZE and there is more data left, error accoured
        if (len != FILE_BLOCK_SIZE && len != in_len - count) {
            err = assembleErrorWithDomain(@"read file error");
            fclose(out_f); remove(out_file);
            goto encrypt_file_end;
        }
        //last block
        if (len == in_len - count) {
            Byte padding = (len + block_size) / block_size * block_size - len;
            memset(in + len, padding, padding);
            len += padding;
        }
        //encrypt block
        sm4_context ctx;
        sm4_setkey_enc(&ctx, sm4Key);
        sm4_crypt_ecb(&ctx, SM4_ENCRYPT, (int)len, in, out);
        //write to out file
        w = fwrite(out, sizeof(Byte), len, out_f);
        if (w != len) {
            err = assembleErrorWithDomain([NSString stringWithFormat:@"write out file error:%zu", w]);
            goto encrypt_file_end;
        }
        
        count += len;
        
        if (count >= in_len) {
            break;
        }
    }
    
    //fixed length when there file size > max_len(10M)
    while (read_len < file_length) {
        len = fread(in, sizeof(Byte), FILE_BLOCK_SIZE, in_f);
        read_len += len;
        //if block size not divide by SM4_BLOCK_SIZE and there is more data left, error accoured
        if (len != FILE_BLOCK_SIZE && read_len != file_length) {
            err = assembleErrorWithDomain(@"read file error");
            fclose(out_f); remove(out_file);
            goto encrypt_file_end;
        }
        //write to out file
        w = fwrite(in, sizeof(Byte), len, out_f);
        if (w != len) {
            err = assembleErrorWithDomain([NSString stringWithFormat:@"write out file error:%zu", w]);
            goto encrypt_file_end;
        }
        
        count += len;
    }
    
    count += VERSION_PREFIX_LEN;
    //*out_len = count;修正文件最后大小
    
encrypt_file_end:
    if (in_f) fclose(in_f);
    if (out_f) fclose(out_f);
    
    if (completion) {
        completion(err);
    }
}

- (void)sm4_decryptFile:(NSString *)srcPath withDestFilePath:(NSString *)desPath withCipherKey:(NSString *)key withCompletion:(void (^ _Nullable)(NSError * _Nullable))completion {
    NSAssert(srcPath.length != 0, @"could not read an empty path!");
    NSAssert(desPath.length != 0, @"could not open an empty path!");
    NSAssert(key.length == SM4_BLOCK_SIZE, @"got a bad key for sm4-ecb!");
    //whether file exist
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if (![fileManager fileExistsAtPath:srcPath]) {
        if (completion) {
            NSError *err = [NSError errorWithDomain:@"could not read an empty file!" code:-1 userInfo:nil];
            completion(err);
        }
        return;
    }
    
    //Byte version[VERSION_PREFIX_LEN];
    NSError *err = nil;
    FILE *in_f = NULL, *out_f = NULL;
    long in_len = 0, file_length = 0;
    
    const char* utf8Key = [key UTF8String];
    size_t utf_len = strlen(utf8Key) + 1;
    unsigned char sm4Key[utf_len];
    memcpy(sm4Key, utf8Key, utf_len);
    
    //open in_file and out_file
    const char * in_file = [srcPath UTF8String];
    const char * out_file = [desPath UTF8String];
    in_f = fopen(in_file, "rb");
    if (in_f == NULL) {
        err = assembleErrorWithDomain(@"failed to open in file!");
        goto decrypt_file_end;
    }
    out_f = fopen(out_file, "wb");
    if (out_f == NULL) {
        err = assembleErrorWithDomain(@"failed to open out file!");
        goto decrypt_file_end;
    }
    //detect file length
    file_length = file_len(in_f);
    if (file_length < 0) {
        err = assembleErrorWithDomain([NSString stringWithFormat:@"failed to detect file length:%ld", file_length]);
        goto decrypt_file_end;
    }
    if (file_length < VERSION_PREFIX_LEN) {
        err = assembleErrorWithDomain(@"ciphertext too short!");
        goto decrypt_file_end;
    }
    //read block caches
    Byte in[FILE_BLOCK_SIZE];
    Byte out[FILE_BLOCK_SIZE];
    size_t count = 0, read_len = 0;
    size_t len, block_len;
    size_t w;
    size_t len_tmp;
    
    //    w = fread(version, sizeof(Byte), VERSION_PREFIX_LEN, in_f);
    //    if (w != VERSION_PREFIX_LEN) {
    //        err = assembleErrorWithDomain(@"read in_file error");
    //        goto decrypt_file_end;
    //    }
    
    //start decrypt
    int block_size = SM4_BLOCK_SIZE;
    in_len = file_length < (FILE_MAX_CRYPTO_SIZE + VERSION_PREFIX_LEN + block_size)?file_length:(FILE_MAX_CRYPTO_SIZE+VERSION_PREFIX_LEN+block_size);
    if ((in_len - VERSION_PREFIX_LEN) % block_size != 0) {
        err = assembleErrorWithDomain([NSString stringWithFormat:@"illegal in_file length: %ld.\n", in_len]);
        goto decrypt_file_end;
    }
    while (1) {
        block_len = (in_len - read_len) < FILE_BLOCK_SIZE?(in_len-read_len):FILE_BLOCK_SIZE;
        len = fread(in, sizeof(Byte), block_len, in_f);
        read_len += len;
        if (len != FILE_BLOCK_SIZE && len != in_len - count - VERSION_PREFIX_LEN) {
            fclose(out_f);remove(out_file);
            err = assembleErrorWithDomain([NSString stringWithFormat:@"read file error: %zu.\n", len]);
            goto decrypt_file_end;
        }
        //decrypt block
        sm4_context ctx;
        sm4_setkey_dec(&ctx, sm4Key);
        sm4_crypt_ecb(&ctx, SM4_DECRYPT, (int)len, in, out);
        
        len_tmp = len;
        if (len == in_len - VERSION_PREFIX_LEN - count) {
            Byte padding = out[len - 1];
            len_tmp -= padding;
        }
        //write to out file
        w = fwrite(out, sizeof(Byte), len_tmp, out_f);
        if (w != len_tmp) {
            err = assembleErrorWithDomain([NSString stringWithFormat:@"write out_file error: %zu.\n", w]);
            goto decrypt_file_end;
        }
        if (count + len >= in_len - VERSION_PREFIX_LEN) {
            count += len_tmp;
            break;
        }
        
        count += len;
    }
    
    //fixed while origin file size > fileMax(10M)
    if (file_length > FILE_MAX_CRYPTO_SIZE + VERSION_PREFIX_LEN + block_size) {
        while (read_len < file_length) {
            len = fread(in, sizeof(Byte), FILE_BLOCK_SIZE, in_f);
            read_len += len;
            if (len != FILE_BLOCK_SIZE && read_len != file_length) {
                err = assembleErrorWithDomain([NSString stringWithFormat:@"read file error: %zu.\n", len]);
                goto decrypt_file_end;
            }
            //write to out file
            w = fwrite(in, sizeof(Byte), len, out_f);
            if (w != len) {
                err = assembleErrorWithDomain([NSString stringWithFormat:@"write out_file error: %zu.\n", w]);
                goto decrypt_file_end;
            }
            count += len;
        }
    }
    
    //*out_len = count;
    
decrypt_file_end:
    if (in_f) fclose(in_f);
    if (out_f) fclose(out_f);
    
    if (completion) {
        completion(err);
    }
}
- (void)sm4_encryptStream:(const Byte *)inBytes inLength:(unsigned int)inLen withOutput:(Byte *)outBytes outLength:(unsigned int *)outLen withCipherKey:(NSString *)key {
    NSAssert(key.length != 0, @"could not use an empty cipher key!");
    //prepare for key
    const char* utf8Key = [key UTF8String];
    size_t utf_len = strlen(utf8Key) + 1;
    unsigned char sm4Key[utf_len];
    memcpy(sm4Key, utf8Key, utf_len);
    //block size
    int block_size = SM4_BLOCK_SIZE;
    size_t len = inLen/block_size * block_size;
    unsigned char *input = malloc(sizeof(Byte) * len);
    memcpy(input, inBytes, len);
    //encrypt with sm4-ecb
    sm4_context ctx;
    sm4_setkey_enc(&ctx, sm4Key);
    sm4_crypt_ecb(&ctx, SM4_ENCRYPT, (int)len, input, outBytes + VERSION_PREFIX_LEN);
    //done
    memcpy(outBytes + VERSION_PREFIX_LEN + len, inBytes + len, inLen - len);
    *outLen = inLen + VERSION_PREFIX_LEN;
    free(input);
}

- (void)sm4_decryptStream:(const Byte *)inBytes inLength:(unsigned int)inLen withOutput:(Byte *)outBytes outLength:(unsigned int *)outLen withCipherKey:(NSString *)key {
    NSAssert(key.length != 0, @"could not use an empty cipher key!");
    //prepare for key
    const char* utf8Key = [key UTF8String];
    size_t utf_len = strlen(utf8Key) + 1;
    unsigned char sm4Key[utf_len];
    memcpy(sm4Key, utf8Key, utf_len);
    //block size
    int block_size = SM4_BLOCK_SIZE;
    size_t len = (inLen - VERSION_PREFIX_LEN)/block_size * block_size;
    Byte *out_tmp = malloc(sizeof(Byte) * len);
    //decrypt
    sm4_context ctx;
    sm4_setkey_dec(&ctx, sm4Key);
    sm4_crypt_ecb(&ctx, SM4_DECRYPT, (int)len, (unsigned char *)inBytes + VERSION_PREFIX_LEN, out_tmp);
    //done
    memcpy(outBytes, out_tmp, len);
    memcpy(outBytes + len, inBytes + VERSION_PREFIX_LEN + len, inLen - VERSION_PREFIX_LEN - len);
    *outLen = inLen - VERSION_PREFIX_LEN;
    free(out_tmp);
}

#pragma mark --- SM3 Algorithm ---

- (NSData *_Nullable)sm3_hashWithPainData:(NSData *)plainData {
    if (plainData == nil) {
        NSLog(@"got an empty input!");
        return plainData;
    }
    int plainLen = (int)plainData.length;
    unsigned char plainInChar[plainLen];
    memcpy(plainInChar, plainData.bytes, plainLen);
    
    //init hash output
    int outputLen = 32;
    unsigned char output[outputLen];
    sm3(plainInChar, plainLen, output);
    return [NSData dataWithBytes:output length:outputLen];
}

- (void)sm3_hashWithFilePath:(NSString *)path withCompletion:(void (^)(NSError * _Nullable, NSData * _Nullable))completion {
    NSAssert(path.length != 0, @"could not read an empty path!");
    NSError *err;
    
    //prepare input file path
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if (![fileManager fileExistsAtPath:path]) {
        err = [NSError errorWithDomain:@"file not exist!" code:-1 userInfo:nil];
        if (completion) {
            completion(err, nil);
        }
        return;
    }
    char *filePath = (char *)[path UTF8String];
    //init hash output
    int outputLen = 32;
    unsigned char output[outputLen];
    sm3_file(filePath, output);
    NSData *outSM3Hex = [NSData dataWithBytes:output length:outputLen];
    if (completion) {
        completion(err, outSM3Hex);
    }
}

#pragma mark --- SM2 Algorithm ---

- (NSArray <NSString *>*)randomSM2KeyPairs {
    unsigned char buff[64] = {0};
    unsigned char prikeyBuff[2000] = {0};
    unsigned long priLen = 2000;
    
    GM_GenSM2keypair(prikeyBuff, &priLen, buff);
    
    NSData *pubXD = [NSData dataWithBytes:buff length:32];
    NSData *pubYD = [NSData dataWithBytes:buff+32 length:32];
    NSData *priD = [NSData dataWithBytes:prikeyBuff length:priLen];
    
    NSString *pubX = [pubXD hexStringFromData:pubXD];
    NSString *pubY = [pubYD hexStringFromData:pubYD];
    NSString *pri = [priD hexStringFromData:priD];
    
    return @[pubX,pubY,pri];
}

- (NSArray<NSString *> *)randomSM2KeyPairs:(NSString *)priKey {
    
    unsigned char buff[65] = {0};
    unsigned char prikeyBuff[2000] = {0};
    unsigned long priLen = 2000;
    if (priKey.length > 0) {
        NSData *prikeyDs = [NSData dataFromHexString:priKey];
        priLen = prikeyDs.length;
        memcpy(prikeyBuff, prikeyDs.bytes, prikeyDs.length);
        GM_GenSM2keypair(prikeyBuff, &priLen, buff);
    } else {
        priLen = 0;
        GM_GenSM2keypair(prikeyBuff, &priLen, buff);
    }
    
    NSData *pubHeadD = [NSData dataWithBytes:buff length:1];
    NSData *pubXD = [NSData dataWithBytes:buff+1 length:32];
    NSData *pubYD = [NSData dataWithBytes:buff+32+1 length:32];
    NSData *priD = [NSData dataWithBytes:prikeyBuff length:priLen];
    NSString *pubhead = [pubHeadD hexStringFromData:pubHeadD];
    NSString *pubX = [pubXD hexStringFromData:pubXD];
    NSString *pubY = [pubYD hexStringFromData:pubYD];
    NSString *pri = [priD hexStringFromData:priD];
    NSString *pub = [pubhead stringByAppendingString:[pubX stringByAppendingString:pubY]];
    
    return @[pri, pub];
}

- (NSString * _Nullable)sm2_encryptPlainString:(NSString *)str withPublicKey:(NSString *)key {
    if ([str length] == 0 || [key length] == 0) {
        return @"";
    }
    
    NSData *ds = [key dataUsingEncoding:NSUTF8StringEncoding];
    if ((ds.length / 2) != 64) {
        // 公钥的长度应该默认都是 64，如果大于该位数表示不正确，默认会从头开始截取
        NSInteger diff = (ds.length / 2) - 64;
        for (NSInteger i = 0; i < (diff * 2); i++) {
            key = [key substringFromIndex:1];
        }
    }
    
    const char *encryptData = [str cStringUsingEncoding:NSUTF8StringEncoding];
    
    int plainInDataLength = (int)str.length;
    unsigned long outlen = plainInDataLength + 32 + 1024;
    unsigned char result[outlen];
    memset(result, 0x00, outlen);
    
    NSData *keyData =  [NSData dataFromHexString:key];
    
    int ret = GM_SM2Encrypt(result,&outlen,(unsigned char *)encryptData,strlen(encryptData),(unsigned char *)keyData.bytes,keyData.length);
    
    if (outlen < 2 || ret != MP_OKAY) {
        //加密出错了
        return @"";
    }
    
    //多一位\x04 需要去掉
    NSData *data = [NSData dataWithBytes:result length:outlen];
    
    return [data hexStringFromData:data];
}

- (NSString * _Nullable)sm2_decryptCipherString:(NSString *)str withPrivateKey:(NSString *)key {
    //密文长度至少也需要64+32位
    if ([str length] < 64 + 32 || [key length] == 0) {
        return @"";
    }
    
    
    int plainInDataLength = (int)str.length;
    unsigned long inlen = (plainInDataLength + 32 + 1024);
    unsigned char pass[inlen];
    memset(pass, 0x00, inlen);
    
    unsigned char result[inlen];
    memset(result, 0x00, inlen);
    
    NSData *keyData =  [NSData dataFromHexString:key];
    
    NSData *data = [NSData dataFromHexString:str];
    memcpy(pass, data.bytes, data.length);
    
    unsigned long outlen = inlen;
    
    int ret = GM_SM2Decrypt((unsigned char *)result, &outlen, pass, data.length + 1, (unsigned char *)keyData.bytes, keyData.length);
    
    if (outlen == 0 || ret != MP_OKAY) {
        //加密出错了
        return @"";
    }
    NSString *resultStr = [[NSString alloc] initWithBytes:result length:outlen encoding:NSUTF8StringEncoding];
    
    return resultStr;
}

- (NSString * _Nullable)sm2_signPlainString:(NSString *)str withUID:(NSString *)uid withPrivateKey:(NSString *)key {
    if ([str length] == 0 || [key length] == 0) {
        return @"";
    }
    
    unsigned char result[64] = {0};
    unsigned long outlen = 64;
    const char *signData = [str cStringUsingEncoding:NSUTF8StringEncoding];
    const char *uidData = [uid cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *keyData =  [NSData dataFromHexString:key];
    
    int ret = GM_SM2Sign((unsigned char *)result, &outlen, (unsigned char *)signData, strlen(signData), (unsigned char *)uidData, strlen(uidData), (unsigned char *)keyData.bytes, keyData.length);
    if (outlen < 2 || ret != MP_OKAY) {
        NSLog(@"签名出错了");
        return @"";
    }
    
    //验证签名
    //    NSData *priKeyData =  [NSData dataFromHexString:priKey];
    //    ret = GM_SM2VerifySig((unsigned char *)result, outlen, (unsigned char *)signData, strlen(signData), (unsigned char *)uidData, strlen(uidData), (unsigned char *)priKeyData.bytes, priKeyData.length);
    
    //多一位\x04 需要去掉
    NSData *data = [NSData dataWithBytes:result length:outlen];
    return [data hexStringFromData:data];
}

- (BOOL)sm2_verifyWithPlainString:(NSString *)str withSigned:(NSString *)sign withUID:(NSString *)uid withPublicKey:(NSString *)key {
    if ([str length] == 0 || sign.length == 0 || [key length] == 0) {
        return false;
    }
    const char *srcData = [str cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *signData = [NSData dataFromHexString:sign];
    const char *uidData = [uid cStringUsingEncoding:NSUTF8StringEncoding];
    
    
    NSData *keyData =  [NSData dataFromHexString:key];
    if (keyData.length > 64) {
        // 移除首位04开头
        const void * pubkeyTemp = [keyData bytes];
        keyData = [NSData dataWithBytes:pubkeyTemp+1 length:keyData.length - 1];
    }
    
    int ret = GM_SM2VerifySig((unsigned char *)signData.bytes, signData.length, (unsigned char *)srcData, strlen(srcData), (unsigned char *)uidData, strlen(uidData), (unsigned char *)keyData.bytes, keyData.length);
    
    return ret == 0;
}

#pragma mark --- AES-GCM-128 Mode ---

- (NSString *)randomAESGCM128Key {
    return [self randomString4Length:SM4_BLOCK_SIZE ];
}
/*
 - (NSData * _Nullable)aes_gcm128EncryptData:(NSData *)plainData withKey:(NSString *)key {
 if (plainData == nil) {
 NSLog(@"got an empty data!");
 return plainData;
 }
 if (plainData.length >= BLOCK_SIZE_CRYPTO) {
 NSLog(@"could not handle with too large data!");
 return nil;
 }
 if (key.length != AES_BLOCK_SIZE) {
 NSLog(@"got a bad aes-gcm key!");
 return nil;
 }
 NSLog(@"origin:%@", plainData);
 //prepare key and iv
 size_t iv_len = GCM_DEFAULT_IV_LEN;
 uint8_t iv[GCM_DEFAULT_IV_LEN] = {
 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};
 //    NSData *keyData =  [NSData dataFromHexString:key];
 //    unsigned char * keyChar = (unsigned char *)[keyData bytes];
 uint8_t keyChar[AES_BLOCK_SIZE] = {
 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
 
 //pre deal with data
 //unsigned char * in = (unsigned char *)[plainData bytes];
 int len = (int)[plainData length];
 //char * out[len];
 
 //fixed length for padding
 //a.对明文数据进行填充来保证位数是16的倍数
 int plainInDataLength = (int)plainData.length;
 //  p是需要填充的数据也是填充的位数
 int p = AES_BLOCK_SIZE - plainInDataLength % AES_BLOCK_SIZE;
 unsigned char plainInChar[plainInDataLength + p];
 memcpy(plainInChar, plainData.bytes, plainInDataLength);
 //  进行数据填充
 for (int i = 0; i < p; i++) {
 plainInChar[plainInDataLength + i] =  p;
 }
 unsigned char cipherOutChar[plainInDataLength + p];
 
 //encrypt
 void * ctx = gcm_init();
 if ( !ctx ) {
 printf("malloc context for gcm128-aes failed.\n");
 return nil;
 }
 operation_result flag = gcm_setkey(ctx, keyChar, 128 );
 if ( OPERATION_FAIL == flag ) {
 NSLog(@"failed to encrypt with aes-gcm-128!");
 return nil;
 }
 //size_t add_len = AES_BLOCK_SIZE+4;
 int mode = len / AES_BLOCK_SIZE;
 if (len % AES_BLOCK_SIZE != 0) {
 mode += 1;
 }
 /*add_len = mode * AES_BLOCK_SIZE;
 //uint8_t add[add_len];
 //memset( add, 0, add_len*sizeof(uint8_t));
 //uint8_t tag[add_len];
 //memset( tag, 0, add_len*sizeof(uint8_t));
 //size_t tag_len = add_len;
 ///
 int add_len = 0;
 uint8_t *add = NULL;
 int tag_len = AES_BLOCK_SIZE;
 uint8_t tag[AES_BLOCK_SIZE] = {0};
 
 flag = gcm_crypt_and_tag(ctx, iv, iv_len, add, add_len, plainInChar, plainInDataLength + p, cipherOutChar, tag, tag_len);
 if (flag == OPERATION_FAIL) {
 NSLog(@"failed encrypt data with aes-gcm-128 mode!");
 gcm_free( ctx);
 return nil;
 }
 
 gcm_free( ctx);
 
 //return [NSData dataWithBytes:out length:len];
 return [[NSData alloc] initWithBytes:cipherOutChar length:sizeof(cipherOutChar)];
 }
 
 - (NSData * _Nullable)aes_gcm128DEcryptData:(NSData *)cipherData withKey:(NSString *)key {
 if (cipherData == nil) {
 NSLog(@"got an empty data!");
 return cipherData;
 }
 if (cipherData.length >= BLOCK_SIZE_CRYPTO) {
 NSLog(@"could not handle with too large data!");
 return nil;
 }
 if (key.length != AES_BLOCK_SIZE) {
 NSLog(@"got a bad aes-gcm key!");
 return nil;
 }
 //prepare key and iv
 size_t iv_len = GCM_DEFAULT_IV_LEN;
 uint8_t iv[GCM_DEFAULT_IV_LEN] = {
 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};
 //    NSData *keyData =  [NSData dataFromHexString:key];
 //    unsigned char * keyChar = (unsigned char *)[keyData bytes];
 uint8_t keyChar[AES_BLOCK_SIZE] = {
 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
 
 //pre deal with data
 //unsigned char * in = (unsigned char *)[cipherData bytes];
 int len = (int)[cipherData length];
 //char * out[len];
 //6将cipherTextData作为输入，调用第4步的解密方法，进行解密
 //将data拷贝到字符数组中
 unsigned char cipherTextChar[cipherData.length];
 memcpy(cipherTextChar, cipherData.bytes, cipherData.length);
 
 
 //decrypt
 //sleep(5);
 void * context = gcm_init();
 if ( !context ) {
 printf("malloc context for gcm128-aes-decrypt failed.\n");
 return nil;
 }
 operation_result flag = gcm_setkey(context, keyChar, 128 );
 if ( OPERATION_FAIL == flag ) {
 NSLog(@"failed to decrypt with aes-gcm-128!");
 return nil;
 }
 
 //size_t add_len = AES_BLOCK_SIZE+4;
 int mode = len / AES_BLOCK_SIZE;
 if (len % AES_BLOCK_SIZE != 0) {
 mode += 1;
 }
 
 int add_len = 0;
 uint8_t *add = NULL;
 int tag_len = AES_BLOCK_SIZE;
 uint8_t tag[AES_BLOCK_SIZE] = {0};
 
 
 //调用解密方法，输出是明文plainOutChar
 unsigned char plainOutChar[cipherData.length];
 flag = gcm_auth_decrypt(context, iv, iv_len, add, add_len, tag, tag_len, cipherTextChar, len, plainOutChar);
 if (flag == OPERATION_FAIL) {
 NSLog(@"failed decrypt data with aes-gcm-128 mode!");
 gcm_free( context);
 return nil;
 }
 
 gcm_free( context);
 
 //由于明文是填充过的，解密时候要去填充，去填充要在解密后才可以，在解密前是去不了的
 int p2 = plainOutChar[sizeof(plainOutChar) - 1];//p2是填充的数据，也是填充的长度
 int outLength = (int)cipherData.length-p2;//明文的长度
 //去掉填充得到明文
 unsigned char plainOutWithoutPadding[outLength];
 memcpy(plainOutWithoutPadding, plainOutChar, outLength);
 
 return [[NSData alloc] initWithBytes:plainOutWithoutPadding length:sizeof(plainOutWithoutPadding)];
 //return [NSData dataWithBytes:out length:len];
 }
 //*/
#define GCM_DEFAULT_IV_LEN (24)
- (NSData *)aes_gcm128EncryptData:(NSData *)plainData withKey:(NSString *)key {
    
    if (plainData == nil) {
        NSLog(@"got an empty data!");
        return plainData;
    }
    if (plainData.length >= BLOCK_SIZE_CRYPTO) {
        NSLog(@"could not handle with too large data!");
        return nil;
    }
    if (key.length != SM4_BLOCK_SIZE ) {
        NSLog(@"got a bad aes-gcm key!");
        return nil;
    }
    NSLog(@"origin:%@", plainData);
    //pre deal with data
    //unsigned char * in = (unsigned char *)[plainData bytes];
    int len = (int)[plainData length];
    //char * out[len];
    
    //*fixed length for padding
    //a.对明文数据进行填充来保证位数是16的倍数
    int plainInDataLength = (int)plainData.length;
    //  p是需要填充的数据也是填充的位数
    int p = SM4_BLOCK_SIZE - plainInDataLength % SM4_BLOCK_SIZE;
    unsigned char plainInChar[plainInDataLength + p];
    memcpy(plainInChar, plainData.bytes, plainInDataLength);
    //  进行数据填充
    for (int i = 0; i < p; i++) {
        plainInChar[plainInDataLength + i] =  p;
    }
    unsigned char cipherOutChar[plainInDataLength + p];
    
    
    //prepare key and iv
    NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
    size_t iv_len = GCM_DEFAULT_IV_LEN;
    uint8_t iv[GCM_DEFAULT_IV_LEN] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88, 0xde, 0xca, 0xf8, 0x88, 0xde, 0xca, 0xf8, 0x88, 0xde, 0xca, 0xf8, 0x88};
    
    aes_gcm_encrypt(cipherOutChar, plainInChar, plainInDataLength + p, [keyData bytes],  [keyData length], iv, iv_len);
    return [NSData dataWithBytes:cipherOutChar length:plainInDataLength + p];
    //*/
    
    //NSString * Key = @"11754cd72aec309bf52f7687212e8957";
    NSString *IV = @"3c819d9a9bed087615030b65";
    //NSData *keyData = [Key dataUsingEncoding:NSUTF8StringEncoding];
    NSData *keyBytes = [NSData dataFromHexString:key];
    NSData * IVData = [NSData dataFromHexString:IV];
    uint8_t IVChar[SM4_BLOCK_SIZE] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
    Byte * res[ [plainData length] ];
    //aes_gcm_encrypt(*res, [plainData bytes], sizeof([plainData bytes]), [keyBytes bytes],  sizeof([keyBytes bytes]), IVChar, sizeof(IVChar));
    aes_gcm_encrypt(*res, [plainData bytes], plainInDataLength+p, [keyBytes bytes],  sizeof([keyBytes bytes]), IVChar, sizeof(IVChar));
    return [NSData dataWithBytes:res length:sizeof(res)];
}

- (NSData *)aes_gcm128DEcryptData:(NSData *)cipherData withKey:(NSString *)key {
    if (cipherData == nil) {
        NSLog(@"got an empty data!");
        return cipherData;
    }
    if (cipherData.length >= BLOCK_SIZE_CRYPTO) {
        NSLog(@"could not handle with too large data!");
        return nil;
    }
    if (key.length != SM4_BLOCK_SIZE ) {
        NSLog(@"got a bad aes-gcm key!");
        return nil;
    }
    /*prepare key and iv
     NSData *keyData = [key dataUsingEncoding:NSUTF8StringEncoding];
     size_t iv_len = GCM_DEFAULT_IV_LEN;
     uint8_t iv[GCM_DEFAULT_IV_LEN] = {
     0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88, 0xde, 0xca, 0xf8, 0x88};
     //*/
    
    
    //NSString * Key = @"11754cd72aec309bf52f7687212e8957";
    NSString *IV = @"3c819d9a9bed087615030b65";
    //NSData *keyData = [Key dataUsingEncoding:NSUTF8StringEncoding];
    NSData *keyBytes = [NSData dataFromHexString:key];
    NSData * IVData = [NSData dataFromHexString:IV];
    uint8_t IVChar[SM4_BLOCK_SIZE] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};
    
    int len = (int)[cipherData length];
    //size_t add_len = AES_BLOCK_SIZE+4;
    int mode = len / SM4_BLOCK_SIZE;
    if (len % SM4_BLOCK_SIZE != 0) {
        mode += 1;
    }
    len = mode * SM4_BLOCK_SIZE;
    Byte * res[ len ];
    sleep(3);
    aes_gcm_decrypt(*res, [cipherData bytes], sizeof([cipherData bytes]), [keyBytes bytes],  sizeof([keyBytes bytes]), IVChar, sizeof(IVChar));
    //aes_gcm_decrypt(*res, [cipherData bytes], len, [keyBytes bytes],  sizeof([keyBytes bytes]), IVChar, sizeof(IVChar));
    return [NSData dataWithBytes:res length:sizeof(res)];
}

@end
