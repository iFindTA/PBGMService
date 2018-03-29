//
//  ViewController.m
//  PBGMService
//
//  Created by nanhujiaju on 2017/9/11.
//  Copyright © 2017年 nanhujiaju. All rights reserved.
//

#import "ViewController.h"
#import "PBGMService.h"
#import <AudioToolbox/AudioQueue.h>
#import <AudioToolbox/AudioToolbox.h>
#import <AVFoundation/AVFoundation.h>

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    //sm4
    NSString *sm4_key = [[PBGMService shared] randomSM4Key];
    NSLog(@"key for sm4:%@", sm4_key);
    
    /*sm4 encrypt
    NSString *plainText = @"hello, world! and home town";
    NSData *plainData = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    NSData *cipherData = [[PBGMService shared] sm4_encryptData:plainData withCipherKey:sm4_key];
//    NSString *base64Cipher = [cipherData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
//    NSLog(@"加密结果:%@---%@", cipherData, base64Cipher);
//    
//    //sm4 decrypt
    NSData *decryptData = [[PBGMService shared] sm4_decryptData:cipherData withCipherKey:sm4_key];
    NSString *convertString = [[NSString alloc] initWithData:decryptData encoding:NSUTF8StringEncoding];
    NSLog(@"解密结果:%@", convertString);
    //*/
    
    /*加密文件 pass
    NSString *srcPath = @"/Users/nanhujiaju/Desktop/Appdelegate.h";
    NSString *desPath = @"/Users/nanhujiaju/Desktop/Appdelegate_en.h";
    [[PBGMService shared] sm4_encryptFile:srcPath withDestFilePath:desPath withCipherKey:sm4_key withCompletion:^(NSError * _Nullable err) {
        NSLog(@"error:%@", err.localizedDescription);
    }];
    
    NSString *des_key = @"V96l2Hip739WR7V5";
    NSString *decPath = @"/Users/nanhujiaju/Desktop/Appdelegate_de.h";
    [[PBGMService shared] sm4_decryptFile:desPath withDestFilePath:decPath withCipherKey:des_key withCompletion:^(NSError * _Nullable err) {
        NSLog(@"decrypt file error:%@", err.localizedDescription);
    }];
    //*/
    
    /* sm3
    NSData *sm3Hash = [[PBGMService shared] sm3_hashWithPainData:plainData];
    NSString *sm3HashString = [sm3Hash pb_base64String];
    NSLog(@"sm3 hash string:%@", sm3HashString);//bsd/Ha2tik1i2r26NTVxgSt4tn7InOzXBFDlBreIzKc=
    //sm3 file
    NSString *srcPath = @"/Users/nanhujiaju/Desktop/EZAudio-master.zip";
    [[PBGMService shared] sm3_hashWithFilePath:srcPath withCompletion:^(NSError * _Nullable err, NSData * _Nullable hash) {
        if (err) {
            NSLog(@"failed to sm3 for error:%@", err.localizedDescription);
        } else {
            NSString *sm3String = [hash pb_base64String];
            NSLog(@"sm3 file hash:%@", sm3String);
        };
    }];
    //*/
    
    /*sm2 key pairs/encrypt/decrypt/sign
    NSArray *keyPairs = [[PBGMService shared] randomSM2KeyPairs];
    NSLog(@"keyPaic = %@",keyPairs);
    
    NSString *publicKey = [NSString stringWithFormat:@"%@%@",keyPairs[0],keyPairs[1]];
    NSString *priviteKey = keyPairs[2];
    NSLog(@"publicKey = %@ , priKey = %@",publicKey,priviteKey);
    //encrypt/decrypt
    NSString *str = @"encryption standard，你好帅哥";
    NSString *encode = [[PBGMService shared] sm2_encryptPlainString:str withPublicKey:publicKey];
    NSLog(@"encode finished");
    NSString *decode = [[PBGMService shared] sm2_decryptCipherString:encode withPrivateKey:priviteKey];
    NSLog(@"encode = %@ , decode = %@",encode,decode);
    //签名、验证签名
    NSString *uid = @"nanhujiaju@gmail.com";
    NSString *signedString = [[PBGMService shared] sm2_signPlainString:str withUID:uid withPrivateKey:priviteKey];
    NSLog(@"signed string:%@", signedString);
    BOOL ret = [[PBGMService shared] sm2_verifyWithPlainString:str withSigned:signedString withUID:uid withPublicKey:publicKey];
    NSLog(@"验证结果:%@", ret?@"成功！":@"失败！");
    //*/
    
    /*sm4 sample stream encrypt/decrypt
    //这里示例为语音录音后的数据缓存段
    AudioQueueBufferRef buffer = NULL;//如何实现录音不再赘述
    NSData *bufferData = [NSData dataWithBytes:buffer->mAudioData length:buffer->mAudioDataByteSize];
    NSUInteger audioLen = [bufferData length];
    NSLog(@"audio data len :%zd",audioLen);
    const Byte *inBytes = (const Byte *)[bufferData bytes];
    //const byte *inBytes = (const byte *)[plainString UTF8String];
    unsigned int in_len = (unsigned int)strlen((const char *)inBytes);
    unsigned int len_mode = in_len / 16;
    if (in_len % 16 != 0) {
        len_mode += 1;
    }
    Byte outBytes[len_mode*16];
    unsigned int out_len;
    [[PBGMService shared] sm4_encryptStream:inBytes inLength:in_len withOutput:outBytes outLength:&out_len withCipherKey:sm4_key];
    
    //decrypt stream
    len_mode = out_len / 16;
    if (out_len % 16 != 0) {
        len_mode += 1;
    }
    Byte out2[len_mode*16];
    unsigned int out_len2 = 0;
    [[PBGMService shared] sm4_decryptStream:outBytes inLength:out_len withOutput:out2 outLength:&out_len2 withCipherKey:sm4_key];
    out2[out_len2] = '\0';
    //*/
    
    //aes-gcm encrypt/decrypt
    NSString *aes_gcm128_key = [[PBGMService shared] randomAESGCM128Key];
    NSLog(@"key for aes-gcm-128:%@", aes_gcm128_key);
    NSString *plainText = @"hello, world! and home town";
    //NSData *plainData = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    NSData *plainData = [NSData dataFromHexString:plainText];
    NSData *cipherData = [[PBGMService shared] aes_gcm128EncryptData:plainData withKey:aes_gcm128_key];
    NSString *base64Cipher = [cipherData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    NSLog(@"加密结果:%@---%@", cipherData, base64Cipher);
    
    
    //TODO:解密暂时还没有写完
    NSData *decryptData = [[PBGMService shared] aes_gcm128DEcryptData:cipherData withKey:aes_gcm128_key];
    NSString *convertString = [[NSString alloc] initWithData:decryptData encoding:NSUTF8StringEncoding];
    NSLog(@"解密结果:%@", convertString);
     
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
