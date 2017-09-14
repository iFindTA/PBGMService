//
//  ViewController.m
//  PBGMService
//
//  Created by nanhujiaju on 2017/9/11.
//  Copyright © 2017年 nanhujiaju. All rights reserved.
//

#import "ViewController.h"
#import "PBGMService.h"
#import "PBBase64.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    //sm4
    NSString *sm4_key = [[PBGMService shared] randomSM4Key];
    NSLog(@"key for sm4:%@", sm4_key);
    
    //sm4 encrypt
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
    
    //sm2
    
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
