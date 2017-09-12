//
//  ViewController.m
//  PBGMService
//
//  Created by nanhujiaju on 2017/9/11.
//  Copyright © 2017年 nanhujiaju. All rights reserved.
//

#import "ViewController.h"
#import "PBGMService.h"

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
    NSString *srcPath = @"/Users/nanhujiaju/Desktop/MXSDK.h";
    NSString *desPath = @"/Users/nanhujiaju/Desktop/MXSDK_EN.h";
    [[PBGMService shared] sm4_encryptFile:srcPath withDestFilePath:desPath withCipherKey:sm4_key withCompletion:^(NSError * _Nullable err) {
        NSLog(@"error:%@", err.localizedDescription);
    }];
    
    NSString *des_key = @"xZpLIJSeFRqvkZrM";
    NSString *decPath = @"/Users/nanhujiaju/Desktop/MXSDK_DE.h";
    [[PBGMService shared] sm4_decryptFile:desPath withDestFilePath:decPath withCipherKey:des_key withCompletion:^(NSError * _Nullable err) {
        NSLog(@"decrypt file error:%@", err.localizedDescription);
    }];
    //*/
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
