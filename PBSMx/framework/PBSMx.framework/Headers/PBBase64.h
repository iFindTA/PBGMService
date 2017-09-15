//
//  PBBase64.h
//  PBGMService
//
//  Created by nanhujiaju on 2017/9/14.
//  Copyright © 2017年 nanhujiaju. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PBBase64 : NSObject

@end

@interface NSData (PBBase64)

- (NSString * _Nullable)pb_base64String;

+ (NSData *)dataFromHexString:(NSString *)hexString;

- (NSString *)hexStringFromData:(NSData *)data;

@end

@interface NSString (PBBase64)

- (NSData * _Nullable)pb_base64Data;

@end

NS_ASSUME_NONNULL_END
