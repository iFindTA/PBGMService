//
//  PBBase64.m
//  PBGMService
//
//  Created by nanhujiaju on 2017/9/14.
//  Copyright © 2017年 nanhujiaju. All rights reserved.
//

#import "PBBase64.h"

@implementation PBBase64

@end

@implementation NSData (PBBase64)

- (NSString *)pb_base64String {
    if (self.length == 0) {
        return nil;
    }
    return [self base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
}

@end

@implementation NSString (PBBase64)

- (NSData *)pb_base64Data {
    if (self.length == 0) {
        return nil;
    }
    return [[NSData alloc] initWithBase64EncodedString:self options:NSDataBase64DecodingIgnoreUnknownCharacters];
}

@end
