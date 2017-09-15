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

+ (NSData *)dataFromHexString:(NSString*) hexString {
    const char *chars = [hexString UTF8String];
    NSInteger i = 0, len = hexString.length;
    
    NSMutableData *data = [NSMutableData dataWithCapacity:len / 2];
    char byteChars[3] = {'\0','\0','\0'};
    unsigned long wholeByte;
    
    while (i < len) {
        byteChars[0] = chars[i++];
        byteChars[1] = chars[i++];
        wholeByte = strtoul(byteChars, NULL, 16);
        [data appendBytes:&wholeByte length:1];
    }
    
    return data;
}

static inline char itoh(int i) {
    if (i > 9) return 'A' + (i - 10);
    return '0' + i;
}

- (NSString *) hexStringFromData:(NSData*) data
{
    NSUInteger i, len;
    unsigned char *buf, *bytes;
    
    len = data.length;
    bytes = (unsigned char*)data.bytes;
    buf = malloc(len*2);
    
    for (i=0; i<len; i++) {
        buf[i*2] = itoh((bytes[i] >> 4) & 0xF);
        buf[i*2+1] = itoh(bytes[i] & 0xF);
    }
    
    return [[NSString alloc] initWithBytesNoCopy:buf
                                          length:len*2
                                        encoding:NSASCIIStringEncoding
                                    freeWhenDone:YES];
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
