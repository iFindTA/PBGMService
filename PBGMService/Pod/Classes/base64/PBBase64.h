//
//  PBBase64.h
//  PBGMService
//
//  Created by nanhujiaju on 2017/9/14.
//  Copyright © 2017年 nanhujiaju. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface PBBase64 : NSObject

@end

@interface NSData (PBBase64)

- (NSString * _Nullable)pb_base64String;

@end

@interface NSString (PBBase64)

- (NSData * _Nullable)pb_base64Data;

@end
