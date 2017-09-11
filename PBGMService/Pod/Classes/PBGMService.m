//
//  PBGMService.m
//  PBGMService
//
//  Created by nanhujiaju on 2017/9/11.
//  Copyright © 2017年 nanhujiaju. All rights reserved.
//

#import "PBGMService.h"

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

@end
