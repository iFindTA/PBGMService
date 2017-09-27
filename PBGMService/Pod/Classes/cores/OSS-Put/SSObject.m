//
//  SSObject.m
//  StoreService
//
//  Created by nanhujiaju on 2017/8/30.
//  Copyright © 2017年 nanhujiaju. All rights reserved.
//

#import "SSObject.h"

//KVO观察 当前进度/当前状态
NSString * const SS_KVO_PATH_PROGRESS                   =   @"progress";
NSString * const SS_KVO_PATH_STATUS                     =   @"status";

@interface SSObject ()

@property (nonatomic, copy, readwrite) NSString * objKey;

@property (nonatomic, copy, nullable, readwrite) NSString *fileName;
//
@property (nonatomic, assign, readwrite) SSFileType fileType;

@end

@implementation SSObject

- (void)dealloc {
    
}

#pragma mark --- Update Setter methods ---

- (void)updateObjectKey:(NSString *)objKey {
    if (PBIsEmpty(objKey)) {
        return;
    }
    _objKey = objKey.copy;
}

- (void)updateFileName:(NSString*)fileName{
    if (PBIsEmpty(fileName)) {
        return;
    }
    _fileName = fileName;
}

- (NSString * _Nullable)fetchObjectKey {
    return _objKey;
}

- (void)updateObjectFileType:(SSFileType)type {
    if (type & (SSFileTypeFile|SSFileTypeImage|SSFileTypeVideo|SSFileTypeContacts)) {
        self.fileType = type;
    }
}

- (NSString *)convertStatus2String {
    return @"等待中...";
}

@end
