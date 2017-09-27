//
//  SSObject.h
//  StoreService
//
//  Created by nanhujiaju on 2017/8/30.
//  Copyright © 2017年 nanhujiaju. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "SSConstant.h"

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSUInteger, SSObjectStatus) {
    SSObjectStatusWaiting                       =   1   <<  0,
    SSObjectStatusProcessing                    =   1   <<  1,//正在处理 eg. 加密
    SSObjectStatusUploading                     =   1   <<  2,//正在上传、下载
    SSObjectStatusFailed                        =   1   <<  3,//上传、下载失败
    SSObjectStatusDone                          =   1   <<  4,//上传、下载完成
    SSObjectStatusDownloading                          =   1   <<  7,//下载中
    SSObjectStatusDownloadFailed                          =   1   <<  8,//下载失败
    SSObjectStatusDownloadSuccess                          =   1   <<  9,//下载成功
    SSObjectStatusDecrypting                          =   1   <<  10,//解密中
};

@class PHAsset;
@interface SSObject : NSObject

/**
 Object对应的全局唯一的key索引 此key用来从云端、本地、后台检索资源
 上传、下载子类覆盖read方法即可
 */
@property (nonatomic, copy, readonly) NSString * objKey;

/**
 Object对应的文件名
 */
@property (nonatomic, copy, readonly, nullable) NSString *fileName;

/**
 Object 对应的类型
 上传、下载子类覆盖read方法即可
 */
@property (nonatomic, assign, readonly) SSFileType fileType;

/**
 Object 对应的传输状态
 */
@property (nonatomic, assign) SSObjectStatus status;

/**
 upload progress 0~1, default is 0.f
 */
@property (nonatomic, assign) CGFloat progress;

/**
 更新Object Key
 */
- (void)updateObjectKey:(NSString *)objKey;
- (NSString * _Nullable)fetchObjectKey;

/**
 更新Object file-type
 */
- (void)updateObjectFileType:(SSFileType)type;

/**
 *更新文件名
 */
- (void)updateFileName:(NSString*)fileName;

/**
 
 将Object 对应的状态转为字符串 eg.等待中
 */
- (NSString *)convertStatus2String NS_REQUIRES_SUPER ;

@end

//KVO观察 当前进度
FOUNDATION_EXPORT NSString * const SS_KVO_PATH_PROGRESS;
//KVO观察 当前状态
FOUNDATION_EXPORT NSString * const SS_KVO_PATH_STATUS;

NS_ASSUME_NONNULL_END
