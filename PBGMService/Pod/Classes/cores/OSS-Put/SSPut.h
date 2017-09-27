//
//  SSPut.h
//  StoreService
//
//  Created by nanhujiaju on 2017/8/29.
//  Copyright © 2017年 nanhujiaju. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "SSConstant.h"

@class PHAsset, SSPutObject;
@interface SSPut : NSObject

NS_ASSUME_NONNULL_BEGIN

/**
 上传队列对应的任务数据源
 */
@property (nonatomic, strong, readonly, nullable) NSMutableArray <SSPutObject*> * taskQueue;

/**
 sigletone-mode
 */
+ (instancetype)shared;

/**
 release singletone for put
 */
+ (void)releasePutSingletone;

/**
 upload assets

 @param assets system assets for image/video
 @param thumbnails system assets thumbnail for image /video
 @param completion callback
 */
- (void)uploadAssets:(NSArray <PHAsset*>*)assets withThumbnails:(NSArray<UIImage*>*)thumbnails withCompletion:(void(^_Nullable)(NSError*_Nullable error))completion;

/**
 upload raw data

 @param data raw data for upload
 @param idf identifier for file
 */
- (void)uploadFileRawData:(NSData *)data withObjectIdentifier:(NSString *)idf withCompletion:(void(^_Nullable)(NSError*_Nullable error))completion;

/**
 cancel or delete upload task

 @param objKey for Object
 */
- (void)removeUploadTask4ObjectKey:(NSString * _Nonnull)objKey;

@end

//PUT上传队列 KVO外键
FOUNDATION_EXPORT NSString * const SS_KVO_PATH_PUT_QUEUE;

NS_ASSUME_NONNULL_END
