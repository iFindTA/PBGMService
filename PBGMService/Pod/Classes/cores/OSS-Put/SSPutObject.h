//
//  SSPutObject.h
//  StoreService
//
//  Created by nanhujiaju on 2017/9/1.
//  Copyright © 2017年 nanhujiaju. All rights reserved.
//

#import "SSObject.h"

NS_ASSUME_NONNULL_BEGIN

@class  OSSPutObjectRequest, SSUploadCell;
@interface SSPutObject : SSObject

/**
 Object placeholder key
 */
@property (nonatomic, copy, readonly) NSString * _Nullable subKey;

/**
 Object 加密后的文件路径 临时路径
 */
@property (nonatomic, copy, readonly) NSString * _Nullable cipherFilePath;

/**
 weak cell
 */
@property (nonatomic, weak) SSUploadCell *weakCell;

/**
 通过PHAsset初始化Object
 */
- (instancetype)initWithAsset:(PHAsset *)asset;

/**
 通过PHAsset初始化Object 附带placeholder
 */
- (instancetype)initWithAsset:(PHAsset *)asset withPlaceholder:(UIImage *)place;

/**
 通过文件原始data初始化Object
 */
- (instancetype)initWithRawData:(NSData *)data withIdentifier:(NSString *)objKey;

/**
 预处理视频等大文件
 预处理：key/type/name
 */
- (void)prepareInitializedObject;

/**
 预估上传data数据 大小
 */
- (uint64_t)evaluatePlainSize4Upload;

/**
 预处理文件
 预处理：文件大小/是否分片/路径或加密数据
 */
- (void)handleDealingPlainFileWhilePreUploadWithCompletion:(void(^_Nullable)(NSError * _Nullable err))completion;

/**
 预处理后的密文数据大小
 */
- (uint64_t)fetchRealCipherSize;

/**
 预处理后的回调参数
 */
- (NSDictionary<NSString*,NSString*>*)fetchCallbackCfg;

/**
 Object placeholder request
 */
- (OSSPutObjectRequest * _Nullable)fetchObjectPlaceholderRequest;

/**
 单个文件上传Request, 如果超过分片大小则为空，需要改为分片上传
 */
- (OSSPutObjectRequest * _Nullable)fetchObjectRealDataPutRequest;

/**
 单个大文件上传RequestID，无需分片则为空
 */
@property (nonatomic, copy, nullable) NSString *requestID;

/**
 单个大文件上传 分片idx，默认-1
 */
@property (nonatomic, assign) int req_part_idx;

@end

NS_ASSUME_NONNULL_END
