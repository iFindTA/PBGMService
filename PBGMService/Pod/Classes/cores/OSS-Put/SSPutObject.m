//
//  SSPutObject.m
//  StoreService
//
//  Created by nanhujiaju on 2017/9/1.
//  Copyright © 2017年 nanhujiaju. All rights reserved.
//

#import "SSPutObject.h"
#import "SSConstant.h"
#import "SSConfigure.h"
#import "SSUploadCell.h"
#import <Photos/PHAsset.h>
#import <AliyunOSSiOS/OSSUtil.h>
#import <AliyunOSSiOS/OSSTask.h>
#import <AliyunOSSiOS/OSSModel.h>
#import <Photos/PHImageManager.h>
#import <Photos/PHAssetResource.h>
#import <Photos/PHAssetResourceManager.h>
#import "FlkKmsSdk.h"

//视频文件压缩系数
static float const SS_VIDEO_COMPRESS_SCALE                       =   0.29f;//compress0.25 + encrypt1.38 = 0.25 x 1.38

@interface SSPutObject ()

@property (nonatomic, copy, readwrite) NSString * subKey;

@property (nonatomic, assign, readwrite) uint64_t filePlainSize, fileCompressSize;

@property (nonatomic, strong, readwrite) NSData *cipherData;

@property (nonatomic, assign, readwrite) uint64_t cipherSize;

/**
 此属性如果占有资源较多 后续可考虑用完之后及时释放
 */
@property (nonatomic, strong, nullable) PHAsset *asset;

@property (nonatomic, strong, nullable) AVURLAsset *assetURL;

@property (nonatomic, strong, readwrite) OSSPutObjectRequest *request;

@property (nonatomic, strong, nullable) NSData *plainData;

@property (nonatomic, strong, nullable) UIImage *placeholder;
@property (nonatomic, strong, nullable) NSData *placeholderData;

//@property (nonatomic, strong, readwrite) NSDictionary<NSString*, NSString*> * callbackCfg;
//
//@property (nonatomic, strong, readwrite) NSDictionary<NSString*, NSString*> * callbackVar;

/**
 视频超过单个切片大小时分片上传记录暂存路径
 */
@property (nonatomic, copy, readwrite) NSString *fileTempPath;
@property (nonatomic, copy, readwrite) NSString *cipherFilePath;

@end

@implementation SSPutObject

- (void)dealloc {
    [self removeObserver:self forKeyPath:SS_KVO_PATH_STATUS];
    [self removeObserver:self forKeyPath:SS_KVO_PATH_PROGRESS];
    NSError *err;
    NSFileManager *fileManager = [NSFileManager defaultManager];
    if (self.fileTempPath.length != 0) {
        [fileManager removeItemAtPath:self.fileTempPath error:&err];
        if (err) {
            NSLog(@"failed to remove tmp file at path:%@---with error:%@", self.fileTempPath, err.localizedDescription);
        }
    }
    if (self.cipherFilePath.length != 0) {
        [fileManager removeItemAtPath:self.cipherFilePath error:&err];
        if (err) {
            NSLog(@"failed to remove encrypt file at path:%@---with error:%@", self.cipherFilePath, err.localizedDescription);
        }
    }
}

- (instancetype)initWithAsset:(PHAsset *)asset {
    self = [super init];
    if (self) {
        NSAssert(asset != nil, @"can not deal with empty asset!");
        self.asset = asset;
        [self configureKVO];
    }
    return self;
}

- (instancetype)initWithAsset:(PHAsset *)asset withPlaceholder:(UIImage *)place {
    self = [super init];
    if (self) {
        NSAssert(asset != nil, @"can not deal with empty asset!");
        NSAssert(place != nil, @"can not deal with empty placeholder!");
        self.asset = asset;
        self.placeholder = place;
        
        [self configureKVO];
    }
    return self;
}

- (instancetype)initWithRawData:(NSData *)data withIdentifier:(NSString *)objKey {
    self = [super init];
    if (self) {
        NSAssert(data != nil, @"can not deal with empty data!");
        NSAssert(objKey.length != 0, @"can not deal with empty object-key!");
        self.plainData = data;
        [self updateObjectKey:objKey];
        [self configureKVO];
    }
    return self;
}

- (void)configureKVO {
    self.req_part_idx = -1;
    self.status = SSObjectStatusWaiting;
    [self addObserver:self forKeyPath:SS_KVO_PATH_STATUS options:NSKeyValueObservingOptionNew|NSKeyValueObservingOptionOld context:NULL];
    [self addObserver:self forKeyPath:SS_KVO_PATH_PROGRESS options:NSKeyValueObservingOptionNew|NSKeyValueObservingOptionOld context:NULL];
}

- (void)observeValueForKeyPath:(NSString *)keyPath ofObject:(id)object change:(NSDictionary<NSKeyValueChangeKey,id> *)change context:(void *)context {
    if ([keyPath isEqualToString:SS_KVO_PATH_PROGRESS]) {
        if (self.weakCell) {
            weakify(self)
            PBMAINDelay(PBANIMATE_DURATION, ^{
                strongify(self)
                self.weakCell.circleView.progress = self.progress;
            });
        }
    } else if ([keyPath isEqualToString:SS_KVO_PATH_STATUS]) {
        if (self.weakCell) {
            weakify(self)
            PBMAINDelay(PBANIMATE_DURATION, ^{
                strongify(self)
                self.weakCell.detailTextLabel.text = [self convertStatus2String];
            });
        }
    }
}

- (BOOL)assetAvalible {
    return self.asset != nil;
}

#pragma mark --- 文件预处理 ---

/**
 just deal with object name
 */
- (void)prepareInitializedObject {
    SSFileType type = [self readObjectType];
    [self updateObjectFileType:type];
    //step 1:handle object key and placeholder key
    SSFileType mediaTypes = (SSFileTypeImage|SSFileTypeVideo);
    if (type & mediaTypes) {
        NSString *objKey = [SSKit generateObjectKey4Asset:self.asset whetherPlaceholder:false];
        [self updateObjectKey:objKey];
        NSString *subKey = [SSKit generateObjectKey4Asset:self.asset whetherPlaceholder:true];
        self.subKey = subKey.copy;
    }
    //step 2:handle file:name/path/data/encrypt
    NSString *objName;
    if (type & mediaTypes) {
        NSArray <PHAssetResource*>*res = [PHAssetResource assetResourcesForAsset:self.asset];
        if (res.count > 0) {
            PHAssetResource *role = [res firstObject];
            objName = role.originalFilename.copy;
        }
    }
    if (PBIsEmpty(objName)) {
        objName = self.objKey.copy;
    }
    [self updateFileName:objName];
    
    //deal with placeholder
    if (self.placeholder) {
        UIImage *scaleImg = [self.placeholder pb_scaleToSize:CGSizeMake(SS_IMAGE_THUMBNAIL_SIZE, SS_IMAGE_THUMBNAIL_SIZE) keepAspect:true];
        self.placeholderData = UIImageJPEGRepresentation(scaleImg, SS_IMAGE_COMPRESS_SCALE);
        _placeholder = nil;
    }
}

- (uint64_t)evaluatePlainSize4Upload {
    uint64_t evaSize = 0;uint64_t placeholderSize = [self.placeholderData length];
    if (self.fileType & SSFileTypeVideo) {
        //plain size
        AVURLAsset *urlAsset = [self fetchVideoAssetURL];
        NSNumber *size;
        [urlAsset.URL getResourceValue:&size forKey:NSURLFileSizeKey error:nil];
        uint64_t tmpSize = [size unsignedLongLongValue];
        NSLog(@"pre evaluate plain size is %f---MB",[size floatValue]/(SS_FILE_UNIT_MB)); //size is /MB
        evaSize = tmpSize * SS_VIDEO_COMPRESS_SCALE;
    } else if (self.fileType & SSFileTypeImage) {
        PHImageRequestOptions *options = [PHImageRequestOptions new];
        options.synchronous = true;
        options.networkAccessAllowed = false;
        options.deliveryMode = PHImageRequestOptionsDeliveryModeHighQualityFormat;
        //同步导出
        __weak typeof(self) wkSlf = self;
        [[PHImageManager defaultManager] requestImageForAsset:self.asset targetSize:PHImageManagerMaximumSize contentMode:PHImageContentModeDefault options:options resultHandler:^(UIImage * _Nullable result, NSDictionary * _Nullable info) {
            if (result) {
                __strong typeof(wkSlf) stgSlf = wkSlf;
                stgSlf.plainData = UIImageJPEGRepresentation(result, SS_IMAGE_COMPRESS_SCALE);
                stgSlf.filePlainSize = self.plainData.length;
            }
        }];
        NSLog(@"asset image size:%zd", self.filePlainSize);
        evaSize = self.filePlainSize;
    } else {
        evaSize = [self.plainData length];
    }
    return evaSize + placeholderSize;
}

/**
 pre deal with file data for compress/encrypt etc.
 */
- (void)handleDealingPlainFileWhilePreUploadWithCompletion:(void(^_Nullable)(NSError * _Nullable err))completion {
    SSFileType type = [self readObjectType];
    NSError *err = nil;
    //path/data encrypt
    if (type & SSFileTypeVideo) {
        AVURLAsset *urlAsset = [self fetchVideoAssetURL];
        if (urlAsset) {
            NSNumber *size;
            [urlAsset.URL getResourceValue:&size forKey:NSURLFileSizeKey error:nil];
            NSLog(@"origin size is %f---MB",[size floatValue]/(SS_FILE_UNIT_MB)); //size is /MB
            self.filePlainSize = [size unsignedLongLongValue];
            //compress video file size
            NSString *fileName = [self.fileName componentsSeparatedByString:@"."][0];
            fileName = PBFormat(@"%@.mp4",fileName);
#if DEBUG
            self.fileTempPath = [NSTemporaryDirectory() stringByAppendingPathComponent:fileName];
//            NSString *homePath = @"/Users/nanhujiaju/Desktop";
//            self.fileTempPath = [homePath stringByAppendingPathComponent:fileName];
#else
            self.fileTempPath = [NSTemporaryDirectory() stringByAppendingPathComponent:fileName];
#endif
            NSFileManager *fileManaher = [NSFileManager defaultManager];
            [fileManaher removeItemAtPath:self.fileTempPath error:nil];
            NSLog(@"开始压缩文件...");
            //compress data for mp4
            PHAssetResource *resource;
            NSArray <PHAssetResource*>*res = [PHAssetResource assetResourcesForAsset:self.asset];
            if (res.count > 0) {
                resource = [res firstObject];
            }
            NSArray *compatiblePresets = [AVAssetExportSession exportPresetsCompatibleWithAsset:urlAsset];
            if ([compatiblePresets containsObject:AVAssetExportPresetLowQuality]) {
                AVAssetExportSession *exportSession = [[AVAssetExportSession alloc] initWithAsset:urlAsset presetName:AVAssetExportPreset640x480];
                exportSession.outputURL = [NSURL fileURLWithPath:self.fileTempPath];//设置压缩后视频流导出的路径
                exportSession.shouldOptimizeForNetworkUse = true;
                //转换后的格式
                exportSession.outputFileType = AVFileTypeMPEG4;
                //异步导出
                __weak typeof(self) wkSlf = self;
                dispatch_semaphore_t sema = dispatch_semaphore_create(0);
                [exportSession exportAsynchronouslyWithCompletionHandler:^{
                    // 如果导出的状态为完成
                    if ([exportSession status] == AVAssetExportSessionStatusCompleted) {
                        //NSLog(@"视频压缩成功,压缩后大小 %f MB",[self fileSize:[self compressedURL]]);
                        NSError *err;
                        __strong typeof(wkSlf) stgSlf = wkSlf;
                        NSDictionary *attr =[fileManaher attributesOfItemAtPath:stgSlf.fileTempPath error:&err] ; //文件属性
                        if (err) {
                            NSLog(@"failed to fetch file attr:%@", err.localizedDescription);
                        }
                        uint64_t size = [[attr objectForKey:NSFileSize] unsignedLongLongValue];
                        NSLog(@"compressed file size is：%f MB ",size/(1024*1024.f));
                        stgSlf.fileCompressSize = size;
                    }else{
                        //压缩失败的回调
                        NSLog(@"压缩失败");
                    }
                    dispatch_semaphore_signal(sema);
                }];
                dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
            }
        }
    } else if (type & SSFileTypeImage) {
        if (!self.plainData) {
            PHImageRequestOptions *options = [PHImageRequestOptions new];
            options.synchronous = true;
            options.networkAccessAllowed = false;
            options.deliveryMode = PHImageRequestOptionsDeliveryModeHighQualityFormat;
            //同步导出
            __weak typeof(self) wkSlf = self;
            [[PHImageManager defaultManager] requestImageForAsset:self.asset targetSize:PHImageManagerMaximumSize contentMode:PHImageContentModeDefault options:options resultHandler:^(UIImage * _Nullable result, NSDictionary * _Nullable info) {
                if (result) {
                    __strong typeof(wkSlf) stgSlf = wkSlf;
                    stgSlf.plainData = UIImageJPEGRepresentation(result, SS_IMAGE_COMPRESS_SCALE);
                }
            }];
        }
    }
    //encrypt file/data
    if (type & SSFileTypeVideo) {
        NSString *fileName = [self.fileName componentsSeparatedByString:@"."][0];
        fileName = PBFormat(@"%@_encrypt.mp4",fileName);
#if DEBUG
        //self.cipherFilePath = self.fileTempPath.copy;
        self.cipherFilePath = [NSTemporaryDirectory() stringByAppendingPathComponent:fileName];
#else
        self.cipherFilePath = [NSTemporaryDirectory() stringByAppendingPathComponent:fileName];
#endif
        //文件加密
        uint64_t size = 0;
        size = [SSKit codecFile:SS_CODEC_TYPE_ENCRYPT atPath:self.fileTempPath withDestPath:self.cipherFilePath];
        if (size == 0) {
            size = self.fileCompressSize;
            self.cipherFilePath = self.fileTempPath.copy;
            NSLog(@"文件加密出错了");
        } else {
            NSLog(@"文件加密成功，即将删除临时文件...");
            NSError *err;
            NSFileManager *fileManager = [NSFileManager defaultManager];
            if (self.fileTempPath.length != 0) {
                [fileManager removeItemAtPath:self.fileTempPath error:&err];
                if (err) {
                    NSLog(@"failed to remove tmp file after encrypt success--with error:%@", err.localizedDescription);
                } else {
                    NSLog(@"已删除临时文件！");
                    self.fileTempPath = nil;
                }
            }
        }
        //size for encrypt file
        NSLog(@"encrypted file size is：%f MB ",size/(1024*1024.f));
        self.cipherSize = size;
        //此时不读到内存 上传时再去读
    } else {
        FlkKmsSdk *kms = [[FlkKmsSdk alloc] init];
        NSData *cipherData = [kms FlkEnrypt_sm4_byte:self.plainData];
        self.cipherData = [NSData dataWithData:cipherData];
        self.cipherSize = [self.cipherData length];
    }
    if (completion) {
        completion(err);
    }
}

- (uint64_t)fetchRealCipherSize {
    return self.cipherSize;
}

- (OSSPutObjectRequest * _Nullable)fetchObjectPlaceholderRequest {
    
    return nil;
}

- (OSSPutObjectRequest * _Nullable)fetchObjectRealDataPutRequest {
    //文件过大 则需要分片上传
    if (self.cipherSize >= SS_FILE_SINGLE_MAX_SIZE) {
        return nil;
    }
    if (self.request == nil) {
        //...
        OSSPutObjectRequest *put = [OSSPutObjectRequest new];
        // 必填字段
        put.bucketName = [self fetchBucketName];
        put.objectKey = self.objKey.copy;
        //put.objectKey = PBFormat(@"tmp_%@.mp4", [SSKit generateRandomObjectKey4Length:10]);
        
        //put.uploadingFileURL = [NSURL fileURLWithPath:@"<filepath>"];
        NSData *cipherData = [self fetchCipherData];
        put.uploadingData = cipherData; // 直接上传NSData
        // 设置Content-Type，可选
        put.contentType = @"application/octet-stream";
        // 设置MD5校验，可选
        //put.contentMd5 = [OSSUtil base64Md5ForFilePath:@"<filePath>"]; // 如果是文件路径
        put.contentMd5 = [OSSUtil base64Md5ForData:cipherData]; // 如果是二进制数据
        self.request = put;
    }
    return self.request;
}

#pragma mark --- Getter methods ---

- (AVURLAsset * _Nullable)fetchVideoAssetURL {
    __block AVURLAsset *dest_asset = nil;
    if (self.asset) {
        if (self.assetURL) {
            return self.assetURL;
        }
        PHVideoRequestOptions *options = [[PHVideoRequestOptions alloc] init];
        options.networkAccessAllowed = false;
        options.version = PHImageRequestOptionsVersionCurrent;
        options.deliveryMode = PHImageRequestOptionsDeliveryModeHighQualityFormat;
        dispatch_semaphore_t sema = dispatch_semaphore_create(0);
        [[PHCachingImageManager defaultManager] requestAVAssetForVideo:self.asset options:options resultHandler:^(AVAsset * _Nullable asset, AVAudioMix * _Nullable audioMix, NSDictionary * _Nullable info) {
            dest_asset = (AVURLAsset *)asset;
            dispatch_semaphore_signal(sema);
        }];
        dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
    }
    self.assetURL = [dest_asset copy];
    return dest_asset;
}

- (void)writeCompressVideoFile2TempDirectoryWithURLAsset:(AVURLAsset *)urlAsset {
    NSString *objName = self.fileName;
    self.fileTempPath = [NSTemporaryDirectory() stringByAppendingPathComponent:objName];
    NSFileManager *fileManaher = [NSFileManager defaultManager];
    [fileManaher removeItemAtPath:self.fileTempPath error:nil];
    
    PHAssetResource *resource;
    NSArray <PHAssetResource*>*res = [PHAssetResource assetResourcesForAsset:self.asset];
    if (res.count > 0) {
        resource = [res firstObject];
    }
    /*
    [[PHAssetResourceManager defaultManager] writeDataForAssetResource:resource
                                                                toFile:[NSURL fileURLWithPath:PATH_MOVIE_FILE]
                                                               options:nil
                                                     completionHandler:^(NSError * _Nullable error) {
                                                         if (error) {
                                                             NSLog(@"failed to write file:%@", error.localizedDescription);
                                                         } else {
                                                             NSError *err;
                                                             NSDictionary *attr =[fileManaher attributesOfItemAtPath:PATH_MOVIE_FILE error:&err] ; //文件属性
                                                             if (err) {
                                                                 NSLog(@"failed to fetch file attr:%@", err.localizedDescription);
                                                             }
                                                             uint64_t size = [[attr objectForKey:NSFileSize] unsignedLongLongValue];
                                                             NSLog(@"file size is：%f MB ",size/(1024*1024.f));
                                                         }
                                                     }];
     //*/
    //*
    NSArray *compatiblePresets = [AVAssetExportSession exportPresetsCompatibleWithAsset:urlAsset];
    if ([compatiblePresets containsObject:AVAssetExportPresetLowQuality]) {
        
        AVAssetExportSession *exportSession = [[AVAssetExportSession alloc] initWithAsset:urlAsset presetName:AVAssetExportPreset640x480];
        exportSession.outputURL = [NSURL fileURLWithPath:self.fileTempPath];//设置压缩后视频流导出的路径
        exportSession.shouldOptimizeForNetworkUse = true;
        //转换后的格式
        exportSession.outputFileType = AVFileTypeMPEG4;
        //异步导出
        [exportSession exportAsynchronouslyWithCompletionHandler:^{
            // 如果导出的状态为完成
            if ([exportSession status] == AVAssetExportSessionStatusCompleted) {
                //NSLog(@"视频压缩成功,压缩后大小 %f MB",[self fileSize:[self compressedURL]]);
                NSError *err;
                NSDictionary *attr =[fileManaher attributesOfItemAtPath:self.fileTempPath error:&err] ; //文件属性
                if (err) {
                    NSLog(@"failed to fetch file attr:%@", err.localizedDescription);
                }
                uint64_t size = [[attr objectForKey:NSFileSize] unsignedLongLongValue];
                NSLog(@"compressed file size is：%f MB ",size/(1024*1024.f));
            }else{
                //压缩失败的回调
                NSLog(@"压缩失败");
            }
        }];
    }
    //*/
}

- (NSData * _Nullable)fetchData4Asset {
    __block NSData *dest_data = nil;
    if (self.asset) {
        if (self.asset.mediaType == PHAssetMediaTypeImage) {
            PHImageRequestOptions *options = [PHImageRequestOptions new];
            options.synchronous = true;
            options.networkAccessAllowed = false;
            options.deliveryMode = PHImageRequestOptionsDeliveryModeHighQualityFormat;
            [[PHImageManager defaultManager] requestImageForAsset:self.asset targetSize:PHImageManagerMaximumSize contentMode:PHImageContentModeDefault options:options resultHandler:^(UIImage * _Nullable result, NSDictionary * _Nullable info) {
                if (result) {
                    dest_data = UIImageJPEGRepresentation(result, SS_IMAGE_COMPRESS_SCALE);
                }
            }];
        } else if (self.asset.mediaType == PHAssetMediaTypeVideo) {
            AVURLAsset *url = [self fetchVideoAssetURL];
            if (url) {
                dest_data = [NSData dataWithContentsOfURL:url.URL];
            }
        }
    }
    return dest_data;
}

- (NSData *)fetchCipherData {
    if (self.fileType & SSFileTypeVideo) {
        //单个视频文件 小于 阈值 则毋需分片
        self.cipherData = [NSData dataWithContentsOfFile:self.cipherFilePath];
    }
    return self.cipherData;
}

- (NSString *)fetchBucketName {
    SSFileType type = [self readObjectType];
    if (type & SSFileTypeImage) {
        return SS_BUCKET_IMG;
    } else if (type & SSFileTypeVideo) {
        return SS_BUCKET_VID;
    }
    return SS_BUCKET_DOC;
}

- (SSFileType)readObjectType {
    if (self.asset) {
        if (self.asset.mediaType == PHAssetMediaTypeVideo) {
            return SSFileTypeVideo;
        } else if (self.asset.mediaType == PHAssetMediaTypeImage) {
            return SSFileTypeImage;
        }
    }
    return SSFileTypeFile;
}

/**
 时间戳 毫秒
 */
- (uint64_t)readTimestamp4Now {
    return [[NSDate date] timeIntervalSince1970] * 1000;
}

- (NSDictionary<NSString*,id>*)fetchCallbackCfgBody {
    NSString *account = [SSConfigure shared].g_usr_acc;
    NSString *fileType = [self convert2TypeString];
    NSString *fileId = self.objKey.copy;
    NSString *fileName = self.fileName.copy;
    NSNumber *fileSize = [NSNumber numberWithDouble:self.cipherSize];
    NSNumber *fileUploadTime = [NSNumber numberWithUnsignedLongLong:[self readTimestamp4Now]];
    //authorization-token
    NSDictionary *header = [[PBNetService shared].requestSerializer HTTPRequestHeaders];
    NSString *token = [header objectForKey:SS_HTTP_PROTO_KEY_AUTHORIZAYION];
    NSDictionary *body = NSDictionaryOfVariableBindings(account, token, fileId, fileName, fileSize, fileType, fileUploadTime);
    return body;
}

- (NSDictionary<NSString*,NSString*>*)fetchCallbackCfg {
    NSString *callbackUrl = PBFormat(@"%@/v1/file/operation/upload", SS_API_HOST);
    NSString *callbackBodyType = @"application/json";
    //callback body/assemble body
    NSDictionary *body = [self fetchCallbackCfgBody];
    NSString *callbackBody = [body mj_JSONString];
    return NSDictionaryOfVariableBindings(callbackUrl, callbackBodyType, callbackBody);
}

- (NSDictionary <NSString*,NSString*>*)readObjectCallbackVar {
    NSMutableDictionary<NSString*,NSString*> *params = [NSMutableDictionary dictionaryWithCapacity:0];
    /**
     {
     "account": "13888887777",
     "fileType": "image",
     "fileId": "zxcczxczxczxc",
     "fileSize": 1000000,
     "fileName": "123.jpg",
     "fileUploadTime": 1504095128000
     }
     */
    //TODO:usr account 此处应判断用户状态
    NSString *account = [SSConfigure shared].g_usr_acc;
    NSString *fileType = [self convert2TypeString];
    NSString *fileId = self.objKey.copy;
    NSString *fileName = self.fileName.copy;
    NSNumber *fileSizeNum = [NSNumber numberWithDouble:self.cipherSize];
    NSString *fileSize = [fileSizeNum stringValue];
    NSNumber *fileUploadTimeNum = [NSNumber numberWithUnsignedLongLong:[self readTimestamp4Now]];
    NSString *fileUploadTime = [fileUploadTimeNum stringValue];
    //authorization-token
    NSString *token = [[[PBNetService shared].requestSerializer HTTPRequestHeaders] objectForKey:SS_HTTP_PROTO_KEY_AUTHORIZAYION];
    NSLog(@"fetched token:%@", token);
    [params setObject:token forKey:@"x:token"];
    [params setObject:fileId forKey:@"x:file_id"];
    [params setObject:account forKey:@"x:account"];
    [params setObject:fileName forKey:@"x:file_name"];
    [params setObject:fileType forKey:@"x:file_type"];
    [params setObject:fileSize forKey:@"x:file_size"];
    [params setObject:fileUploadTime forKey:@"x:file_upload_time"];
    //NSDictionaryOfVariableBindings(account, fileType, fileId, fileSize, fileName, fileUploadTime, token);
    return params.copy;
}

#pragma mark --- Convert methods ---

- (NSString *)convertStatus2String {
    [super convertStatus2String];
    
    NSString *statusString = @"等待中...";
    if (self.status & SSObjectStatusProcessing) {
        statusString = @"正在处理...";
    } else if (self.status & SSObjectStatusUploading) {
        statusString = @"正在上传...";
    } else if (self.status & SSObjectStatusFailed) {
        statusString = @"上传失败";
    } else if (self.status & SSObjectStatusDone) {
        statusString = @"上传完成";
    }
    return statusString;
}

- (NSString *)convert2TypeString {
    NSString *typeString = @"other";
    SSFileType type = [self readObjectType];
    if (type & SSFileTypeImage) {
        typeString = @"image";
    } else if (type & SSFileTypeVideo) {
        typeString = @"video";
    } else if (type & SSFileTypeFile) {
        typeString = @"file";
    } else if(type & SSFileTypeContacts){
        typeString = @"contact";
    }
    return typeString;
}

@end
