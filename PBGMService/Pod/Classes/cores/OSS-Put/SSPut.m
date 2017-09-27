//
//  SSPut.m
//  StoreService
//
//  Created by nanhujiaju on 2017/8/29.
//  Copyright © 2017年 nanhujiaju. All rights reserved.
//

#import "SSPut.h"
#import "SSKit.h"
#import "SSPutObject.h"
#import "SSConfigure.h"
#import "AppDelegate.h"
#import <Photos/PHAsset.h>
#import <AliyunOSSiOS/AliyunOSSiOS.h>
#import <SVProgressHUD/SVProgressHUD.h>

static NSString * const SS_SCHEME = @"https";
static NSString * const SS_DOMAIN = @"oss-cn-hangzhou.aliyuncs.com";//外网

NSString * const SS_KVO_PATH_PUT_QUEUE =   @"taskQueue";

typedef void(^completionCallback)(NSError*_Nullable err);

@interface SSPut ()

/**
 client for oss
 */
@property (nonatomic, strong) OSSClient * osc;

@property (nonatomic, copy, nullable) completionCallback completion;

/**
 queue for upload task
 */
@property (nonatomic, strong) NSMutableArray <SSPutObject*>*taskQueue;
@property (nonatomic, assign) BOOL isRunning;
@property (nonatomic, assign, readwrite) AFNetworkReachabilityStatus netStatus;

@end

static SSPut * instance = nil;
static dispatch_once_t onceToken;

@implementation SSPut

- (void)dealloc {
    [self removeObserver:self forKeyPath:SS_KVO_PATH_PUT_QUEUE];
}

/**
 singletone mode
 */
+ (instancetype)shared {
    dispatch_once(&onceToken, ^{
        if (instance == nil) {
            instance = [[[self class] alloc] init];
        }
    });
    return instance;
}

+ (void)releasePutSingletone {
    [instance removeObserver:instance forKeyPath:SS_KVO_PATH_PUT_QUEUE];
    onceToken = 0;
    instance = nil;
}

- (id)init {
    self = [super init];
    if (self) {
        //监控上传队列变化
        self.isRunning = false;
        [self addObserver:self forKeyPath:SS_KVO_PATH_PUT_QUEUE options:NSKeyValueObservingOptionNew|NSKeyValueObservingOptionOld context:NULL];
        
        //网络监听
        self.netStatus = AFNetworkReachabilityStatusUnknown;
        weakify(self)
        [[AFNetworkReachabilityManager sharedManager] setReachabilityStatusChangeBlock:^(AFNetworkReachabilityStatus status) {
            strongify(self)
            [self networkStateChanged];
        }];
        [[AFNetworkReachabilityManager sharedManager] startMonitoring];
        AFNetworkReachabilityStatus status = [[AFNetworkReachabilityManager sharedManager] networkReachabilityStatus];
        NSLog(@"init engine network state:%zd",status);
        sleep(0.25);
    }
    return self;
}

- (NSString *)description {
    return @"hello, 帅哥！";
}

#pragma mark -- Getter for OSS-Client --

/**
 检测OSS-Token是否可用
 */
- (void)checkOSSTokenAvailable {
    uint64_t timestamp_now = [[NSDate date] timeIntervalSince1970];
    uint64_t timestamp_sts = [SSConfigure shared].g_oss_expire.unsignedLongLongValue;
    if (timestamp_now >= timestamp_sts - 60 * 2) {
        //will expired, offset for 2 minutes
        NSLog(@"ststoken will expired!");
        
        //refresh sts-token and api-token
        NSString *path = @"v1/sts/token";
        NSString *account = [SSConfigure shared].g_usr_acc.copy;
        NSDictionary *params = NSDictionaryOfVariableBindings(account);
        dispatch_semaphore_t sema = dispatch_semaphore_create(0);
        [[PBNetService shared] GET:path parameters:params class:self.class view:nil hudEnable:true progress:^(NSProgress * _Nonnull progress) {
            
        } success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObj) {
            NSLog(@"refresh oss-token response:%@", responseObj);
            if (responseObj) {
                NSUInteger code = [[responseObj objectForKey:SS_HTTP_RESPONSE_KEY_CODE] integerValue];
                if (code == PB_NETWORK_RESPONSE_CODE_SUCCESS) {
                    NSDictionary *sts = [responseObj pb_dictionaryForKey:@"data"];
                    //refresh
                    [[SSConfigure shared] updateWithInfoMap:sts];
                    _osc = nil;
                } else if (code == SS_HTTP_RESPONSE_KEY_AUTHOR) {
                    [[NSNotificationCenter defaultCenter] postNotificationName:SS_APPLICATION_TOKEN_INVALID_NOTIFICATION object:nil];
                    return ;
                }
            }
            dispatch_semaphore_signal(sema);
        } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
            NSLog(@"failed to refresh sts token:%@", error.localizedDescription);
            [[NSNotificationCenter defaultCenter] postNotificationName:SS_APPLICATION_TOKEN_INVALID_NOTIFICATION object:nil];
            dispatch_semaphore_signal(sema);
        }];
        dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
    }
}

- (OSSClient *)osc {
    //传输过程中 sts-token 过期 则置空client
    if (!_osc) {
        NSString *endpoint = PBFormat(@"%@://%@", SS_SCHEME, SS_DOMAIN);
        // 由阿里云颁发的AccessKeyId/AccessKeySecret构造一个CredentialProvider。
        // 移动端建议使用STS方式初始化OSSClient。更多鉴权模式请参考后面的访问控制章节。
        id<OSSCredentialProvider> credential;
        //#if DEBUG
        //        credential = [[OSSPlainTextAKSKPairCredentialProvider alloc] initWithPlainTextAccessKey:SS_YUN_PRIVATE_ID secretKey:SS_YUN_PRIVATE_SECRETE];
        //#else
        //        credential = [[OSSStsTokenCredentialProvider alloc] initWithAccessKeyId:SS_YUN_PRIVATE_ID secretKeyId:SS_YUN_PRIVATE_SECRETE securityToken:nil];
        //#endif
        NSString *ossID = [SSConfigure shared].g_oss_kid.copy;
        NSString *ossToken = [SSConfigure shared].g_oss_ktoken.copy;
        NSString *ossSecret = [SSConfigure shared].g_oss_ksecret.copy;
        credential = [[OSSStsTokenCredentialProvider alloc] initWithAccessKeyId:ossID secretKeyId:ossSecret securityToken:ossToken];
        OSSClientConfiguration * cfg = [OSSClientConfiguration new];
        cfg.maxRetryCount = 3; // 网络请求遇到异常失败后的重试次数
        cfg.timeoutIntervalForRequest = 30; // 网络请求的超时时间
        cfg.timeoutIntervalForResource = 60 * 5; // 允许资源传输的最长时间
        /**
         由于限制，后台上传只支持直接上传文件，所以，SDK目前只在 putObject 接口，且只在 设置 fileURL 上传时，支持后台传输服务
         https://bbs.aliyun.com/simple/t294622.html
         */
        cfg.enableBackgroundTransmitService = true;
        cfg.backgroundSesseionIdentifier = [NSBundle pb_mainBundle4Key:@"CFBundleIdentifier"];
        _osc = [[OSSClient alloc] initWithEndpoint:endpoint credentialProvider:credential clientConfiguration:cfg];
    }
    return _osc;
}

#pragma mark -- Network state change --

- (void)networkStateChanged {
    NSLog(@"put server networkStateChanged!");
    UIApplicationState state = [UIApplication sharedApplication].applicationState;
    NSLog(@"UIApplicationState:%zd", state);
    if (state == UIApplicationStateBackground) {
        //在后台则不做任何操作
        return;
    }
    
    AFNetworkReachabilityStatus status = [[AFNetworkReachabilityManager sharedManager] networkReachabilityStatus];
    if (status == AFNetworkReachabilityStatusNotReachable) {
        [self failedAll4UploadTasks];
    } else if (status == AFNetworkReachabilityStatusReachableViaWiFi) {
        [self retryUploadAllQueueTasks];
    } else if (status == AFNetworkReachabilityStatusReachableViaWWAN) {
        if (!self.isRunning || self.netStatus == status || self.netStatus == AFNetworkReachabilityStatusUnknown) {
            return;
        }
        NSString *msg = @"您当前处于非Wi-Fi环境，是否继续上传？";
        NSString *ok = @"继续";
        __weak typeof(self) wkSlf = self;
        void(^cancelCompletion)() = ^{
            __strong typeof(wkSlf) stgSlf = wkSlf;
            [stgSlf failedAll4UploadTasks];
        };
        [self excuteAlertEventWithMsg:msg whetherShowCancel:true whetherShowOk:true cfgOK:ok withCancelBlock:cancelCompletion withOKBlock:nil];
    }
    self.netStatus = status;
}

- (void)excuteAlertEventWithMsg:(NSString *)msg whetherShowCancel:(BOOL)cancelShow whetherShowOk:(BOOL)okShow cfgOK:(NSString *)ok withCancelBlock:(void(^_Nullable)())cancelCompletion withOKBlock:(void(^_Nullable)())okCompletion {
    UIAlertController *alertController = [UIAlertController alertControllerWithTitle:@"提示" message:@"您当前处于非Wi-Fi环境，是否继续上传？" preferredStyle:UIAlertControllerStyleAlert];
    if (okShow) {
        NSString *okItem = ok.length == 0?@"确定":ok;
        UIAlertAction *okAction = [UIAlertAction actionWithTitle:okItem style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            if (okCompletion) {
                okCompletion();
            }
        }];
        [alertController addAction:okAction];
    }
    if (cancelShow) {
        UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            if (cancelCompletion) {
                cancelCompletion();
            }
        }];
        [alertController addAction:cancelAction];
    }
    [[self getRootProfile] presentViewController:alertController animated:true completion:^{
        
    }];
}

#pragma mark --- Getter methods ---

- (NSMutableArray<SSPutObject*>*)taskQueue {
    if (_taskQueue == nil) {
        _taskQueue = [NSMutableArray arrayWithCapacity:0];
    }
    return _taskQueue;
}

- (UIViewController *)getRootProfile {
    AppDelegate *app = (AppDelegate*)[UIApplication sharedApplication].delegate;
    return app.window.rootViewController;
}

- (BOOL)networkAvaliable {
    return [AFNetworkReachabilityManager sharedManager].networkReachabilityStatus != AFNetworkReachabilityStatusNotReachable;
}

#pragma mark --- 上传 触发器 ---

/**
 上传资源文件前先询问存储空间是否足够
 */
- (void)preQueryUsrStorage4FileSize:(uint64_t)size withCompletion:(void(^)(BOOL enough, NSString * _Nullable msg))completion {
    //v1/upload/prepare
    if (size <= 0) {
        NSLog(@"can not upload empty size---");
        if (completion) {
            completion(false, @"can not upload empty size!");
        }
        return;
    }
    NSLog(@"准备上传的文件大小:%llu M", size / SS_FILE_UNIT_MB);
    NSString *account = [SSConfigure shared].g_usr_acc;
    NSNumber *fileSize = [NSNumber numberWithUnsignedLongLong:size];//此处目前先不乘系数
    NSDictionary *params = NSDictionaryOfVariableBindings(account, fileSize);
    [[PBNetService shared] GET:@"v1/upload/prepare" parameters:params class:self.class view:nil hudEnable:true progress:^(NSProgress * _Nonnull progress) {
        
    } success:^(NSURLSessionDataTask * _Nonnull task, id  _Nullable responseObj) {
        NSLog(@"prepare query response:%@", responseObj);
        BOOL ret = false;NSString *msg = @"您当前云盘剩余容量不够，请扩容后再试！";
        if (responseObj) {
            NSUInteger code = [[responseObj objectForKey:SS_HTTP_RESPONSE_KEY_CODE] integerValue];
            msg = [responseObj pb_stringForKey:SS_HTTP_RESPONSE_KEY_MSG];
            if (code == PB_NETWORK_RESPONSE_CODE_SUCCESS) {
                ret = true;
            } else if (code == SS_HTTP_RESPONSE_KEY_AUTHOR) {
                [[NSNotificationCenter defaultCenter] postNotificationName:SS_APPLICATION_TOKEN_INVALID_NOTIFICATION object:nil];
                return ;
            }
        }
        if (completion) {
            completion(ret, msg);
        }
    } failure:^(NSURLSessionDataTask * _Nullable task, NSError * _Nonnull error) {
        NSLog(@"prepare query failed:%@", error.localizedDescription);
        if (completion) {
            completion(false, error.localizedDescription);
        }
    }];
}

/**
 当用户存储空间不够 提示用户
 TODO:这里其实可以引导用户扩容
 */
- (void)showAlert2UsrWhileCapacityNotEnoughWithMsg:(NSString *)msg {
    NSString *ok = @"知道了";
    [self excuteAlertEventWithMsg:msg whetherShowCancel:false whetherShowOk:true cfgOK:ok withCancelBlock:nil withOKBlock:nil];
}

/**
 上传系统资源文件 assets 首先转换为Request
 */
- (void)uploadAssets:(NSArray<PHAsset *> *)assets withThumbnails:(NSArray<UIImage*>*)thumbnails withCompletion:(void (^ _Nullable)(NSError * _Nullable))completion{
    self.completion = [completion copy];
    
    //无网络直接返回错误
    if (![self networkAvaliable]) {
        NSError *error = [NSError errorWithDomain:NSNetServicesErrorDomain code:-1 userInfo:nil];
        if (completion) {
            completion(error);
        }
        return;
    }
    
    //meta数据个数与thumbnail不匹配返回错误
    if (thumbnails.count != assets.count) {
        NSError *error = [NSError errorWithDomain:NSArgumentDomain code:-1 userInfo:nil];
        if (completion) {
            completion(error);
        }
        return;
    }
    
    
    // 大文件需要分片上传
    PHAsset *firstAsset = [assets firstObject];
    if (firstAsset.mediaType == PHAssetMediaTypeVideo) {
        SSPutObject *tmpObj = [[SSPutObject alloc] initWithAsset:firstAsset];
        [tmpObj prepareInitializedObject];
        uint64_t evaSize = [tmpObj evaluatePlainSize4Upload];
        if (evaSize >= SS_FILE_UPLOAD_MAX_SIZE) {
            NSLog(@"文件太大了:%@", [SSKit transformedValue:evaSize]);
            NSString *fileSize = [SSKit transformedValue:SS_FILE_UPLOAD_MAX_SIZE];
            NSString *errString = [NSString stringWithFormat:@"选择的文件不能超过%@!",fileSize];
            NSError *error = [NSError errorWithDomain:errString code:-1 userInfo:nil];
            if (completion) {
                completion(error);
            }
            return;
        }
        //判断本地空间是否足够处理
        uint64_t localStorage = [SSKit fetchPhoneStorage];
        NSLog(@"本地剩余空间:%@", [SSKit transformedValue:localStorage]);
        if (evaSize * 2.38 >= localStorage) {
            //casue of tmp/encrypt
            NSString *errString = @"本地空间不足，无法处理上传请求！";
            NSError *error = [NSError errorWithDomain:errString code:-1 userInfo:nil];
            if (completion) {
                completion(error);
            }
            return;
        }
    }
    
    //预处理 数据
    [SVProgressHUD setDefaultMaskType:SVProgressHUDMaskTypeClear];
    [SVProgressHUD showWithStatus:@"正在处理..."];
    
    //统计数据size 转换对象
    __block uint64_t asset_size = 0;//__block NSMutableArray <UIImage *>*thumbImgs = [NSMutableArray arrayWithCapacity:0];
    NSMutableArray <SSPutObject*>* tmpObjs = [NSMutableArray arrayWithCapacity:0];
    [assets enumerateObjectsUsingBlock:^(PHAsset * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        //转换为Object
        SSPutObject *tmpObj = [[SSPutObject alloc] initWithAsset:obj];
        [tmpObj prepareInitializedObject];
        UIImage *thumbnail = [thumbnails objectAtIndex:idx];
        UIImage *scaleImg = [thumbnail pb_scaleToSize:CGSizeMake(SS_IMAGE_THUMBNAIL_SIZE, SS_IMAGE_THUMBNAIL_SIZE) keepAspect:true];
        NSString *objKey = tmpObj.objKey.copy;
        //NSData *thumbnailData = UIImageJPEGRepresentation(scaleImg, SS_IMAGE_COMPRESS_SCALE);
        [[SDImageCache sharedImageCache] storeImage:scaleImg forKey:objKey toDisk:true completion:nil];
        [tmpObjs addObject:tmpObj];
        //累计size
        asset_size += [tmpObj evaluatePlainSize4Upload];
    }];
    //预询问用户存储空间
    __block BOOL canContinue = false;__block NSString *alertMsg = nil;
    weakify(self)
    [self preQueryUsrStorage4FileSize:asset_size withCompletion:^(BOOL enough, NSString * _Nullable msg) {
        canContinue = enough; alertMsg = msg.copy;
        [SVProgressHUD dismiss];
        strongify(self)
        if (!canContinue) {
            [self showAlert2UsrWhileCapacityNotEnoughWithMsg:alertMsg];
            return;
        }
        PBBACKDelay(PBANIMATE_DURATION, ^{
            //加入上传队列 开启后台线程上传任务
            [[self mutableArrayValueForKeyPath:SS_KVO_PATH_PUT_QUEUE] addObjectsFromArray:tmpObjs.copy];
        });
    }];
}

/**
 上传未加密的明文数据
 */
- (void)uploadFileRawData:(NSData *)data withObjectIdentifier:(NSString *)idf withCompletion:(void (^ _Nullable)(NSError * _Nullable))completion{
    self.completion = [completion copy];
    //数据滤空
    if (data.length == 0 || idf.length == 0) {
        if (completion) {
            NSError *error = [NSError errorWithDomain:@"can not upload empty data!" code:-1 userInfo:nil];
            completion(error);
        }
        return;
    }
    //无网络直接返回错误
    if (![self networkAvaliable]) {
        NSError *error = [NSError errorWithDomain:NSNetServicesErrorDomain code:-1 userInfo:nil];
        if (completion) {
            completion(error);
        }
        return;
    }
    
    //预询问用户存储空间
    __block BOOL canContinue = false;__block NSString *alertMsg = nil;
    [self preQueryUsrStorage4FileSize:data.length withCompletion:^(BOOL enough, NSString * _Nullable msg) {
        canContinue = enough; alertMsg = msg.copy;
    }];
    if (!canContinue) {
        [self showAlert2UsrWhileCapacityNotEnoughWithMsg:alertMsg];
        return;
    }
    //加入上传队列 开启后台线程上传任务
    SSPutObject *obj = [[SSPutObject alloc] initWithRawData:data withIdentifier:idf];
    [obj prepareInitializedObject];
    PBBACKDelay(PBANIMATE_DURATION, ^{
        [[self mutableArrayValueForKeyPath:SS_KVO_PATH_PUT_QUEUE] addObject:obj];
    });
}

#pragma mark --- KVO for task-queue count ---

- (void)observeValueForKeyPath:(NSString *)keyPath ofObject:(id)object change:(NSDictionary<NSKeyValueChangeKey,id> *)change context:(void *)context {
    if ([keyPath isEqualToString:SS_KVO_PATH_PUT_QUEUE]) {
        NSLog(@"observed key path:%@", keyPath);
        if (self.isRunning) {
            NSLog(@"upload task is running");
            return;
        }
        [self handleValueChangeEvent4TaskQueue];
    }
}

#pragma mark --- Upload task ---

- (void)checkUploadTaskError:(NSError *)err {
    if (err.code == 403) {
        //TODO:sts-token error
    }
}

/**
 只需通过添加变化来驱动 自动上传功能
 */
- (void)handleValueChangeEvent4TaskQueue {
    
    NSLog(@"task queue count: %zd", self.taskQueue.count);
    //标记为自动上传
    @synchronized (self) {
        self.isRunning = true;
    }
    
    //读取第一个 且开始自动递归上传
    SSPutObject *obj = [self nextTask];
    [self autoRecursiveUploadTask4Object:obj];
}

- (SSPutObject * _Nullable)nextTask {
    if (!PBIsEmpty(self.taskQueue)) {
        __block SSPutObject *dest_obj = nil;
        @synchronized (self.taskQueue) {
            [self.taskQueue enumerateObjectsUsingBlock:^(SSPutObject * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
                if (obj.status == SSObjectStatusWaiting) {
                    dest_obj = obj;
                    *stop = true;
                }
            }];
        }
        return dest_obj;
    }
    return nil;
}

/**
 上传成功后从队列中删除Object
 */
- (void)removeTask4ObjWhileDone:(SSPutObject *)o {
    if (!PBIsEmpty(self.taskQueue)) {
        @synchronized (self.taskQueue) {
            [self.taskQueue enumerateObjectsUsingBlock:^(SSPutObject * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
                if (o.objKey == obj.objKey) {
                    //[self.taskQueue removeObject:obj];
                    [[self mutableArrayValueForKeyPath:SS_KVO_PATH_PUT_QUEUE] removeObject:obj];
                    *stop = true;
                }
            }];
        }
    }
}

- (void)autoRecursiveUploadTask4Object:(SSPutObject *)obj {
    if (!obj) {
        NSLog(@"got an empty object");
        return;
    }
    //pre query whether sts-token will expired
    [self checkOSSTokenAvailable];
    
    obj.status = SSObjectStatusProcessing;
    //step 1:预处理-同步
    NSLog(@"开始预处理文件数据...");
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    [obj handleDealingPlainFileWhilePreUploadWithCompletion:^(NSError * _Nullable err) {
        if (err) {
            NSLog(@"pre handle error:%@", err.domain);
        }
        dispatch_semaphore_signal(sema);
    }];
    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
    NSLog(@"开始上传了");
    NSLog(@"task queue now count: %zd", self.taskQueue.count);
    __block __weak typeof(SSPutObject) *obj_wk = obj;
    OSSPutObjectRequest *req = [obj fetchObjectRealDataPutRequest];
    if (req != nil) {
        //单个文件上传 不需要切片
        // 当前上传段长度、当前已经上传总长度、一共需要上传的总长度
        req.uploadProgress = ^(int64_t bytesSent, int64_t totalBytesSent, int64_t totalBytesExpectedToSend) {
            CGFloat progress = (CGFloat)totalBytesSent / (CGFloat)totalBytesExpectedToSend;
            //NSLog(@"progress:%.2f----%lld----%lld------%lld", progress, bytesSent, totalBytesSent, totalBytesExpectedToSend);
            __strong typeof(obj_wk) obj_stg = obj_wk;
            obj_stg.progress = progress;
        };
        //设置上传回调 https://help.aliyun.com/document_detail/31989.html?spm=5176.doc32060.2.1.HtfAXn
        req.callbackParam = [obj fetchCallbackCfg];
        //根据阿里云OSS官方文档目前自定义参数无法传递给应用服务器（比如自己的后台，目前只能设置到配置参数的Body里边）
        //req.callbackVar = [obj readObjectCallbackVar];
        
        obj.status = SSObjectStatusUploading;
        OSSTask *task = [self.osc putObject:req];
        __weak typeof(self) wkSf = self;
        [task continueWithBlock:^id _Nullable(OSSTask * _Nonnull task) {
            __strong typeof(wkSf) stSf = wkSf;
            SSPutObject *next_obj = [self nextTask];
            if (!task.error) {
                [stSf done4SingleTask:obj withNextObj:next_obj];
            } else {
                NSLog(@"upload object failed, error: %@" , task.error);
                [stSf failed4SingleTask:obj withNextObj:next_obj];
            }
            return nil;
        }];
    } else {
        //需要分片上传
        //step 2: init multicast slice
        obj.status = SSObjectStatusUploading;
        __block NSString * uploadId = nil;
        __block NSMutableArray * partInfos = [NSMutableArray new];
        NSString * uploadToBucket = SS_BUCKET_VID;
        NSString * uploadObjectkey = obj.objKey.copy;
        OSSInitMultipartUploadRequest * init = [OSSInitMultipartUploadRequest new];
        init.bucketName = uploadToBucket;
        init.objectKey = uploadObjectkey;
        // init.contentType = @"application/octet-stream";
        OSSTask * initTask = [self.osc multipartUploadInit:init];
        [initTask waitUntilFinished];
        if (!initTask.error) {
            OSSInitMultipartUploadResult * result = initTask.result;
            uploadId = result.uploadId;
        } else {
            NSLog(@"multipart upload failed, error: %@", initTask.error);
            SSPutObject *next_obj = [self nextTask];
            [self failed4SingleTask:obj withNextObj:next_obj];
            return;
        }
        //really upload file
        uint64_t fileSie = [obj fetchRealCipherSize];
        //要上传的文件
        unsigned int chuckCount = (unsigned int)(fileSie / SS_FILE_SLICE_BLOCK);
        if (fileSie % SS_FILE_SLICE_BLOCK != 0) {
            chuckCount += 1;
        }
        if (chuckCount >= 10000) {
            //TODO:超过最大分片数 失败
            NSLog(@"超过了最大切片数！");
        }
        //分片上传 block size
        uint64_t offset = SS_FILE_SLICE_BLOCK;
        //分片大小
        uint64_t updateSize = 0;
        @autoreleasepool {
            for (int i = 1; i <= chuckCount; i++) {
                OSSUploadPartRequest * uploadPart = [OSSUploadPartRequest new];
                uploadPart.bucketName = uploadToBucket;
                uploadPart.objectkey = uploadObjectkey;
                uploadPart.uploadId = uploadId;
                uploadPart.partNumber = i; // part number start from 1
                NSFileHandle* readHandle = [NSFileHandle fileHandleForReadingAtPath:obj.cipherFilePath];
                [readHandle seekToFileOffset:offset * (i -1)];
                NSData* data = [readHandle readDataOfLength:offset];
                uploadPart.uploadPartData = data;
                //TODO:如果想支持后台上传 设置分片uploadPartFileURL即可
                __block int64_t sliceTotalBytes = 0;
                uploadPart.uploadPartProgress = ^(int64_t bytesSent, int64_t totalBytesSent, int64_t totalBytesExpectedToSend) {
                    //NSLog(@"multi progress:----%lld----%lld------%lld", bytesSent, totalBytesSent, totalBytesExpectedToSend);
                    sliceTotalBytes = totalBytesExpectedToSend;
                    CGFloat progress = (CGFloat)(updateSize + totalBytesSent) / (CGFloat)(fileSie);
                    NSLog(@"multicast progress:%f", progress);
                    __strong typeof(obj_wk) obj_stg = obj_wk;
                    obj_stg.progress = progress;
                };
                OSSTask * uploadPartTask = [self.osc uploadPart:uploadPart];
                [uploadPartTask waitUntilFinished];
                if (!uploadPartTask.error) {
                    OSSUploadPartResult * result = uploadPartTask.result;
                    uint64_t fileSize = [[[NSFileManager defaultManager] attributesOfItemAtPath:uploadPart.uploadPartFileURL.absoluteString error:nil] fileSize];
                    [partInfos addObject:[OSSPartInfo partInfoWithPartNum:i eTag:result.eTag size:fileSize]];
                    updateSize += sliceTotalBytes;
                } else {
                    SSPutObject *next_obj = [self nextTask];
                    [self failed4SingleTask:obj withNextObj:next_obj];
                    NSLog(@"upload part error: %@", uploadPartTask.error);
                    
                    //TODO:上传过程中STS token可能会过期
                    
                    return;
                }
            }
        }
        
        //完成上传
        OSSCompleteMultipartUploadRequest * complete = [OSSCompleteMultipartUploadRequest new];
        complete.bucketName = SS_BUCKET_VID;
        complete.objectKey = obj.objKey.copy;
        complete.uploadId = uploadId;
        complete.partInfos = partInfos;
        complete.callbackParam = [obj fetchCallbackCfg];
        OSSTask * completeTask = [self.osc completeMultipartUpload:complete];
        __weak typeof(self) wkSf = self;
        [[completeTask continueWithBlock:^id(OSSTask *task) {
            __strong typeof(wkSf) stSf = wkSf;
            SSPutObject *next_obj = [self nextTask];
            if (!task.error) {
                OSSCompleteMultipartUploadResult * result = task.result;
                NSLog(@"server call back return : %@", result.serverReturnJsonString);
                [stSf done4SingleTask:obj withNextObj:next_obj];
            } else {
                NSLog(@"upload object failed, error: %@" , task.error);
                [stSf failed4SingleTask:obj withNextObj:next_obj];
            }
            return nil;
        }] waitUntilFinished];
    }
}

/**
 单条上传失败
 */
- (void)failed4SingleTask:(SSPutObject *)obj withNextObj:(SSPutObject *)next {
    obj.status = SSObjectStatusFailed;
    [self startNextTask:next];
}

/**
 完成单条上传
 */
- (void)done4SingleTask:(SSPutObject *)obj withNextObj:(SSPutObject *)next{
    NSLog(@"upload object success!");
    //通知UI
    dispatch_async(dispatch_get_main_queue(), ^{
        long date = [[NSDate date] timeIntervalSince1970]*1000;
        NSDictionary *objInfo = @{@"fileId":obj.objKey,@"fileName":obj.fileName,@"fileSize":@([obj fetchRealCipherSize]),@"fileUploadTime":@(date),@"fileType":@(obj.fileType)};
        [[NSNotificationCenter defaultCenter] postNotificationName:@"PutObjectSuccess" object:objInfo];
    });
    
    obj.status = SSObjectStatusDone;
    [self removeTask4ObjWhileDone:obj];
    [self startNextTask:next];
}

- (void)startNextTask:(SSPutObject *)next {
    next.status = SSObjectStatusProcessing;
    /**
     单条上传完成动作：本地数据库存储且上报API后台，本版本此处做简化处理为仅仅上报API后台 用户刷新即可
     */
    //v1/file/operation/upload 此处采取阿里云-后台回调的方式处理
    
    if (!next) {
        [self done4UploadTasks];
    } else {
        [self autoRecursiveUploadTask4Object:next];
    }
}

/**
 上传队列完成
 */
- (void)done4UploadTasks {
    //[[self mutableArrayValueForKeyPath:SS_KVO_PATH_PUT_QUEUE] removeAllObjects];
    //仅删除已完成的任务
    @synchronized (self.taskQueue) {
        __block NSMutableArray <SSPutObject *> * tmpObjects = [NSMutableArray arrayWithCapacity:0];
        [self.taskQueue enumerateObjectsUsingBlock:^(SSPutObject * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
            if (obj.status != SSObjectStatusFailed) {
                [tmpObjects addObject:obj];
            }
        }];
        [[self mutableArrayValueForKeyPath:SS_KVO_PATH_PUT_QUEUE] removeObjectsInArray:tmpObjects.copy];
    }
    
    @synchronized (self) {
        self.isRunning = false;
    }
    
    NSLog(@"上传任务已经全部结束！");
}

/**
 重置上传队列中的所有任务为失败，比如断网
 */
- (void)failedAll4UploadTasks {
    if (!PBIsEmpty(self.taskQueue)) {
        @synchronized (self.taskQueue) {
            [self.taskQueue enumerateObjectsUsingBlock:^(SSPutObject * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
                if (obj.status != SSObjectStatusDone) {
                    obj.status = SSObjectStatusFailed;
                }
            }];
        }
    }
    
    [self done4UploadTasks];
}

/**
 重置上传队列所有任务为重新上传状态，比如连上Wi-Fi
 */
- (void)retryUploadAllQueueTasks {
    if (!PBIsEmpty(self.taskQueue)) {
        __block NSMutableArray <SSPutObject *> * tmpObjects = [NSMutableArray arrayWithCapacity:0];
        @synchronized (self.taskQueue) {
            [self.taskQueue enumerateObjectsUsingBlock:^(SSPutObject * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
                if (obj.status == SSObjectStatusFailed) {
                    [tmpObjects addObject:obj];
                }
            }];
            [[self mutableArrayValueForKeyPath:SS_KVO_PATH_PUT_QUEUE] removeAllObjects];
            [[self mutableArrayValueForKeyPath:SS_KVO_PATH_PUT_QUEUE] addObjectsFromArray:tmpObjects.copy];
        }
    }
}

- (void)removeUploadTask4ObjectKey:(NSString *)objKey {
    if (objKey.length == 0) {
        return;
    }
    
    NSLog(@"prepare remove object for key:%@", objKey);
    PBBACKDelay(PBANIMATE_DURATION, ^{
        __block SSPutObject *destObj = nil;
        @synchronized(self.taskQueue){
            [self.taskQueue enumerateObjectsUsingBlock:^(SSPutObject * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
                NSString *tmpKey = obj.objKey;
                if ([tmpKey isEqualToString:objKey]) {
                    destObj = obj;
                }
            }];
            if (destObj) {
                NSLog(@"找到了要删除的元数据!");
                OSSPutObjectRequest *req = [destObj fetchObjectRealDataPutRequest];
                if (!req.isCancelled) {
                    [req cancel];
                }
                [[self mutableArrayValueForKeyPath:SS_KVO_PATH_PUT_QUEUE] removeObject:destObj];
                //[self.taskQueue removeObject:destObj];
            }
        }
    });
}

@end
