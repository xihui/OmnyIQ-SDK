/**
 * @file message.h
 * @brief  :define cmd and cmd node
 * @author Lei Dai
 * @version 1.0
 * @date 2015-07-23
 */

#ifndef _DEVICE_PROFILE_INTERFACE_H_
#define _DEVICE_PROFILE_INTERFACE_H_
#include "cJSON.h"

#define MAX_CMD_LEN (100)
#define MAX_MONITOR_TYPE_LEN (100)
#define MAX_KVList_LEN (100)
#define MAX_KEY_LEN (100)
#define MAX_VAL_LEN (100)

#define MAX_SN_LEN (50)
#define MAX_MODEL_LEN (50)
#define MAX_MAC_LEN (24)
#define MAX_COUNTRY_LEN (100)
#define MAX_LOCATION_LEN (100)

struct BasicDeviceInfo_s
{
	char SN[MAX_SN_LEN];			//序列号
	char Model[MAX_MODEL_LEN];		//型号
	char MAC[MAX_MAC_LEN];			//MAC地址
	char Country[MAX_COUNTRY_LEN];	//国家
	char Location[MAX_LOCATION_LEN];//地区
	//其他信息待添加
};

typedef struct BasicDeviceInfo_s BasicDeviceInfo;

/* call this function before calling "DeviceInit" to enable the xmpp logging */
/* set "on" to 1 to enable */
void Set_Xmpp_Log_On(int on);

/**
 * @brief  :需要用户实现的回调函数。用户需要根据收到的命令，将需要反馈的结果按照JSON格式填充好，并将JSON指针通过response返回出来即可
 *
 * @Param  :request - 收到的命令及参数（以json格式展现）
 * @Param  :response- 对命令进行处理后，可能需要反馈处理结果，以该指针传出
 *
 * @Returns  :	 0 - on success
 * 				-1 - on error
 */
typedef int (*ON_CMD_FUNC)(cJSON *request, cJSON **response);

/**
 * @brief  :用户按照Cloud_Payload的格式，组织好一段数据后，调用该接口将数据发送出去
 *
 * @Param  :payload - 待发送的数据流
 *
 * @Returns  :	0	- on success
 * 				-1	- on fail
 */
int Send_Report(const char*payload);
//往指定账户发送消息
int Send_Report_To(const char*payload, const char *acc);
//往默认账户发送一段JSON
int Send_Report_CJSON(cJSON *report);
//在JSON结构前面添加一段前缀后，往默认账户发送
int Send_Report_CJSON_With_Prefix(cJSON *report, char *prefix);
//往指定账户发送JSON
int Send_Report_CJSON_To(cJSON* report, char *acc);
//在JSON结构前面添加一段前缀后，往指定账户发送
int Send_Report_CJSON_With_Prefix_To(cJSON* report, char *prefix, char *acc);

void Wait_Xmpp_Logon();

int Xmpp_Has_TLS();

void Enable_Xmpp_TLS();

/**
 * @brief  :初始化设备资源，在程序退出时需要调用Device_Destroy进行资源回收
 *
 * @Param  :BsicInfo -设备的基本信息，参见BasiceDeviceInfo_s结构体定义
 * @Param  :on_cmd_fun -所有命令的回调函数,当路由器收到管理端发来的命令后，会调用该回调函数进行处理，命令的格式按照JSON格式，双方进行约定
 *
 * @Returns  :	0	- on success
 * 				-1	- on error
 */
int Device_Init(struct BasicDeviceInfo_s* BasicInfo, const char* acc, ON_CMD_FUNC on_cmd_fun);

/**
 * @brief  :调用该接口后，程序进入接口内部进行事件循环,即等待接收命令-接收命令-处理命令的循环中
 *
 * @Returns  :
 */
int Device_Run(char * (*loop_fun)(), int loop_tv);

/**
 * @brief  :回收设备资源
 */
void Device_Destroy();
#endif
