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
	char SN[MAX_SN_LEN];			//serial number
	char Model[MAX_MODEL_LEN];		//mode type
	char MAC[MAX_MAC_LEN];			//MAC address
	char Country[MAX_COUNTRY_LEN];	//country
	char Location[MAX_LOCATION_LEN];//location
};

typedef struct BasicDeviceInfo_s BasicDeviceInfo;

/* call this function before calling "DeviceInit" to enable the xmpp logging */
/* set "on" to 1 to enable */
void Set_Xmpp_Log_On(int on);

/**
 * @brief  :callback function users must realize by themselves. user need to fill the feedback results with JSON format according to received command and then returned the JSON pointer through the response
 *
 * @Param  :request - received command and parameter (JSON format)
 * @Param  :response- handle the command and maybe feedback the handled results through this pointer
 *
 * @Returns  :	 0 - on success
 * 				-1 - on error
 */
typedef int (*ON_CMD_FUNC)(cJSON *request, cJSON **response);

/**
 * @brief  : user sends data invoking this interface after organizes data according to format of Cloud_Payload
 *
 * @Param  :payload - data flow to be sent
 *
 * @Returns  :	0	- on success
 * 				-1	- on fail
 */
int Send_Report(const char*payload);
//send messages to appointed account
int Send_Report_To(const char*payload, const char *acc);
//send JSON message to appointed account
int Send_Report_CJSON(cJSON *report);
//add some prefix to JSON message and then send it to default account
int Send_Report_CJSON_With_Prefix(cJSON *report, char *prefix);
//send JSON message to appointed account
int Send_Report_CJSON_To(cJSON* report, char *acc);
//add some prefix to JSON message and then send it to appointed account
int Send_Report_CJSON_With_Prefix_To(cJSON* report, char *prefix, char *acc);

void Wait_Xmpp_Logon();

int Xmpp_Has_TLS();

void Enable_Xmpp_TLS();

/**
 * @brief  :c，Initialize device resources. And as program exits， Device_Destory will be called to recycle resources
 *
 * @Param  :BasicInfo - device essential information, referenced by BasiceDeviceInfo_s struct definition
 * @Param  :acc - xmpp cloud account, as program calls Send_Report function，it will send the received message to this account
 * @Param  :on_cmd_fun - callback function for all commands. As router received the command from management end， it will call this callback function to handle. Both sides can arranged command format followed JSON.
 *
 * @Returns  :  0   - on success
 *              -1  - on error
 */
int Device_Init(struct BasicDeviceInfo_s* BasicInfo, const char* acc, ON_CMD_FUNC on_cmd_fun);

/**
 * @brief  :When invoking this interface, program will enter internal interface to do event loop. etc. the loop of waiting for an order-taking an order - handling an order
 *
 * @Returns  :
 */
int Device_Run(char * (*loop_fun)(), int loop_tv);

/**
 * @brief  : recycle device resources
 */
void Device_Destroy();
#endif
