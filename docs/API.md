## FOR INITIALIZATION & GARBAGE COLLECTION

### Device_Init

Initialize device resources. This API uses BasicInfo->SN as xmpp protocol login account. And before this API is called, We must make sure that BasicInfo->SN will be assigned a MAC value or a serial number.
```C
/* 
 * @brief:	Initialize device resources. And as program exits, Device_Destory will be called to recycle resources.
 *
 * @Param:	BasicInfo - device essential information, referenced by BasicDeviceInfo_s struct definition.
 * @Param:	acc - xmpp cloud account - when program calls Send_Report function,
 			it will send the received message to this account.
 * @Param:	on_cmd_fun - callback function for all commands. When the device receives the command from management end,
 			it will call this callback function to handle. Both sides can arrange command format following JSON.
 *
 * @Returns:	0 - on success
 *             -1 - on error
 */
 
int Device_Init(struct BasicDeviceInfo_s* BasicInfo, const char* acc, ON_CMD_FUNC on_cmd_fun);

```
### Device_Run
```C
/* 
 * @brief:	After invoking this interface, program will enter the internal infinite loop and xmpp protocol will work regularly.
 *
 * @Returns:
 */
int Device_Run(char * (*loop_fun)(), int loop_tv);
```
### Device_Destroy
```C
/*
 * @brief:	Garbage Collection
 */
void Device_Destroy();
```

## FOR DATA REPORTING

### Send_Report
```C
/*
 * @brief:	Send payload data to xmpp cloud account with xmpp protocol
 *
 * @Param:	payload	- dataflow to be sent 
 * @Returns:	0 - on success
 *             -1 - on fail
 */
int Send_Report(const char*payload);
```

### Send_Report_To
```C
/*
 * @brief:	Send payload data to specified xmpp cloud account with xmpp protocol
 *
 * @Param:	payload	- dataflow to be sent 
 * @Param:	acc		- cloud account
 *
 * @Returns:	0	- on success
 *             -1 - on fail
 */
int Send_Report_To(const char*payload, const char *acc);
```
### Send_Report_CJSON
```C
/*
 * @brief:	Send JSON data to xmpp cloud account with xmpp protocol
 *
 * @Param:	report	- JSON to be sent
 *
 * @Returns:	0	- on success
 *             -1 - on fail
 */
int Send_Report_CJSON(cJSON *report);
```

### Send_Report_CJSON_With_Prefix
```C
/*
 * @brief:	Send Combination of prefix and JSON to xmpp account with xmpp protocol
 *
 * @Param:	report	- JSON to be sent
 * @Param:	prefix	- prefix of JSON
 *
 * @Returns:	0  - on success
 *             -1 - on fail
 */
int Send_Report_CJSON_With_Prefix(cJSON *report, char *prefix);
```
### Send_Report_CJSON_To
```C
/*
 * @brief:	Send JSON data to specified xmpp cloud account with xmpp protocol
 *
 * @Param:	report	- JSON to be sent
 * @Param:	acc	- appointed xmpp account 
 *
 * @Returns:	0	- on success
 *             -1 - on fail
 */
int Send_Report_CJSON_To(cJSON* report, char *acc);
```

### Send_Report_CJSON_With_Prefix_To
```C
/* @brief:	Send Combination of prefix and JSON to specified xmpp account with xmpp protocol
 *
 * @Param:	report	- JSON to be sent
 * @Param:	prefix	- prefix of JSON
 * @Param:	acc	- specified xmpp account  
 *
 * @Returns:	0 - on success
 *             -1 - on fail
 */
int Send_Report_CJSON_With_Prefix_To(cJSON* report, char *prefix, char *acc);
```

## FOR DEBUGGING
### Set_Xmpp_Log_On
```C
/*
 * @brief:	Turn on or off the debugging function of xmpp end
 * @Param:	on - set 1 to enable debug; set 0 to disable dubug
 * 
 */
void Set_Xmpp_Log_On(int on);
```
### Wait_Xmpp_Logon
```C
/*
 * @brief:	Waiting for xmpp account login success. After logging in xmpp account successfully, this interface will return. Or it will be in a blocking state
 * @Param:	on	- set 1 to enable debug;set 0 to disable dubug
 * 
 */
void Wait_Xmpp_Logon();
```
