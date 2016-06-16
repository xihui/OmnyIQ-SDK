/*	An example that you can define your own command */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "DeviceProfileInterface.h"

/* a callback function that parse "cmd" & do actions, such as tun on/of LED */
int on_cmd_test(cJSON *request, cJSON **response)
{
	if (!request)
	{
		return -1;
	}

	//find out the key word "cmd" from json
	cJSON *child = cJSON_GetObjectItem(request, "cmd");
	if (child)
	{
		//"cmd"都是字符串,"cmd"对应的值就是命令
		char *cmd = child->valuestring;
		
		/*the "set-led" command
		 * {
		 *   "cmd":	"set-led"
		 *   "params": {
		 *     "num": 1
		 *     "status": "on"
		 *   }
		 * }
		 */
		if (!strncmp(cmd, "set-led", strlen("set-led")))
		{
			int led_num = 0;
			int led_status = 0;
			
			cJSON *params = cJSON_GetObjectItem(request, "params");
			cJSON *num = cJSON_GetObjectItem(params, "num");
			cJSON *status = cJSON_GetObjectItem(params, "status");

			if (num->type == cJSON_Number && status->type == cJSON_String)
			{
				led_num = num->valueint;
				if (!strncmp(status->valuestring, "on", strlen("on")))
				{
					led_status = 1;
				}
				else
				{
					led_status = 0;
				}
				//TODO: set_led_status(led_num, led_status);
			}
			else
			{
				return -1;
			}
			/* to generate the info that will be returned 
			 * format that as below
			 * {
			 * 	"cmd":	"test",
			 * 	"result":	{
			 * 	"info":	"this is just a test"
			 * 	}
			 * }
			 * */
			cJSON *result = NULL;
			cJSON *res = cJSON_CreateObject();
			cJSON_AddStringToObject(res, "cmd", "test");
			cJSON_AddItemToObject(res, "result", result = cJSON_CreateObject());
			cJSON_AddStringToObject(result, "info", "this is just a test");
			*response = res;
			return 0;
		}
	}
	else
	{
		return -1;
	}
}

/* An example to explain how to use Send_Report_CJSON */
void *thr_fn(void *arg)
{
	pthread_detach(pthread_self());
	while(1)
	{
		sleep(10);
		//Send_Report("Hello world!!!");
		/* or call Send_Report_CJSON if nessesary, you should use the cJSON.h to create the CJSON Object, and free the CJSON object after call the function. Please refer to examples/test_json dir for more about how to use cJSON */
		cJSON *j_root = cJSON_CreateObject();
		//TODO: fill the j_root
		Send_Report_CJSON(j_root);
		cJSON_Delete(j_root);
	}
	return NULL;
}

int main()
{
	/* To get the basic info */
	BasicDeviceInfo DevInfo;
	strcpy(DevInfo.SN, "test-netgear");
	strcpy(DevInfo.Model, "R7000");
	strcpy(DevInfo.MAC, "A1B2C3D4E5F6");
	Device_Init(&DevInfo, "example2", on_cmd_test);
	
	/* To do what you want */
	pthread_t ntid;
	int err = pthread_create(&ntid, NULL, thr_fn, NULL);
	
	/* Go to event loop，block the main thread */
	Device_Run(NULL, 1);

	Device_Destroy();
	return 0;
}