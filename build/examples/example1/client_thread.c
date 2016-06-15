#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "DeviceProfileInterface.h"

/* An example to explain how to use Send_Report */
void *thr_fn(void *arg)
{
	pthread_detach(pthread_self());
	while(1)
	{
		sleep(10);
		Send_Report("Hello World!!!");
	}
	return NULL;
}

int main()
{
	BasicDeviceInfo DevInfo;
	
	/*TODO: to get the basic info, such as Serial number/MAC address/Model of your device  */
	strcpy(DevInfo.SN, "test-netgear");
	strcpy(DevInfo.Model, "R7000");
	strcpy(DevInfo.MAC, "A1B2C3D4E5F6");

	Device_Init(&DevInfo, "example1", NULL);
	
	/* To do what you want here */
	pthread_t ntid;
	int err = pthread_create(&ntid, NULL, thr_fn, NULL);
	
	/* Go to the event loop */
	Device_Run(NULL, 1);

	Device_Destroy();

	return 0;
}