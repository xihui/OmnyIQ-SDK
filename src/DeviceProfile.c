 /**
 * @file DeviceProfile.c
 * @brief  : Implement xmpp server communication
 * @author Lei Dai
 * @version lei.dai
 * @date 2016-01-05
 */
 
/*
 *	Communication procedure: 
 *	//Establish a tcp connection through appointed port with server
 *	//Log in the server with account and password based on tcp connection
 *  - 1. Device_Init						-----------> step 1: Set account，password of the sender，xmpp server address，account of the reciever，and some other information
 *  - 2. Device_Run	(Directly call j_connect)		-----------> step 2: Connect and Communicate with server，Communication procedure is reflected in two step，Initiate connection with server and log in the server
 *     -- 2.1 iks_connect_tcp				-----------> step 2.1 : connect with server
 *     -- 2.2 iks_stream_new				-----------> step 2.2 : log in the server(for the details of login procedure)
 * */


 /*
 *	login procedure: 
 *	//Data which server sent to client will be filtered through j_setup_filter function
 *	- 1. on_stream							-----------> step 1: generate login data package using iks_make_auth，and then send login data package to the server using iks_send
 *	@successful login 
 *	- 2. on_iq_auth_result					-----------> step 2: if data package after filtered is suited to the character of successful login， the package will be sent to the this function
 *	@failed login
 *	- 2. on_iq_auth_error					-----------> step 2: if data package after filtered is suited to the character of failed login， the package will be sent to the this function
 *   
	The account which is enter on_iq_auth_error function will be thought as unregistered account， and it will be enter the register procedure in this function
 *																 (详见注册流程)
 */
 

 /*
 * register procedure
 * //after register successfully， it will initiate login procedure again
 * - two steps in register:
 * - 1. iks_make_reg1						-----------> step 1: generate data-1 registered package using this function，and then send it to the server. The purpose of this data-1 package is asking for register format from server
 *   														
	register format returned from server will be handled inon_iq_result_reg1
 * - 2. iks_make_reg2						-----------> step 2: generate data-2 registered package using this function，and then send it to the server. The purpose of this data-2 package is registered normally from server
 *   															 
 register format returned from server will be handled inon_iq_result_reg2
 * */
 
 
 
 /*
 * Chat mechanism(information interaction)
 * //after log in successfully，it will receive some message similar to QQ chat message. you can see on_msg function to get handle procedure
 * mainly handle two format Chat message
 * @prefix of message with “cmd:”，the remain part will be regarded as linux command to be handled， and it will return result
 * @message of JSON format，user defined，its handle method is also defined by userself
 *    basic format of JSON：
 *    {
 *		"cmd" : "xxx",
 *		"params" : {						-----------> the content of params struct can be defined by user 
 *			"para" : "jjj"
 *		}
 *    }
 * */
 

#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include "iksemel.h"
#include "cJSON.h"
#include "DeviceProfileInterface.h"

#include "Debug.h"


/*
 * Macro definition
 */
/* Xmpp Sever Address */
#define SERVER_ADDR "xmpp.siteview.com"
//#define SERVER_ADDR "192.168.0.2"
/* Xmpp Sever port*/
#define SERVER_PORT (5222)

#define MAX_USER_LEN (100)
#define MAX_USER_FULL_LEN (201)
#define MAX_PASSWD_LEN (100)
#define MAX_SERVER_LEN (100)

/* 
 * Struct definition 
 */
struct session {
        iksparser *prs;
        iksid *acc;
        char *pass;
        int features;
        int authorized;
        int counter;
        int set_roster;
        int job_done;
		int logged;
};


struct connect_info_s
{
	char user_full[MAX_USER_FULL_LEN];
	char user[MAX_USER_LEN];			//the username
	char passwd[MAX_PASSWD_LEN];		//the passwd for the user
	char server[MAX_SERVER_LEN];		//the server name
	char remote_first_user[MAX_SERVER_LEN];		//the first user to talk to when router finish initing
	char remote_admin_user[MAX_SERVER_LEN];		//the admin user to talk to when router finish initing
	int  port;							//the server port
};

/* 
 * Global variable
 */
pthread_mutex_t g_sess_lock;
/* the global session */
struct session sess;
/* the global connect info */
struct connect_info_s g_connect_info;
/* the first user that the router talk to when finishing init */
struct connect_info_s g_connect_info;
/* the global basic device info */
BasicDeviceInfo g_dev_info;
/* global callbak function */
ON_CMD_FUNC g_cmd_func;
/* precious roster we'll deal with */
iks *my_roster;
/* out packet filter */
iksfilter *my_filter;
/* connection time outs if nothing comes for this much seconds */
int opt_timeout = 30;
/* connection flags */
int opt_use_tls;
int opt_use_sasl;
int opt_use_plain;
int opt_log=0;

#define MAX_NO_RES_CNT (4)
/* using this global variable to record the counts to ping server. If the count is more than the specified count， we will regard that xmpp client is offline. It will disconnect actively and login again. */
int ping_no_res_cnt = 0;


/* 
 * Realization of function
 */

iks *
iks_make_reg1 ()
{
	iks *x, *y;

	x = iks_new("iq");
	iks_insert_attrib (x, "type", "get");
	iks_insert_attrib (x, "id", "reg1");
	y = iks_insert(x, "query");
	iks_insert_attrib (y, "xmlns", "jabber:iq:register");
	return x;
}

iks *
iks_make_reg2 (const char *user, const char *passwd)
{
	if (!(user && passwd))
	{
		return NULL;
	}
	iks *x, *y;
	x = iks_new("iq");
	iks_insert_attrib (x, "type", "set");
	iks_insert_attrib (x, "id", "reg2");
	y = iks_insert(x, "query");
	iks_insert_attrib (x, "xmlns", "jabber:iq:register");
	iks_insert_cdata (iks_insert (y, "username"), user, 0); 
	iks_insert_cdata (iks_insert (y, "password"), passwd, 0); 
	return x;
}

iks *
iks_make_ping(void)                                                                                                                                                                                                                          
{   
	iks *x, *y;
	x = iks_new("iq");
	iks_insert_attrib(x, "id", "ping");
	iks_insert_attrib(x, "type", "get");

	y = iks_insert (x, "ping");
	iks_insert_attrib(y, "xmlns", "urn:xmpp:ping");
	return x;
}

iks *
iks_make_ping_result(char *id, char *from, char *to)
{
	iks *x, *y; 

	x = iks_new("iq");
	iks_insert_attrib (x, "type", "result");
	iks_insert_attrib (x, "id", id);
	iks_insert_attrib (x, "from", from);
	iks_insert_attrib (x, "to", to);
	return x;
}

void Set_Xmpp_Log_On(int on)
{
	if (on)
	{
		opt_log = 1;
	}
}

int Xmpp_Has_TLS()
{
	return iks_has_tls();
}

void Enable_Xmpp_TLS()
{
	opt_use_tls = 1;
}

void
j_error (char *msg)
{
        //fprintf (stderr, "iksroster: %s\n", msg); 
		DEBUG_INFO("%s", msg);
}

int
on_iq_result(struct session *sess, ikspak *pak)
{
	iks *x;
	iks *child;
	x = pak->x;

	char *id = iks_find_attrib(x, "id");
	if (!strncmp(id, "ping", strlen("ping")))
	{
		//printf("Get a ping result\n");
		ping_no_res_cnt = 0;
	}
	return IKS_FILTER_EAT;
}

//收到PING包的处理
int
on_iq_get(struct session *sess, ikspak *pak)
{
	iks *x;
	iks *child;
	x = pak->x;
	child=iks_child(x);

	if (child)
	{
		if (strcmp(iks_name(child), "ping") == 0)
		{
			iks *ret = NULL;
			char *id = iks_find_attrib(x, "id");
			//returned package needs to be reverse the position between from and to
			char *to = iks_find_attrib(x, "from");
			char *from = iks_find_attrib(x, "to");
			ret = iks_make_ping_result(id, from, to);
			iks_send (sess->prs, ret);
			iks_delete (ret);
		}
	}
	return IKS_FILTER_EAT;
}

//log in successfully

/**
 * @brief  :
 *
 * @Param  :sess
 * @Param  :pak
 *
 * @Returns  :
 */
int
on_iq_auth_result (struct session *sess, ikspak *pak)
{
	iks *x;
	iks *pre;
	iks *y;
	//Set online
	//iks_make_pres (enum ikshowtype show, const char *status)  //char *t(chat,away,xa,dnd,null)
	//  char *status
	DEBUG_INFO("Logon successed\n");
	pre=iks_make_pres (IKS_SHOW_CHAT, "online") ;
	iks_send (sess->prs, pre);
	iks_delete (pre);
	y=iks_make_session();
	iks_send (sess->prs, y);
	iks_delete (y);
	if (sess->set_roster == 0) {
			x = iks_make_iq (IKS_TYPE_GET, IKS_NS_ROSTER);
			iks_insert_attrib (x, "id", "roster");
			iks_send (sess->prs, x);
			iks_delete (x);
	} else {
			iks_insert_attrib (my_roster, "type", "set");
			iks_send (sess->prs, my_roster);
	}

	//temperately set manage account as initial manage account ， load balancing will be achived in the future, it can be modified in this area
	strcpy(g_connect_info.remote_admin_user, g_connect_info.remote_first_user);
	//report the basic device info to administrator
	iks *msg = iks_make_msg(IKS_TYPE_CHAT,g_connect_info.remote_first_user, NULL);
	//iks *msg = iks_make_msg(IKS_TYPE_CHAT,g_connect_info.remote_first_user, NULL);
	iks_insert_attrib(msg, "id", "msglai");  /// iks *iks_insert_attrib (iks *x, const char *name, const char *value);
	iks *body = iks_insert(msg, "body");
	iks_insert_attrib(body, "type", "report");
	/* Our "gallery" item: */
	cJSON *root=cJSON_CreateObject();
	cJSON *devinfo = cJSON_CreateObject();
	cJSON_AddItemToObject(root, "Device-Info",devinfo); 
	cJSON_AddStringToObject(devinfo, "SN", g_dev_info.SN);
	cJSON_AddStringToObject(devinfo, "Model", g_dev_info.Model);
	cJSON_AddStringToObject(devinfo, "MAC", g_dev_info.MAC);
	cJSON_AddStringToObject(devinfo, "Country", g_dev_info.Country);
	cJSON_AddStringToObject(devinfo, "Location", g_dev_info.Location);

	char *out=cJSON_Print(root);  cJSON_Delete(root); 
	iks_insert_cdata(body, out, 0);
	iks_send(sess->prs, msg);
	iks_delete(msg);
	free(out);
	sess->logged = 1;
	return IKS_FILTER_EAT;
}


/**
 * @brief  :
 *
 * @Param  :sess
 * @Param  :type
 * @Param  :node
 *
 * @Returns  :
 */
int
on_stream (struct session *sess, int type, iks *node)
{
        sess->counter = opt_timeout;
        switch (type) {
                case IKS_NODE_START:
                        if (opt_use_tls && !iks_is_secure (sess->prs)) {
                                iks_start_tls (sess->prs);
                                break;
                        }
                        if (!opt_use_sasl) {
                                iks *x;
                                char *sid = NULL;
                                if (!opt_use_plain) sid = iks_find_attrib (node, "id");
                                x = iks_make_auth (sess->acc, sess->pass, sid);
                                iks_insert_attrib (x, "id", "auth");
                                //
                                //iks_insert_attrib (x, "mechanism","PLAIN");
                                //iks_insert_attrib(x,"ga:client-uses-full-bind-result","true");
                                //
                                iks_send (sess->prs, x);
                                iks_delete (x);
                        }
                        break;
                case IKS_NODE_NORMAL:
                        if (strcmp ("stream:features", iks_name (node)) == 0) {
                                sess->features = iks_stream_features (node);
                                if (opt_use_sasl) {
                                        if (opt_use_tls && !iks_is_secure (sess->prs)) break;
                                        if (sess->authorized) {
                                                iks *t;
                                                if (sess->features & IKS_STREAM_BIND) {
                                                        t = iks_make_resource_bind (sess->acc);
                                                        iks_send (sess->prs, t);
                                                        iks_delete (t);
                                                }
                                                if (sess->features & IKS_STREAM_SESSION) {
                                                        t = iks_make_session ();
                                                        iks_insert_attrib (t, "id", "auth");
                                                        iks_send (sess->prs, t);
                                                        iks_delete (t);
                                                }
                                        } else {
                                                if (sess->features & IKS_STREAM_SASL_MD5)
                                                        iks_start_sasl (sess->prs, IKS_SASL_DIGEST_MD5, sess->acc->user, sess->pass);
                                                else if (sess->features & IKS_STREAM_SASL_PLAIN)
                                                        iks_start_sasl (sess->prs, IKS_SASL_PLAIN, sess->acc->user, sess->pass);
                                        }
                                }
                        } else if (strcmp ("failure", iks_name (node)) == 0) {
                                j_error ("sasl authentication failed");
                        } else if (strcmp ("success", iks_name (node)) == 0) {
                                sess->authorized = 1;
                                iks_send_header (sess->prs, sess->acc->server);
                        } else {
                                ikspak *pak;
                                pak = iks_packet (node);
                                iks_filter_packet (my_filter, pak);
                                if (sess->job_done == 1) return IKS_HOOK;
                        }
                        break;
                case IKS_NODE_STOP:
                        j_error ("server disconnected");
                case IKS_NODE_ERROR:
                        j_error ("stream error");
        }
        if (node) iks_delete (node);
        return IKS_OK;
}

//failed login

/**
 * @brief  :
 *
 * @Param  :sess
 * @Param  :pak
 *
 * @Returns  :
 */
int
on_iq_auth_error (struct session *sess, ikspak *pak)
{
	//login failed, may be caused by unregister， and to do register. three steps in register procedure：
	//reg1: acquire registry keys, i.e. register format required by server
	//reg2: fill in register table, and send to server
	//reg3: client can choose to improve user register information, and acquire the detailed tables throungh sending reg3

	//implement reg1
	iks *x = iks_make_reg1();

	iks_send(sess->prs, x);

	iks_delete(x);
	return IKS_FILTER_EAT;
}

//Acquire registry successfully

/**
 * @brief  :
 *
 * @Param  :sess
 * @Param  :pak
 *
 * @Returns  :
 */
int
on_iq_reg1_result (struct session *sess, ikspak *pak)
{
	//the second step to implement register
	iks *x = iks_make_reg2(sess->acc->user, sess->pass);

	iks_send(sess->prs, x);

	iks_delete(x);
	return IKS_FILTER_EAT;
}

//register successfully

/**
 * @brief  :
 *
 * @Param  :sess
 * @Param  :pak
 *
 * @Returns  :
 */
int
on_iq_reg2_result (struct session *sess, ikspak *pak)
{
	//implement login procedure after register successfully
	//printf("Start logon when finish registering\n");
	//printf("[USER]:%s\n", sess->acc->user);
	//printf("[PASSWD]:%s\n", sess->pass);
	iks *x = iks_make_auth(sess->acc, sess->pass, NULL);
	iks_insert_attrib (x, "id", "auth");

	iks_send(sess->prs, x);

	iks_delete(x);
	return IKS_FILTER_EAT;
}

//register failed

/**
 * @brief  :
 *
 * @Param  :sess
 * @Param  :pak
 *
 * @Returns  :
 */
int
on_iq_reg2_error (struct session *sess, ikspak *pak)
{
	//register failed and print failed error
	iks *x;
	iks *child;
	x = pak->x;
    child=iks_child(x);
    child=iks_next(child);

	DEBUG_INFO("%s", iks_find_attrib(child, "code"));
	//fprintf (stderr, "[reg2][error:%s]\n", error_code);
	return IKS_FILTER_EAT;
}


/**
 * @brief  :
 *
 * @Param  :sess
 * @Param  :pak
 *
 * @Returns  :
 */
int
on_roster (struct session *sess, ikspak *pak)  //After acquire roster, it will send hello message to one of them

{
	iks *child;
	my_roster = pak->x;
	//sess->job_done = 1;
	//return IKS_FILTER_EAT;
	//find a linkman
    child=iks_child(my_roster);
    child=iks_child(child);
    child=iks_next(child);
    char *jid=iks_find_attrib(child,"jid"); //one of roster user
    
	if (jid)
	{
        /* send hello message to this linkman */
    	iks *msg=iks_make_msg(IKS_TYPE_CHAT,jid,"hello,test msg!");
    	iks_insert_attrib (msg, "id", "msglai"); 
    	iks_send (sess->prs, msg);
    	iks_delete (msg);
	}
    return IKS_FILTER_EAT;
}

//sdk can handle default command with JSON format. Currently it is relative with set-remote-admin command of future load balancing.
/**
 * @brief  :
 *
 * @Param  :request
 * @Param  :response
 *
 * @Returns  :
 */
int on_default_func(cJSON *request, cJSON **response)
{
	if (!request)
	{
		return -1;
	}
	cJSON *child = cJSON_GetObjectItem(request, "dft-cmd");
	if (child)
	{
		char *cmd = child->valuestring;
		if (!strncmp(cmd, "set-remote-admin", strlen("set-remote-admin")))
		{
			cJSON *params = cJSON_GetObjectItem(request, "params");
			if (params)
			{
				cJSON *user = cJSON_GetObjectItem(params, "user");
				if (user)
				{
					strcpy(g_connect_info.remote_admin_user, user->valuestring);
					return 0;
				}
			}
		}
	}
	return -1;
}



#if 1
#define TMP_RESULT_FILE "/tmp/cmd_result.txt"
#define MIN(x, y) ((x)<(y)?(x):(y))
long get_file_size(FILE *file)
{
	long filesize = 0;
	fseek(file, 0, SEEK_END);
	filesize = ftell(file);
	rewind(file);
	return filesize;
}

int do_cmd(char *cmd, char *output, long output_len)
{
	int ret;
	long file_size;
	int prefix_len = 0;
	FILE *res_file;
	char cmd_buf[400] = "";
	sprintf(cmd_buf, "%s >"TMP_RESULT_FILE, cmd);
	//self-checking with file system before implement reboot command
	if (strncmp(cmd, "reboot", strlen("reboot")) == 0)
	{
		int self_check_result = system("ls /bin/cp");
		if (self_check_result < 0)
		{
			strncpy(output, "cmd:-1:", strlen("cmd:-1:") + 1);
		}
		else
		{
			strncpy(output, "cmd:0:", strlen("cmd:0:") + 1);
		}
		return self_check_result;
	}
	ret = system(cmd_buf);
	sprintf(output, "cmd:%d:", ret);
	prefix_len = strlen(output);
	output_len -= (prefix_len + 1);
	res_file = fopen(TMP_RESULT_FILE, "r");
	if (res_file)
	{
		file_size = get_file_size(res_file);
		if (file_size > 0)
		{
			file_size = MIN(file_size, output_len);
			fread(output + prefix_len, file_size, 1, res_file);
		}
		fclose(res_file);
	}
	return ret;
}
#endif

#define MAX_RESULT_BLOCK_LEN (20000)

//implement received broadcast message
//broadcast message is regarded as command to be handled，because of it not needing response of client
int
on_broadcast(struct session *sess, ikspak *pak) 
{
	/* 判断ikspak 的类型 */
	if(pak->type==IKS_PAK_MESSAGE)
	{
		DEBUG_INFO("Get Broadcast\n");
		iks *x = pak->x;
		char *payload = iks_find_cdata(x, "body");
		if (payload)
		{
			DEBUG_INFO("Body:%s\n", payload);
			system(payload);
		}
	}
	return IKS_FILTER_EAT;
}

//handle received chat message 
/**
 * @brief  :
 *
 * @Param  :sess
 * @Param  :pak
 *
 * @Returns  :
 */
int
on_msg (struct session *sess, ikspak *pak) 
{
	//judge types of ikspak
	if(pak->type==IKS_PAK_MESSAGE)
	{
		if(pak->subtype==IKS_TYPE_CHAT)
		{   
			iks *x = pak->x;
			char *id = iks_find_attrib(x, "id");
			char *payload = iks_find_cdata(x, "body");
			if (payload)
			{
				
				 //1. firstly judge whether or not it's shell command 

				//simply judge whether or not that first four bytes of content is "cmd:" . if it is, it can be shell command. After implement command， returns the result
				//Attention：do not send the command which can not be quited, i.e. ping -c or top -n
				if (!strncmp(payload, "cmd:", strlen("cmd:")))
				{
					char *cmd_content = payload + strlen("cmd:");
					char cmd_res[MAX_RESULT_BLOCK_LEN];
					memset(cmd_res, 0, MAX_RESULT_BLOCK_LEN);
					int ret = do_cmd(cmd_content, cmd_res, MAX_RESULT_BLOCK_LEN);

					iks *body;
					//generate structs of message
					iks *msg=iks_make_msg(IKS_TYPE_CHAT,pak->from->full,NULL);
					//add id ness neccessary, or receiver can not be received
					if (id)
					{
						iks_insert_attrib(msg, "id", id);
					}
					else
					{
						iks_insert_attrib(msg, "id", "msglai");
					}
					/* add message body */
					
					body = iks_insert(msg, "body");
					iks_insert_cdata(body, cmd_res, 0);
					iks_send(sess->prs, msg);
					iks_delete (msg);

					//postpone the reboot command
					if (strncmp(cmd_content, "reboot", strlen("reboot")) ==0 && ret == 0)
					{
						system("reboot");
					}
					return IKS_FILTER_EAT;
				}

				/* 
				 * 2 To judge whether or nor it is JSON format command
				 */
				/* parse JSON root node */
				cJSON *json_root = cJSON_Parse(payload);
				cJSON *response = NULL;
				char *str_resp = NULL;
				int ret;
				if (json_root)
				{
					/* handle internal command priorly */
					if (on_default_func(json_root, &response) >= 0)
					{
						;
					}
					/* second handle command from Device_Init  */
					else if (g_cmd_func)
					{
						ret = g_cmd_func(json_root, &response);
					}
					/* handle command if there is returned result */
					if (response)
					{
						str_resp = cJSON_Print(response);
						if (str_resp)
						{
							iks *body;
							/* generate struct of message*/
							iks *msg=iks_make_msg(IKS_TYPE_CHAT,pak->from->full,NULL);
							if (id)
							{
								iks_insert_attrib(msg, "id", id);
							}
							else
							{
								iks_insert_attrib(msg, "id", "msglai");
							}
							/* add message body */
							body = iks_insert(msg, "body");
							if (body)
							{
								iks_insert_cdata(body, str_resp, 0);
							}
							else
							{
								fprintf(stderr, "can't find body\n");
							}
							iks_send (sess->prs, msg);
							iks_delete (msg);
							free(str_resp);
						}
						else
						{
							;
						}
						cJSON_Delete(response);
					}
					cJSON_Delete(json_root);
				}
			}
		}
	}
    return IKS_FILTER_EAT;
}


//handle the received online message
/**
 * @brief  :
 *
 * @Param  :sess
 * @Param  :pak
 *
 * @Returns  :
 */
int 
on_presence(struct session *sess, ikspak *pak)
{
    iks *pre=iks_make_s10n(IKS_TYPE_SUBSCRIBED,pak->from->full,"hello, master");
    //iks_insert_attrib (pre, "id", "msglai");  /// iks *iks_insert_attrib (iks *x, const char *name, const char *value);
    iks_send (sess->prs, pre);
    iks_delete (pre);
    return IKS_FILTER_EAT;
}

//debug message from communicated server
/**
 * @brief  :
 *
 * @Param  :sess
 * @Param  :data
 * @Param  :size
 * @Param  :is_incoming
 */
void
on_log (struct session *sess, const char *data, size_t size, int is_incoming)
{
        if (iks_is_secure (sess->prs)) fprintf (stderr, "Sec");
        if (is_incoming) fprintf (stderr, "RECV"); else fprintf (stderr, "SEND");
        fprintf (stderr, "[%s]\n", data);
}

//the most important procedure in communication with server, set the filter. when iks_recv received the data package from server, it will follow the filter settings to check the data package.
/**
 * @brief  :
 *
 * @Param  :sess
 */
void
j_setup_filter (struct session *sess)
{
        if (my_filter) iks_filter_delete (my_filter);
        my_filter = iks_filter_new ();
		/* return if received ping  */
		iks_filter_add_rule (my_filter, (iksFilterHook *) on_iq_result, sess,
                IKS_RULE_TYPE, IKS_PAK_IQ,
                IKS_RULE_SUBTYPE, IKS_TYPE_RESULT,
                IKS_RULE_ID, "ping",
                IKS_RULE_DONE);
		/* handle received ping package */
		iks_filter_add_rule (my_filter, (iksFilterHook *) on_iq_get, sess,
                IKS_RULE_TYPE, IKS_PAK_IQ,
                IKS_RULE_SUBTYPE, IKS_TYPE_GET,
                IKS_RULE_DONE);
        iks_filter_add_rule (my_filter, (iksFilterHook *) on_iq_auth_result, sess,
                IKS_RULE_TYPE, IKS_PAK_IQ,
                IKS_RULE_SUBTYPE, IKS_TYPE_RESULT,
                IKS_RULE_ID, "auth",
                IKS_RULE_DONE);
        iks_filter_add_rule (my_filter, (iksFilterHook *)on_iq_auth_error, sess,
                IKS_RULE_TYPE, IKS_PAK_IQ,
                IKS_RULE_SUBTYPE, IKS_TYPE_ERROR,
                IKS_RULE_ID, "auth",
                IKS_RULE_DONE);
		iks_filter_add_rule (my_filter, (iksFilterHook *) on_iq_reg1_result, sess,
                IKS_RULE_TYPE, IKS_PAK_IQ,
                IKS_RULE_SUBTYPE, IKS_TYPE_RESULT,
                IKS_RULE_ID, "reg1",
                IKS_RULE_DONE);
        iks_filter_add_rule (my_filter, (iksFilterHook *)on_iq_reg2_result, sess,
                IKS_RULE_TYPE, IKS_PAK_IQ,
                IKS_RULE_SUBTYPE, IKS_TYPE_RESULT,
                IKS_RULE_ID, "reg2",
                IKS_RULE_DONE);
        iks_filter_add_rule (my_filter, (iksFilterHook *)on_iq_reg2_error, sess,
                IKS_RULE_TYPE, IKS_PAK_IQ,
                IKS_RULE_SUBTYPE, IKS_TYPE_ERROR,
                IKS_RULE_ID, "reg2",
                IKS_RULE_DONE);

        iks_filter_add_rule (my_filter, (iksFilterHook *) on_roster, sess,
                IKS_RULE_TYPE, IKS_PAK_IQ,
                IKS_RULE_SUBTYPE, IKS_TYPE_RESULT,
                IKS_RULE_ID, "roster",
                IKS_RULE_DONE);
		iks_filter_add_rule (my_filter, (iksFilterHook *) on_msg, sess,  //when returns，lailaigq@gmail.com/auth" id="roster" type="result">  implement。
                IKS_RULE_TYPE, IKS_PAK_MESSAGE,
                IKS_RULE_SUBTYPE, IKS_TYPE_CHAT,
                //IKS_RULE_FROM_PARTIAL, "dailei@xmpp.siteview.com",
                //IKS_RULE_FROM_PARTIAL, "guanquan.lai@gmail.com",
                IKS_RULE_DONE);
		iks_filter_add_rule (my_filter, (iksFilterHook *) on_broadcast, sess,  //when returns，lailaigq@gmail.com/auth" id="roster" type="result">  implement。
                IKS_RULE_TYPE, IKS_PAK_MESSAGE,
                //IKS_RULE_SUBTYPE, IKS_TYPE_CHAT, /* cancle the limit of type="cgat" in order to receive broadcast */
                IKS_RULE_FROM, SERVER_ADDR,	/* message from server */
                //IKS_RULE_FROM_PARTIAL, "guanquan.lai@gmail.com",
                IKS_RULE_DONE);
        // when accept the request to be friends from presence 
 //zbwgy718823@gmail.com" to="lailaigq@gmail.com"> xmlns:sub="google:subscribe">
		iks_filter_add_rule (my_filter, (iksFilterHook *) on_presence, sess,  //when returns，lailaigq@gmail.com/auth" id="roster" type="result">  implement。
                IKS_RULE_TYPE, IKS_PAK_PRESENCE,
                IKS_RULE_SUBTYPE, IKS_TYPE_SUBSCRIBE,
                //IKS_RULE_FROM_PARTIAL, "zbwgy718823@gmail.com",
                IKS_RULE_DONE);
}

//connect with server
/**
 * @brief  :
 *
 * @Param  :jabber_id
 * @Param  :pass
 * @Param  :server
 * @Param  :port
 * @Param  :set_roster
 * @Param  :loop_fun
 * @Param  :loop_tv
 */
void
j_connect (char *jabber_id, char *pass, char *server, int port, int set_roster, char* (*loop_fun)(), int loop_tv)
{
	int e;
	memset (&sess, 0, sizeof (sess));
	sess.prs = iks_stream_new (IKS_NS_CLIENT, &sess, (iksStreamHook *) on_stream);
	if (opt_log) iks_set_log_hook (sess.prs, (iksLogHook *) on_log);
	sess.acc = iks_id_new (iks_parser_stack (sess.prs), jabber_id);
	if (NULL == sess.acc->resource) {
			/* user gave no resource name, use the default */
			char *tmp;
			tmp = iks_malloc (strlen (sess.acc->user) + strlen (sess.acc->server) + 9 + 3);
			sprintf (tmp, "%s@%s/%s", sess.acc->user, sess.acc->server, "iksroster");
			sess.acc = iks_id_new (iks_parser_stack (sess.prs), tmp);
			iks_free (tmp);
	}
	sess.pass = pass;
	sess.set_roster = set_roster;
	j_setup_filter (&sess);
	if (!port)
	{
		port = IKS_JABBER_PORT;
	}
#if 1
	e = iks_connect_tcp (sess.prs, server, port);
#else
	e = iks_connect_via (sess.prs, "192.68.0.2", port, server);
#endif
	switch (e) {
			case IKS_OK:
					break;
			case IKS_NET_NODNS:
					j_error ("hostname lookup failed");
					return;
			case IKS_NET_NOCONN:
					j_error ("connection failed");
					return;
			default:
					j_error ("io error");
					return;
	}
	sess.counter = opt_timeout;
	while (1) {
			pthread_mutex_lock(&g_sess_lock);
			e = iks_recv (sess.prs, 1);
			pthread_mutex_unlock(&g_sess_lock);
			//printf("[e] = %d\n", e);
			if (IKS_HOOK == e) break;
			if (IKS_NET_TLSFAIL == e)
			{	
				j_error ("tls handshake failed");
				break;
			}
			if (IKS_OK != e)
			{
				j_error ("io error");
				break;
			}
			sess.counter--;
#if 1
			if (sess.counter <= 0) 
			{
				j_error ("network timeout");
				//if connect to server with ping of MAX_NO_RES_CNT times, we thought that the client is offline. Quit the function and wait for the next connect
				if (ping_no_res_cnt++ >= MAX_NO_RES_CNT)
				{
					j_error ("need restart xmpp");
					ping_no_res_cnt = 0;
					break;
				}
				iks *x = iks_make_ping();
				iks_send(sess.prs, x);
				iks_delete(x);
				sess.counter = opt_timeout;
			}
#endif

			if (sess.logged)
			{
				if (loop_fun)
				{
					sleep(loop_tv);
					char *payload = loop_fun();
					Send_Report(payload);
					free(payload);	
				}
			}
	}
	sess.logged = 0;
	sess.authorized = 0;
	iks_parser_delete (sess.prs);
}

//wait for client to be online, referenced to exmaple
/**
 * @brief  :
 */
void Wait_Xmpp_Logon()
{
	while(!sess.logged)
	{
		sleep(3);
	}
}

#if 1
//report message to the default receiver
/**
 * @brief  :
 *
 * @Param  :report
 *
 * @Returns  :
 */
int Send_Report(const char* report)
{	
	char *acc = g_connect_info.remote_admin_user;
	if ((!report) || (!acc[0]) || (!sess.logged))
	{
		return -1;
	}

	iks *msg=iks_make_msg(IKS_TYPE_CHAT,acc,report);
	iks_insert_attrib(msg, "id", "msgreport");

	pthread_mutex_lock(&g_sess_lock);
	iks_send (sess.prs, msg);
	pthread_mutex_unlock(&g_sess_lock);
	iks_delete(msg);
	return 0;
}

//report message to the appointed receiver
int Send_Report_To(const char* report, const char *acc)
{	
	if ((!report) || (!acc) || (!acc[0]) || (!sess.logged))
	{
		return -1;
	}

	iks *msg=iks_make_msg(IKS_TYPE_CHAT,acc,report);
	iks_insert_attrib(msg, "id", "msgreport");  /// iks *iks_insert_attrib (iks *x, const char *name, const char *value);

	pthread_mutex_lock(&g_sess_lock);
	iks_send (sess.prs, msg);
	pthread_mutex_unlock(&g_sess_lock);
	iks_delete(msg);
	return 0;
}

//report JSON message to the receiver
int Send_Report_CJSON_With_Prefix(cJSON* report, char *prefix)
{
	char *send_buf = NULL;
	char *acc = g_connect_info.remote_admin_user;
	if ((!report) || (!acc[0]) || (!sess.logged))
	{
		return -1;
	}

	char *payload = cJSON_Print(report);
	if (!payload)
	{
		return -1;
	}

	send_buf = malloc(strlen(prefix) + strlen(payload) + 10);
	strcpy(send_buf, prefix);
	strcat(send_buf, payload);

	iks *msg=iks_make_msg(IKS_TYPE_CHAT,acc,NULL);
	iks_insert_attrib(msg, "id", "msgreport");  /// iks *iks_insert_attrib (iks *x, const char *name, const char *value);

	iks *body = iks_insert(msg, "body");

	iks_insert_cdata(body, send_buf, 0);

	pthread_mutex_lock(&g_sess_lock);
	iks_send (sess.prs, msg);
	pthread_mutex_unlock(&g_sess_lock);
	iks_delete(msg);
	free(payload);
	free(send_buf);

	return 0;
}

//report JSON message to the receiver
int Send_Report_CJSON(cJSON* report)
{
	char *acc = g_connect_info.remote_admin_user;
	if ((!report) || (!acc[0]) || (!sess.logged))
	{
		return -1;
	}

	char *payload = cJSON_Print(report);
	if (!payload)
	{
		return -1;
	}

	iks *msg=iks_make_msg(IKS_TYPE_CHAT,acc,NULL);
	iks_insert_attrib(msg, "id", "msgreport");  /// iks *iks_insert_attrib (iks *x, const char *name, const char *value);

	iks *body = iks_insert(msg, "body");

	iks_insert_cdata(body, payload, 0);

	pthread_mutex_lock(&g_sess_lock);
	iks_send (sess.prs, msg);
	pthread_mutex_unlock(&g_sess_lock);
	iks_delete(msg);
	free(payload);

	return 0;
}

//report JSON message to the receiver
int Send_Report_CJSON_With_Prefix_To(cJSON* report, char *prefix, char *acc)
{
	char *send_buf = NULL;
	if ((!report) || (!acc) || (!acc[0]) || (!sess.logged))
	{
		return -1;
	}

	char *payload = cJSON_Print(report);
	if (!payload)
	{
		return -1;
	}

	send_buf = malloc(strlen(prefix) + strlen(payload) + 10);
	strcpy(send_buf, prefix);
	strcat(send_buf, payload);

	iks *msg=iks_make_msg(IKS_TYPE_CHAT,acc,NULL);
	iks_insert_attrib(msg, "id", "msgreport");  /// iks *iks_insert_attrib (iks *x, const char *name, const char *value);

	iks *body = iks_insert(msg, "body");

	iks_insert_cdata(body, send_buf, 0);

	pthread_mutex_lock(&g_sess_lock);
	iks_send (sess.prs, msg);
	pthread_mutex_unlock(&g_sess_lock);
	iks_delete(msg);
	free(payload);
	free(send_buf);

	return 0;
}

//report JSON message to the receiver
int Send_Report_CJSON_To(cJSON* report, char *acc)
{
	if ((!report) || (!acc) || (!acc[0]) || (!sess.logged))
	{
		return -1;
	}

	char *payload = cJSON_Print(report);
	if (!payload)
	{
		return -1;
	}

	iks *msg=iks_make_msg(IKS_TYPE_CHAT,acc,NULL);
	iks_insert_attrib(msg, "id", "msgreport");  /// iks *iks_insert_attrib (iks *x, const char *name, const char *value);

	iks *body = iks_insert(msg, "body");

	iks_insert_cdata(body, payload, 0);

	pthread_mutex_lock(&g_sess_lock);
	iks_send (sess.prs, msg);
	pthread_mutex_unlock(&g_sess_lock);
	iks_delete(msg);
	free(payload);

	return 0;
}
#endif



// initialize the device information. we need SN(used to generate client account), receiver manage account(used to report the message) in DeviInfo. other information can be filled in non-null value. attention that exceed length of arrays
//on_cmd_func is used to handle user-defined JSON command. referenced to Device_Init in demo
/**
 * @brief  :
 *
 * @Param  :DevInfo
 * @Param  :admin_acc
 * @Param  :on_cmd_func
 *
 * @Returns  :
 */
int Device_Init(struct BasicDeviceInfo_s *DevInfo, const char*admin_acc, ON_CMD_FUNC on_cmd_func)
{
	memcpy((void *)&g_dev_info, (const void*)DevInfo, sizeof(BasicDeviceInfo));
	g_cmd_func = on_cmd_func;
	if (DevInfo && admin_acc)
	{
		/* generate username with SN*/
		memcpy(&g_dev_info, DevInfo, sizeof(*DevInfo));
		strncpy(g_connect_info.user, DevInfo->SN, sizeof(DevInfo->SN));
		strcpy(g_connect_info.server, SERVER_ADDR);
		/* save manage account */
		strcpy(g_connect_info.remote_first_user, admin_acc);
		strcat(g_connect_info.remote_first_user, "@");
		strcat(g_connect_info.remote_first_user, SERVER_ADDR);
		/* use siteview and SN number to generate password */
		strcpy(g_connect_info.passwd, "siteview");
		strcat(g_connect_info.passwd, DevInfo->SN);
		/* generate full name of username. username@server */
		strcpy(g_connect_info.user_full, g_connect_info.user);
		strcat(g_connect_info.user_full, "@");
		strcat(g_connect_info.user_full, SERVER_ADDR);
		g_connect_info.port = SERVER_PORT;
		pthread_mutex_init(&g_sess_lock, NULL);
		return 0;
	}
	else
	{
		return -1;
	}
}



//connect from client to server
/**
 * @brief  :
 *
 * @Param  :loop_fun
 * @Param  :loop_tv
 *
 * @Returns  :
 */
int Device_Run(char* (*loop_fun)(), int loop_tv)
{
	while(1)
	{
		j_connect (g_connect_info.user_full, g_connect_info.passwd, g_connect_info.server, g_connect_info.port, 0, loop_fun, loop_tv);
		//if errors occurred, sleep ten seconds and then connect again.
		sleep(10);
	}
}

/**
 * @brief  :
 */
void Device_Destroy()
{
	//cmd_table_destroy();
}
