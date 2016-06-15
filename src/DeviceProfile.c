/**
 * @file DeviceProfile.c
 * @brief  : 实现与xmpp服务器的通信
 * @author Lei Dai
 * @version lei.dai
 * @date 2016-01-05
 */

/*
 *	通信流程: 
 *	//连接服务器只建立服务器指定端口的tcp连接
 *	//登录服务器在tcp连接的基础上采用帐号+密码的验证方式登录
 *  - 1. Device_Init						-----------> step 1: 设置帐号，密码，服务器地址，对端帐号等信息
 *  - 2. Device_Run	(直接调用j_connect)		-----------> step 2: 与服务器进行连接，并通信，通信流程主要体现在发起连接和登录这两个步骤中
 *     -- 2.1 iks_connect_tcp				-----------> step 2.1 : 连接服务器
 *     -- 2.2 iks_stream_new				-----------> step 2.2 : 开始登录服务器(详见登录流程)
 * */

/*
 *	登录流程: 
 *	//服务器发给客户端的数据都要经过j_setup_filter进行过滤
 *	- 1. on_stream							-----------> step 1: 调用iks_make_auth生成登录数据包,再调用iks_send将登录数据包发送至服务器 
 *	@登录成功
 *	- 2. on_iq_auth_result					-----------> step 2: 经过filter过滤后的数据包如果符合登录成功的特征，将进入该函数进行处理
 *	@登录失败
 *	- 2. on_iq_auth_error					-----------> step 2: 经过filter过滤后的数据包如果符合登录失败的特征，将进入该函数进行处理
 *																 进入登录失败流程的帐号都被认为是未注册帐号，在该函数中将进入注册流程
 *																 (详见注册流程)
 */

/*
 * 注册流程
 * //注册成功后，再次发起登录流程
 * - 注册分两个步骤:
 * - 1. iks_make_reg1						-----------> step 1: 调用该函数生成注册1数据包，发往服务器。该数据包的目的是向服务器询问注册格式
 *   															 服务器返回的注册格式会在on_iq_result_reg1函数中进行处理
 * - 2. iks_make_reg2						-----------> step 2: 调用该函数生成注册2数据包，发往服务器。该数据包的目的是向服务器正式注册
 *   															 服务器返回的注册格式会在on_iq_result_reg2函数中进行处理
 * */

/*
 * 聊天（信息交互）机制
 * //登录成功后，可以收到类似于QQ聊天一样的信息,处理流程见on_msg函数
 * 主要处理2种格式的聊天消息
 * @前缀为“cmd:”开头的消息，其剩余部分会被当作linux命令来处理，并返回执行结果
 * @JSON格式的消息，是用户自定义的消息，具体的处理方式由Device_Init传入的on_cmd_func函数由用户自己来处理。
 *    该JSON格式需要满足的基本格式是：
 *    {
 *		"cmd" : "xxx",
 *		"params" : {						-----------> params结构中的具体内容由用户自行定义零至多个
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
 * 宏定义区
 */
/* 服务器地址 */
#define SERVER_ADDR "xmpp.siteview.com"
//#define SERVER_ADDR "192.168.0.2"
/* 服务器端口 */
#define SERVER_PORT (5222)

#define MAX_USER_LEN (100)
#define MAX_USER_FULL_LEN (201)
#define MAX_PASSWD_LEN (100)
#define MAX_SERVER_LEN (100)

/* 
 * 结构定义区
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
 * 全局变量区
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
/* 用该全局变量记录ping服务器无响应次数，若超过一定次数则认为客户端掉线，主动断开连接，重新登录 */
int ping_no_res_cnt = 0;


/* 
 * 函数实现区
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
			//返回的包需要将from与to调换位置
			char *to = iks_find_attrib(x, "from");
			char *from = iks_find_attrib(x, "to");
			ret = iks_make_ping_result(id, from, to);
			iks_send (sess->prs, ret);
			iks_delete (ret);
		}
	}
	return IKS_FILTER_EAT;
}

//登陆成功

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
	//设置在线
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

	/* 暂时把管理账户设置成初始管理账户,未来要实现的负载均衡，可修改此处 */
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

//登陆失败

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
	//登陆失败，可能是未注册引起的，执行注册过程。注册过程分3步：
	//reg1:获取注册表信息，即服务器要求的注册信息格式
	//reg2:填写注册表单，发往服务器
	//reg3:客户端可以选择性的完善用户注册信息，通过发送reg3得到详细表单
	
	//执行reg1即可
	iks *x = iks_make_reg1();

	iks_send(sess->prs, x);

	iks_delete(x);
	return IKS_FILTER_EAT;
}

//获取注册表成功

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
	//执行注册过程第二步
	iks *x = iks_make_reg2(sess->acc->user, sess->pass);

	iks_send(sess->prs, x);

	iks_delete(x);
	return IKS_FILTER_EAT;
}

//注册成功

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
	//注册成功执行登陆过程
	//printf("Start logon when finish registering\n");
	//printf("[USER]:%s\n", sess->acc->user);
	//printf("[PASSWD]:%s\n", sess->pass);
	iks *x = iks_make_auth(sess->acc, sess->pass, NULL);
	iks_insert_attrib (x, "id", "auth");

	iks_send(sess->prs, x);

	iks_delete(x);
	return IKS_FILTER_EAT;
}

//注册失败

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
	//注册失败，打印失败code
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
on_roster (struct session *sess, ikspak *pak)  //获取 roster之后，给其中一个人发一个 hello 的信息 。
{
	iks *child;
	my_roster = pak->x;
	//sess->job_done = 1;
	//return IKS_FILTER_EAT;
	//找出一个联系人
    child=iks_child(my_roster);
    child=iks_child(child);
    child=iks_next(child);
    char *jid=iks_find_attrib(child,"jid"); //roster中的一个用户
    
	if (jid)
	{
        /* 给该联系人发一个hello 信息 */
    	iks *msg=iks_make_msg(IKS_TYPE_CHAT,jid,"hello,test msg!");
    	iks_insert_attrib (msg, "id", "msglai"); 
    	iks_send (sess->prs, msg);
    	iks_delete (msg);
	}
    return IKS_FILTER_EAT;
}

//sdk 能处理的JSON格式的默认命令,目前只有与未来要实现负载均衡相关的set-remote-admin命令有效

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
	/* 执行reboot命令前需要自检文件系统是否正常 */
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

//处理收到的广播消息
//由于广播消息无需客户端响应,所以广播消息都是直接当作命令来处理
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
//处理收到的聊天消息

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
	/* 判断ikspak 的类型 */
	if(pak->type==IKS_PAK_MESSAGE)
	{
		if(pak->subtype==IKS_TYPE_CHAT)
		{   
			iks *x = pak->x;
			char *id = iks_find_attrib(x, "id");
			char *payload = iks_find_cdata(x, "body");
			if (payload)
			{
				/* 
				 * 1.首先判断是否shell命令 
				 */

				/* 简单只判断内容的头4个字节是否为"cmd:"，如果是，则说明是shell命令,执行完命令后，将执行结果发回 */
				/* 需要注意：千万不要发送不可退出的命令如不加-c参数的ping命令和不加-n参数的top命令 */
				if (!strncmp(payload, "cmd:", strlen("cmd:")))
				{
					char *cmd_content = payload + strlen("cmd:");
					char cmd_res[MAX_RESULT_BLOCK_LEN];
					memset(cmd_res, 0, MAX_RESULT_BLOCK_LEN);
					int ret = do_cmd(cmd_content, cmd_res, MAX_RESULT_BLOCK_LEN);

					iks *body;
					/* 生成消息结构 */
					iks *msg=iks_make_msg(IKS_TYPE_CHAT,pak->from->full,NULL);
					/* 必须添加id，否则对端收不到 */
					if (id)
					{
						iks_insert_attrib(msg, "id", id);
					}
					else
					{
						iks_insert_attrib(msg, "id", "msglai");
					}
					/* 添加消息体 */
					body = iks_insert(msg, "body");
					iks_insert_cdata(body, cmd_res, 0);
					iks_send(sess->prs, msg);
					iks_delete (msg);

					//reboot命令延后处理
					if (strncmp(cmd_content, "reboot", strlen("reboot")) ==0 && ret == 0)
					{
						system("reboot");
					}
					return IKS_FILTER_EAT;
				}

				/* 
				 * 2 判断是否JSON格式的命令
				 */
				/* 解析json根节点 */
				cJSON *json_root = cJSON_Parse(payload);
				cJSON *response = NULL;
				char *str_resp = NULL;
				int ret;
				if (json_root)
				{
					/* 优先处理内部命令 */
					if (on_default_func(json_root, &response) >= 0)
					{
						;
					}
					/* 其次处理Device_Init传入的命令 */
					else if (g_cmd_func)
					{
						ret = g_cmd_func(json_root, &response);
					}
					/* 命令处理中，如果有反馈结果 */
					if (response)
					{
						str_resp = cJSON_Print(response);
						if (str_resp)
						{
							iks *body;
							/* 生成消息结构 */
							iks *msg=iks_make_msg(IKS_TYPE_CHAT,pak->from->full,NULL);
							if (id)
							{
								iks_insert_attrib(msg, "id", id);
							}
							else
							{
								iks_insert_attrib(msg, "id", "msglai");
							}
							/* 添加消息体 */
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


//对收到在线状态消息的处理
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

//与服务器进行通信中的调试信息
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

//与服务器通信中最重要的步骤,设置过滤器。当调用iks_recv收到服务器发来的数据包时，会按照过滤器中的设置对数据包进行检查

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
		/* 对收到ping返回 */
		iks_filter_add_rule (my_filter, (iksFilterHook *) on_iq_result, sess,
                IKS_RULE_TYPE, IKS_PAK_IQ,
                IKS_RULE_SUBTYPE, IKS_TYPE_RESULT,
                IKS_RULE_ID, "ping",
                IKS_RULE_DONE);
		/* 对收到ping包的处理 */
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
		iks_filter_add_rule (my_filter, (iksFilterHook *) on_msg, sess,  //当返回时，lailaigq@gmail.com/auth" id="roster" type="result">  执行。
                IKS_RULE_TYPE, IKS_PAK_MESSAGE,
                IKS_RULE_SUBTYPE, IKS_TYPE_CHAT,
                //IKS_RULE_FROM_PARTIAL, "dailei@xmpp.siteview.com",
                //IKS_RULE_FROM_PARTIAL, "guanquan.lai@gmail.com",
                IKS_RULE_DONE);
		iks_filter_add_rule (my_filter, (iksFilterHook *) on_broadcast, sess,  //当返回时，lailaigq@gmail.com/auth" id="roster" type="result">  执行。
                IKS_RULE_TYPE, IKS_PAK_MESSAGE,
                //IKS_RULE_SUBTYPE, IKS_TYPE_CHAT, /* 取消type="chat"的限制，以接受广播消息 */
                IKS_RULE_FROM, SERVER_ADDR,	/* 消息来自于服务器 */
                //IKS_RULE_FROM_PARTIAL, "guanquan.lai@gmail.com",
                IKS_RULE_DONE);
        //当接受到 presence 请求加为好友时
 //zbwgy718823@gmail.com" to="lailaigq@gmail.com"> xmlns:sub="google:subscribe">
		iks_filter_add_rule (my_filter, (iksFilterHook *) on_presence, sess,  //当返回时，lailaigq@gmail.com/auth" id="roster" type="result">  执行。
                IKS_RULE_TYPE, IKS_PAK_PRESENCE,
                IKS_RULE_SUBTYPE, IKS_TYPE_SUBSCRIBE,
                //IKS_RULE_FROM_PARTIAL, "zbwgy718823@gmail.com",
                IKS_RULE_DONE);
}

//与服务器进行连接
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
				//连续ping服务器MAX_NO_RES_CNT次都没有响应，则认为客户端已经掉线，退出函数等待下一次重新连接
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

//等待客户端上线,参见example
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
//上报消息至默认对端
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

//上报消息至指定对端
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

//上报JSON结构的数据至对端
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

//上报JSON结构的数据至对端
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

//上报JSON结构的数据至对端
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

//上报JSON结构的数据至对端
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


//设备初始化信息，主要需要DeviInfo信息中的SN（用于生成客户端帐号）,对端管理帐号（用于向对端上报信息）,其他信息可以随意填写非空值。注意不要超过数组长度
//on_cmd_func用于处理用户定义的JSON命令，请参考demo程序中调用Device_Init
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
		/* 用SN号生成用户名 */
		memcpy(&g_dev_info, DevInfo, sizeof(*DevInfo));
		strncpy(g_connect_info.user, DevInfo->SN, sizeof(DevInfo->SN));
		strcpy(g_connect_info.server, SERVER_ADDR);
		/* 保存管理员账户 */
		strcpy(g_connect_info.remote_first_user, admin_acc);
		strcat(g_connect_info.remote_first_user, "@");
		strcat(g_connect_info.remote_first_user, SERVER_ADDR);
		/* 用siteview和SN号生成一个密码 */
		strcpy(g_connect_info.passwd, "siteview");
		strcat(g_connect_info.passwd, DevInfo->SN);
		/* 生成用户名的全名，由用户名@server组成 */
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


//调用次函数，发起客户端向服务器的连接
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
		//如果有错误发生，则休眠10秒钟后发起下一次连接
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
