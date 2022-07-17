
#include "business.h"
#include "include.h"
#include "util.h"

//主页信息加载
void do_main_load(int client)
{
				struct logininfo *linfo;
				linfo = read_login_info();
				long uptime=0; 
				char time_str[64] = { 0 };
				long totalram=0;
				double cpuuse=0.0;
				double memuse=0.0;
				unsigned long rx=0;
				unsigned long tx=0;
				char buf[1024];

				cal_cpu_occupy(&cpuuse);
				cal_mem_occupy(&memuse);
				get_current_time(time_str, 64);
				sys_info(&uptime,&totalram);
				cal_net_info(&rx,&tx);
				char response[1024]={0};
				sprintf(response,"{\"userName\": \"%s\",\"loginTime\": \"%s\",\"curtime\":\"%s\",\"uptime\": %ld,\"totalram\": %ld,\"cpuuse\": %2.2lf,\"memuse\":%2.2lf,\"rx\":%ld,\"tx\":%ld}",linfo->userName,linfo->loginTime,time_str,uptime,totalram,cpuuse,memuse,rx,tx);
				strcpy(buf, "HTTP/1.0 200 OK\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				strcpy(buf, SERVER_STRING);
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "Content-Type: text/json\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				strcpy(buf, "\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				if(send(client, response, strlen(response), MSG_NOSIGNAL)==-1)return;
}

void do_login(int client,char *p,int content_length)
{
				//读取用户名和密码参数
				char username[1024]={0};
				char password[1024]={0};
				char *q;
				q=p;
				int i;
				int j=0;
				char key[1024]={0};
				for(i=0;i<=content_length;i++){
								if(*(q+j)=='='){
												*(q+j)='\0';
												strcpy(key,q);
												q=q+j+1;
												j=-1;	
								}else if(*(q+j)=='&'||*(q+j)=='\0'){
												*(q+j)='\0';
												if(strcmp(key,"username")==0){
																strcpy(username,q);
												}else if(strcmp(key,"password")==0){
																strcpy(password,q);
												}
												memset(key, 0, sizeof(key));
												q=q+j+1;
												j=-1;
								}
								j++;
				}

				extern int debug;
				if(debug)
				{
								printf("read cfg file\n");
				}
				//读取配置文件存储的用户名和密码
				char *uname;
				char *upass;

				readCFG(FNAME,"userName",&uname);
				readCFG(FNAME,"userPass",&upass);

				if(debug)
				{
								printf("userName:%s\n",uname);
								printf("password:%s\n",upass);

				}

				//char *response;	
				if(strcmp(username,uname)==0&&strcmp(password,upass)==0){
								//登陆成功
								write_login_info(username);
								opsuccess(client);
				}else{
								//登陆失败
								opfail(client);
				}
				free(uname);
				free(upass);
}

void do_dev_set(int client,char *p,int content_length)
{
				/*
				 *设备设置操作 
				 */
				int args[6]={0};
				char *q;
				q=p;
				int i,j=0;
				char key[1024]={0};
				for(i=0;i<=content_length;i++){
								if(*(q+j)=='='){
												*(q+j)='\0';
												memset(key, 0, sizeof(key));
												strcpy(key,q);
												q=q+j+1;
												j=-1;	
								}else if(*(q+j)=='&'||*(q+j)=='\0'){
												*(q+j)='\0';
												if(strcmp(key,"port1_delay")==0){
																args[0]=atoi(q);
												}else if(strcmp(key,"port2_delay")==0){
																args[1]=atoi(q);
												}else if(strcmp(key,"port3_delay")==0){
																args[2]=atoi(q);
												}else if(strcmp(key,"port4_delay")==0){
																args[3]=atoi(q);
												}else if(strcmp(key,"port5_delay")==0){
																args[4]=atoi(q);	
												}else if(strcmp(key,"attenuation")==0){
																args[5]=atoi(q);
												}
												q=q+j+1;
												j=-1;
								}
								j++;
				}
				//set delay
				for(i=0;i<6;i++){
								//pldelay_set(1<<(i+1),args[i]);i
								printf("args%d %d   ",i,args[i]);
				}
				printf("\n");
				//set attenuation
				//plspi_write(args[5]);
				opsuccess(client);
}
