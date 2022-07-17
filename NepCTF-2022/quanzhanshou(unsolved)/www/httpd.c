
#include "include.h"
#include "conf.h"
#include "util.h"
#include "daemond.h"
#include "business.h"

#define TOKEN "token"
#define ISspace(x) isspace((int)(x))


#ifdef DEBUG
int debug=1;
#else
int debug=0;
#endif

void backups()
{
	FILE *fp1,*fp2;
char c;
fp1=fopen("flag","r"); /*打开源文件*/
fp2=fopen("X-admin/flag.txt","w"); /*打开将写入的文件*/
while ((c=fgetc(fp1))!=EOF) /*将源文件fp1的内容转存(复制)到目标文件fp2中*/
fputc(c,fp2);
fclose(fp1); /*关闭文件*/
fclose(fp2);
    return main();
}


void accept_request(int);
void bad_request(int);
void cat(int, FILE *);
void cannot_execute(int);
void error_die(const char *);
void execute_cgi(int, const char *, const char *, const char *);
void headers(int, const char *);
void not_found(int);
void serve_file(int, const char *);
void unimplemented(int);
void execute_action(int client,const char *url,const char *method,const char *query_string,int content_length);
void unlogin(int client);
void opsuccess(int client);
void opfail(int client);
void cookie_header(char *name, char *value, int secondsToLive,char *buf);
int cookie_set(int client);
int check_login(char *cookie);
int get_line(int, char *, int);
int startup(u_short *);

/////////////////////////////////////////////

static char *days[] = {
				"Sun",
				"Mon",
				"Tue",
				"Wed",
				"Thu",
				"Fri",
				"Sat"
};

static char *months[] = {
				"Jan",
				"Feb",
				"Mar",
				"Apr",
				"May",
				"Jun",
				"Jul",
				"Aug",
				"Sep",
				"Oct",
				"Nov",
				"Dec"
};


/**********************************************************************/
/* A request has caused a call to accept() on the server port to
 * return.  Process the request appropriately.
 * Parameters: the socket connected to the client */
/**********************************************************************/
void accept_request(int client)
{
				char buf[1024];
				int numchars;
				char method[255];
				char url[255];
				char path[512];
				size_t i, j;
				struct stat st;
				char cookie[1024]={0};
				int content_length=-1;
				//int cgi = 0;
				/* becomes true if server decides this is a CGI program */
				char *query_string = NULL;

				numchars = get_line(client, buf, sizeof(buf));
				i = 0; j = 0;
				while (!ISspace(buf[j]) && (i < sizeof(method) - 1))
				{
								method[i] = buf[j];
								i++; j++;
				}
				method[i] = '\0';

				if (strcasecmp(method, "GET") && strcasecmp(method, "POST"))
				{
								unimplemented(client);
								close(client);
								pthread_detach(pthread_self());
								return;
				}

				//if (strcasecmp(method, "POST") == 0)
				//	cgi = 1;

				i = 0;
				while (ISspace(buf[j]) && (j < sizeof(buf)))
								j++;
				while (!ISspace(buf[j]) && (i < sizeof(url) - 1) && (j < sizeof(buf)))
				{
								url[i] = buf[j];
								i++; j++;
				}
				url[i] = '\0';

				if (strcasecmp(method, "GET") == 0)
				{
								query_string = url;
								while ((*query_string != '?') && (*query_string != '\0'))
												query_string++;
								if (*query_string == '?')
								{
												//	cgi = 1;
												*query_string = '\0';
												query_string++;
								}
				}

				/*
				 *在此处对请求url过滤处理 
				 */
				//sprintf(path, "htdocs%s", url);
				sprintf(path, "X-admin%s", url);
				if(debug)
				{
								printf("path,%s method,%s\n",path,method);
				}
				if (stat(path, &st) == -1) {
								/*
								 *解析cookie
								 */
								do{
												char cbuf[16]={0};
												numchars=get_line(client,buf,sizeof(buf));		
												strncpy(cbuf,buf,15);
												if (strcasecmp(cbuf, "Content-Length:") == 0)
												{
																content_length = atoi(&(buf[16]));
												}else{
																cbuf[7] = '\0';
																if(strcasecmp(cbuf,"Cookie:")==0){
																				strcpy(cookie,&buf[8]);
																}
												}
								}while((numchars>0)&&strcmp("\n",buf));	

								if(debug)
								{
												printf("cookie:%s\n",cookie);
								}
								/*
								 * 如果不是做登陆请求,未通过登陆验证,返回未登陆。
								 */
								if((strcmp(url,"/login.action")!=0)&&(check_login(cookie)!=0)){
												if(content_length>0){
																char x;	
																for (i = 0; i <(unsigned)content_length; i++) {
																				recv(client,&x, 1, 0);
																}
												}
												unlogin(client);
								}else{
												execute_action(client,url,method,query_string,content_length);
								}
								//while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
								//	numchars = get_line(client, buf, sizeof(buf));
								//not_found(client);
				}
				else
				{
								if ((st.st_mode & S_IFMT) == S_IFDIR)
												strcat(path, "/index.html");
								/*if ((st.st_mode & S_IXUSR) ||	(st.st_mode & S_IXGRP) || (st.st_mode & S_IXOTH) )
									cgi = 1;
									if (!cgi)
									serve_file(client, path);
									else
									execute_cgi(client, path, method, query_string);
								 */
								serve_file(client, path);
				}

				close(client);
}

/**********************************************************************/
/* Inform the client that a request it has made has a problem.
 * Parameters: client socket */
/**********************************************************************/
void bad_request(int client)
{
				char buf[1024];

				sprintf(buf, "HTTP/1.0 400 BAD REQUEST\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "Content-type: text/html\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "<P>Your browser sent a bad request, ");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "such as a POST without a Content-Length.\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
}

/**********************************************************************/
/* Put the entire contents of a file out on a socket.  This function
 * is named after the UNIX "cat" command, because it might have been
 * easier just to do something like pipe, fork, and exec("cat").
 * Parameters: the client socket descriptor
 *             FILE pointer for the file to cat */
/**********************************************************************/
void cat(int client, FILE *resource)
{
				char buf[1024];
				/*
					 fgets(buf, sizeof(buf), resource);
					 while (!feof(resource))
					 {
					 send(client, buf, strlen(buf), 0);
					 fgets(buf, sizeof(buf), resource);
					 }*/

				int n;

				while((n=fread(buf,1,sizeof(buf),resource))>0){
								//printf("read:%d\n",n);
								int x=send(client,buf,n,MSG_NOSIGNAL);
								//printf("send:%d\n",x);
								if(x==-1){
												break;
								}
				}
}

/**********************************************************************/
/* Inform the client that a CGI script could not be executed.
 * Parameter: the client socket descriptor. */
/**********************************************************************/
void cannot_execute(int client)
{
				char buf[1024];

				sprintf(buf, "HTTP/1.0 500 Internal Server Error\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "Content-type: text/html\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "<P>Error prohibited CGI execution.\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
}

/**********************************************************************/
/* Print out an error message with perror() (for system errors; based
 * on value of errno, which indicates system call errors) and exit the
 * program indicating an error. */
/**********************************************************************/
void error_die(const char *sc)
{
				perror(sc);
				exit(1);
}
/*
 * 执行处理
 */
void execute_action(int client,const char *url,const char *method,const char *query_string,int content_length){
				int i;
				char *p;
				if(strcasecmp(method,"GET")==0){
								if(strcmp(url,"/main_load.action")==0){
												if(debug){
																printf("invoke main_load\n");
												}
												do_main_load(client);
								}
								else{
												unimplemented(client);
								}
				}else{/*POST*/
								if (content_length == -1) {
												bad_request(client);
												return;
								}
								//获取参数
								p=malloc(content_length+1);
								memset(p,0,content_length+1);
								for (i = 0; i < content_length; i++) {
												recv(client, p+i, 1, 0);
								}
								if(debug)
								{
												printf("%s,length:%d\n",p,strlen(p));
								}
								/*
								 * 根据url，处理对应的请求。
								 */
								if(strcmp("/login.action",url)==0){
												if(debug){
																printf("invoke login\n");
												}
												do_login(client,p,content_length);
								}
								else if(strcmp("/sbsz_set.action",url)==0){
												if(debug)
												{
																printf("invoke dev_set");
												}
												do_dev_set(client,p,content_length);
								}
								else{
												unimplemented(client);
								}
								free(p);
				}
}


/**********************************************************************/
/* Execute a CGI script.  Will need to set environment variables as
 * appropriate.
 * Parameters: client socket descriptor
 *             path to the CGI script */
/**********************************************************************/
void execute_cgi(int client, const char *path,
								const char *method, const char *query_string)
{
				char buf[1024];
				int cgi_output[2];
				int cgi_input[2];
				pid_t pid;
				int status;
				int i;
				char c;
				int numchars = 1;
				int content_length = -1;

				buf[0] = 'A'; buf[1] = '\0';
				if (strcasecmp(method, "GET") == 0)
								while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
												numchars = get_line(client, buf, sizeof(buf));
				else    /* POST */
				{
								numchars = get_line(client, buf, sizeof(buf));
								while ((numchars > 0) && strcmp("\n", buf))
								{
												buf[15] = '\0';
												if (strcasecmp(buf, "Content-Length:") == 0)
																content_length = atoi(&(buf[16]));
												numchars = get_line(client, buf, sizeof(buf));
								}
								if (content_length == -1) {
												bad_request(client);
												return;
								}
				}

				sprintf(buf, "HTTP/1.0 200 OK\r\n");
				send(client, buf, strlen(buf), 0);

				if (pipe(cgi_output) < 0) {
								cannot_execute(client);
								return;
				}
				if (pipe(cgi_input) < 0) {
								cannot_execute(client);
								return;
				}

				if ( (pid = fork()) < 0 ) {
								cannot_execute(client);
								return;
				}
				if (pid == 0)  /* child: CGI script */
				{
								char meth_env[255];
								char query_env[255];
								char length_env[255];

								dup2(cgi_output[1], 1);
								dup2(cgi_input[0], 0);
								close(cgi_output[0]);
								close(cgi_input[1]);
								sprintf(meth_env, "REQUEST_METHOD=%s", method);
								putenv(meth_env);
								if (strcasecmp(method, "GET") == 0) {
												sprintf(query_env, "QUERY_STRING=%s", query_string);
												putenv(query_env);
								}
								else {   /* POST */
												sprintf(length_env, "CONTENT_LENGTH=%d", content_length);
												putenv(length_env);
								}
								execl(path, path, NULL);
								exit(0);
				} else {    /* parent */
								close(cgi_output[1]);
								close(cgi_input[0]);
								if (strcasecmp(method, "POST") == 0)
												for (i = 0; i < content_length; i++) {
																recv(client, &c, 1, 0);
																write(cgi_input[1], &c, 1);
												}
								while (read(cgi_output[0], &c, 1) > 0)
												send(client, &c, 1, 0);

								close(cgi_output[0]);
								close(cgi_input[1]);
								waitpid(pid, &status, 0);
				}
}

/**********************************************************************/
/* Get a line from a socket, whether the line ends in a newline,
 * carriage return, or a CRLF combination.  Terminates the string read
 * with a null character.  If no newline indicator is found before the
 * end of the buffer, the string is terminated with a null.  If any of
 * the above three line terminators is read, the last character of the
 * string will be a linefeed and the string will be terminated with a
 * null character.
 * Parameters: the socket descriptor
 *             the buffer to save the data in
 *             the size of the buffer
 * Returns: the number of bytes stored (excluding null) */
/**********************************************************************/
int get_line(int sock, char *buf, int size)
{
				int i = 0;
				char c = '\0';
				int n;

				while ((i < size - 1) && (c != '\n'))
				{
								n = recv(sock, &c, 1, 0);
								/* DEBUG printf("%02X\n", c); */
								if (n > 0)
								{
												if (c == '\r')
												{
																n = recv(sock, &c, 1, MSG_PEEK);
																/* DEBUG printf("%02X\n", c); */
																if ((n > 0) && (c == '\n'))
																				recv(sock, &c, 1, 0);
																else
																				c = '\n';
												}
												buf[i] = c;
												i++;
								}
								else
												c = '\n';
				}
				buf[i] = '\0';

				return(i);
}

/**********************************************************************/
/* Return the informational HTTP headers about a file. */
/* Parameters: the socket to print the headers on
 *             the name of the file */
/**********************************************************************/
void headers(int client, const char *filename)
{
				char buf[1024];
				//(void)filename;  /* could use filename to determine file type */
				char *p=(char *)filename;
				strcpy(buf, "HTTP/1.0 200 OK\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				strcpy(buf, SERVER_STRING);
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				char *suffix=strrchr(p,'.')+1;
				if(suffix){
								if(strcasecmp(suffix,"js")==0){
												sprintf(buf, "Content-Type: application/javascript\r\n");
								}else if(strcasecmp(suffix,"css")==0){
												sprintf(buf, "Content-Type: text/css\r\n");
								}else if(strcasecmp(suffix,"png")==0){
												sprintf(buf, "Content-Type: image/png\r\n");
								}else if(strcasecmp(suffix,"jpeg")==0){
												sprintf(buf, "Content-Type: image/jpeg\r\n");
								}else{
												sprintf(buf, "Content-Type: text/html\r\n");
								}
				}else{
								sprintf(buf, "Content-Type: text/html\r\n");
				}
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				strcpy(buf, "\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
}

/**********************************************************************/
/* Give a client a 404 not found status message. */
/**********************************************************************/
void not_found(int client)
{
				char buf[1024];

				sprintf(buf, "HTTP/1.0 404 NOT FOUND\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, SERVER_STRING);
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "Content-Type: text/html\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "<HTML><TITLE>Not Found</TITLE>\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "<BODY><P>The server could not fulfill\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "your request because the resource specified\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "is unavailable or nonexistent.\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "</BODY></HTML>\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
}

/**********************************************************************/
/* Send a regular file to the client.  Use headers, and report
 * errors to client if they occur.
 * Parameters: a pointer to a file structure produced from the socket
 *              file descriptor
 *             the name of the file to serve */
/**********************************************************************/
void serve_file(int client, const char *filename)
{
				FILE *resource = NULL;
				int numchars = 1;
				char buf[1024];
				buf[0] = 'A'; buf[1] = '\0';
				while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
								numchars = get_line(client, buf, sizeof(buf));
				resource = fopen(filename, "r");
				if (resource == NULL)
								not_found(client);
				else
				{
								headers(client, filename);
								cat(client, resource);
				}
				fclose(resource);
}

/**********************************************************************/
/* This function starts the process of listening for web connections
 * on a specified port.  If the port is 0, then dynamically allocate a
 * port and modify the original port variable to reflect the actual
 * port.
 * Parameters: pointer to variable containing the port to connect on
 * Returns: the socket */
/**********************************************************************/
int startup(u_short *port)
{
				int httpd = 0;
				struct sockaddr_in name;

				httpd = socket(PF_INET, SOCK_STREAM, 0);
				if (httpd == -1)
								error_die("socket");
				memset(&name, 0, sizeof(name));
				name.sin_family = AF_INET;
				name.sin_port = htons(*port);
				name.sin_addr.s_addr = htonl(INADDR_ANY);
				//允许端口复用
				int opt=1;
				setsockopt(httpd,SOL_SOCKET,SO_REUSEPORT,&opt,sizeof(opt));

				if (bind(httpd, (struct sockaddr *)&name, sizeof(name)) < 0)
								error_die("bind");
				if (*port == 0)  /* if dynamically allocating a port */
				{
								socklen_t namelen = sizeof(name);
								if (getsockname(httpd, (struct sockaddr *)&name, &namelen) == -1)
												error_die("getsockname");
								*port = ntohs(name.sin_port);
				}
				if (listen(httpd, 5) < 0)
								error_die("listen");
				return(httpd);
}

/**********************************************************************/
/* Inform the client that the requested web method has not been
 * implemented.
 * Parameter: the client socket */
/**********************************************************************/
void unimplemented(int client)
{
				char buf[1024];

				sprintf(buf, "HTTP/1.0 501 Method Not Implemented\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, SERVER_STRING);
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "Content-Type: text/html\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "<HTML><HEAD><TITLE>Method Not Implemented\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "</TITLE></HEAD>\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "<BODY><P>HTTP request method not supported.\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "</BODY></HTML>\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
}
/*
 * 未登陆
 */
void unlogin(int client)
{
				char buf[1024];
				sprintf(buf, "HTTP/1.0 200 OK\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, SERVER_STRING);
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "Content-Type: text/json\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "{\"unlogin\":true}");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
}
void opsuccess(int client)
{
				char buf[1024];
				sprintf(buf, "HTTP/1.0 200 OK\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, SERVER_STRING);
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				cookie_set(client);
				sprintf(buf, "Content-Type: text/json\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "{\"success\":true}");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
}
void opfail(int client)
{
				char buf[1024];
				sprintf(buf, "HTTP/1.0 200 OK\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, SERVER_STRING);
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "Content-Type: text/json\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "\r\n");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
				sprintf(buf, "{\"success\":false}");
				if(send(client, buf, strlen(buf), MSG_NOSIGNAL)==-1)return;
}

/*
 * set cookie
 */
int cookie_set(int client) {
				char buf[1024]={0};
				char str[10] = { 0 };
				random_key(str, 10);
				if (writeCFG(FNAME, TOKEN, str) == 0) {
								cookie_header(TOKEN,str,300,buf);
								return send(client, buf, strlen(buf), MSG_NOSIGNAL);
				}
				return -1;
}

/*
 * cookie header string
 */
void cookie_header(char *name, char *value, int secondsToLive,char *buf)
{
				/* cgic 2.02: simpler and more widely compatible implementation.
				 * Thanks to Chunfu Lai. 
				 * cgic 2.03: yes, but it didn't work. Reimplemented by
				 * Thomas Boutell. ; after last element was a bug. 
				 * Examples of real world cookies that really work:
				 * Set-Cookie: MSNADS=UM=; domain=.slate.com; 
				 * expires=Tue, 26-Apr-2022 19:00:00 GMT; path=/
				 * Set-Cookie: MC1=V=3&ID=b5bc08af2b8a43ff85fcb5efd8b238f0; 
				 * domain=.slate.com; expires=Mon, 04-Oct-2021 19:00:00 GMT; path=/
				 * */
				time_t now;
				time_t then;
				struct tm *gt;
				time(&now);
				then = now + secondsToLive;
				gt = gmtime(&then);
				sprintf(buf, "Set-Cookie: %s=%s; expires=%s, %02d-%s-%04d %02d:%02d:%02d GMT\r\n",
												name, value, 
												days[gt->tm_wday],
												gt->tm_mday,
												months[gt->tm_mon],
												gt->tm_year + 1900, 	
												gt->tm_hour,
												gt->tm_min,
												gt->tm_sec);
}

/*
 * check login
 */
int check_login(char *cookie) {
				if(strlen(cookie)==0){
								return -1;
				}
				char *p=cookie;
				char *q=NULL;
				char buf[1024]={0};
				int i;
				int j=0;
				int len=strlen(p);
				printf("p:%s,len:%d\n",p,len);
				for(i=0;i<=len;i++){
								if(*(p+j)=='='){
												*(p+j)='\0';
												memset(buf, 0, sizeof(buf));
												strcpy(buf,p);
												p=p+j+1;
												j=-1;
								}
								else if(*(p+j)==';'||*(p+j)=='\0'||*(p+j)=='\n'||*(p+j)==' '||*(p+j)=='\r'){
												*(p+j)='\0';
												printf("buf:%s\n",buf);
												if(strcmp(buf,TOKEN)==0){
																q=p;		
																break;
												}			
												p=p+j+1;
												j=-1;
								}
								j++;
				}
				if(q==NULL){
								return -1;
				}
				char *tkValue;
				readCFG(FNAME, TOKEN, &tkValue);
				printf("q:%s,length:%d\n",q,strlen(q));
				printf("tkValue:%s,length:%d\n",tkValue,strlen(tkValue));
				if (strlen(q) == 0 || strlen(tkValue) == 0) {
								return -1;
				}
				i= strcmp(q, tkValue);
				free(tkValue);
				return i;
}

/**********************************************************************/

int main(void)
{
				//daemond();
				int server_sock = -1;
				u_short port = 90;
				int client_sock = -1;
				struct sockaddr_in client_name;
				socklen_t client_name_len = sizeof(client_name);
				pthread_t newthread;

				server_sock = startup(&port);
				if (debug)
				{
								printf("\n");
								printf("debug info .....\n");
								printf("httpd running on port %d\n", port);
				}
				while (1)
				{
								client_sock = accept(server_sock,
																(struct sockaddr *)&client_name,
																&client_name_len);
								if (client_sock == -1)
												error_die("accept");
								/*accept_request(client_sock);*/
								if (pthread_create(&newthread , NULL, accept_request, client_sock) != 0)
												perror("pthread_create");
								pthread_detach(newthread);
				}
				printf("error:%s\n",strerror(errno));
				close(server_sock);
				return(0);
}
