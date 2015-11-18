#ifndef DNS_HEALTH_CHECK_H_H
#define DNS_HEALTH_CHECK_H_H

typedef struct 
{
	unsigned short id; // identification number
	unsigned char rd :1; // recursion desired
	unsigned char tc :1; // truncated message
	unsigned char aa :1; // authoritive answer
	unsigned char opcode :4; // purpose of message
	unsigned char qr :1; // query/response flag: 0=query; 1=response
	 
	unsigned char rcode :4;
	unsigned char z :3;
	unsigned char ra :1;
	 
	unsigned short qdcount;
	unsigned short ancount;
	unsigned short nscount;
	unsigned short arcount;
} __attribute__((__packed__))dns_header_t;

typedef struct
{
	unsigned short qtype;
	unsigned short qclass;
} dns_question_t;

typedef struct 
{
	unsigned short type;
	unsigned short class;
	unsigned int ttl;
	unsigned short rdlength;
} __attribute__((__packed__)) dns_rr_t;

/* 读取配置文件中的dns服务器地址 成功则
   把ip地址放入server_addr 返回0。 失败返回-1 */
int read_dns_server_ip(char *server_addr, char *config_file);

/* 解析dnsbuf中no位后的一个域名信息放到domain_buf中
   domain_buf在函数外分配内存 */
int get_domain(int no, char* domain_buf, unsigned char* dns_buf);


/* API入口参数检查 */
int proto_check(char *proto);
int type_check(char *type);
int port_check(char *port);
int parameter_check(char *domain, char *type, char *proto, char *port, char *server_ip);

/* dest在外面分配好大小，大小为strlen(domain) + 2
 * 把域名转换为数据包中的格式 www.abc.cn --> 3www3abc2cn0 */
int domain_transform(char *dest, char *domain);

/* 创建一个dns查询包，返回包的长度 */
int gen_dns_packet(char *buffer, char *domain_name, char *type, char *proto);

/* 取得服务器的响应包，返回的是错误代码 */
int get_dns_response(char *sendbuf, unsigned char * recv_buf, int sendbuf_len, char *proto, char *port, char *server_ip);

/* 打印一条资源记录信息 */
int print_dns_rr(unsigned char *data, int type, unsigned char *recv_buf, int offset);

/* 打印dns响应包，返回服务器健康情况，*/
int unpacket(unsigned char *recv_buf,char *proto, char *type);

int dns_health_check(char *server_ip, char *domain, char *type, char *proto, char *port);

#endif