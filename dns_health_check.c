#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h> 
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "dns_health_check.h"

#define BUFFER_MAX_SIZE 2048
#define DOMAIN_MAX_SIZE 256
#define DNS_RR_MAX_SIZE 256

#define DNS_CHECK_SUCCESS 0
#define DNS_SERVER_HEALTH 1
#define DNS_SERVER_NOT_HEALTH 2

#define PARAMETER_ERROR -1
#define GET_DNS_SERVER_IP_ERROR -2
#define QUARY_SEND_ERROR -3
#define RESPONSE_RECV_ERROR -5
#define TCP_CONNECT_ERROR -4
#define SOCKET_ERROR -6


/* 读取配置文件中的dns服务器地址 成功则把
   ip地址放入server_addr 返回0。 失败返回-1 */
int read_dns_server_ip(char *server_addr, char *config_file)
{
	FILE *file;
	char buffer[128];
	int flag = 0;
	file = fopen(config_file, "r");
	if (file == NULL)
	{
		printf("open %s filed!\n", config_file);
		return -1;
	}
	
	
	while(!feof(file))
	{
		memset(buffer, 0, sizeof(buffer));
		fgets(buffer, sizeof(buffer), file);
		if(buffer[0] == '#' || buffer[0] == '\0')
		{
			continue;
		}	
		if(strstr(buffer, "nameserver") != NULL)
		{
			flag = 1;
			break;
		}
	}
	fclose(file);
	if (flag == 1)
	{
		char *token = NULL;
		token = strtok(buffer, " ");
		token = strtok(NULL, " ");
		token = strtok(token, "\n");
		memset(server_addr, 0, sizeof(server_addr));
		sprintf(server_addr, "%s",token);

		return 0;
	}
	else
	{
		printf("read filed\n");
		return -1;
	}
}

/* 解析dnsbuf中no位后的一个域名信息放到
 * domain_buf中domain_buf在函数外分配内存
 */
int get_domain(int no, char* domain_buf, unsigned char* dns_buf)
{
    int dns_buf_no = no;
    int domain_buf_no = 0;
    int jump_flag = 0;  /* 域名压缩的标志 */
    int n;
	int NO = 49152; /* 1100 0000 0000 0000 */
	if(dns_buf[dns_buf_no] == 0)
	{
		domain_buf[0] = '.';
		return no + 1;
	}
    while (dns_buf[dns_buf_no] != 0) 
	{
        if (dns_buf[dns_buf_no] < 192) /* 1100 0000 */
		{
            n = dns_buf[dns_buf_no];
            memcpy(domain_buf + domain_buf_no, dns_buf + dns_buf_no + 1, n);
            domain_buf_no += n;
            domain_buf[domain_buf_no++] = '.';
            dns_buf_no += n + 1;
    		if (jump_flag == 0) 
			{
                no += n + 1;
			}
		} 
		else 
		{
            if (jump_flag == 0) 
			{
                no += 2;
                jump_flag = 1;
			}
			 dns_buf_no = dns_buf[dns_buf_no] * 256 + dns_buf[dns_buf_no + 1] - NO;     
		}
	}
    if (jump_flag == 0) 
		no = no + 1;
    domain_buf[domain_buf_no] = 0;
    return no;
}

int proto_check(char *proto)
{
	if (proto == NULL)
	{
		return -1;
	}
	if(strncmp(proto, "UDP", 3) != 0 && strncmp(proto, "TCP", 3) != 0)
	{
		return -1;
	}
	else
	{
		return 0;
	}

}

int type_check(char *type)
{
	if (type == NULL)
		return -1;
	
	else if (strcmp(type, "A") == 0) 
		return 1;
	
	else if (strncmp(type, "CNAME", 5) == 0) 
		return 5;
	
	else if (strncmp(type, "NS", 2) == 0) 
		return 2;
	
	else if (strncmp(type, "AAAA", 4) == 0) 
		return 28;
	
	else if (strncmp(type, "MX", 2) == 0) 
		return 15;
	
	else if (strncmp(type, "SOA", 3) == 0) 
		return 6;
	
	else if (strncmp(type, "TXT", 3) == 0) 
		return 16;
	
	else
		return -1;
}

int port_check(char *port)
{
	if (port == NULL)
	{
		return -1;
	}
	int num = atoi(port);
	if (num <=0 )
	{
		return -1;
	}
	return num;
}

int parameter_check(char *domain, char *type, char *proto, char *port)
{
	if (domain == NULL || type_check(type) == -1 ||\
		proto_check(proto)== -1 || port_check(port) == -1)
	{
		return -1;
	}
	else 
	{
		return 0;
	}
}

/* dest在外面分配好大小，大小为strlen(domain) + 2
 * 把域名转换为数据包中的格式 www.abc.cn --> 3www3abc2cn0 */
int domain_transform(char *dest, char *domain)
{
	if (dest == NULL || domain == NULL)
	{
		return -1;
	}
	char domain_copy[128];
	memset(domain_copy, 0, 128);
	strcpy(domain_copy, domain);
	
	char *token = NULL;
	int token_length = 0;
	int offset = 0;
	token = strtok(domain_copy, ".");
	while (token != NULL)
	{
		offset += token_length;
		token_length = strlen(token);
		dest[offset] = token_length;
		sprintf(dest + offset + 1, "%s", token);
		token_length++;
		token = strtok(NULL, ".");
	}
	dest[offset + token_length] = 0;
	return 0;
}

/* 创建一个dns查选包，返回包的长度 */
int gen_dns_packet(char *buffer, char *domain_name, char *type, char *proto)
{
	dns_header_t header;
	dns_question_t question;
	int offset = 0;
	char domain[strlen(domain_name) + 2];
	
	domain_transform(domain, domain_name);
	header.id = 1;
    header.rd = 1;
    header.tc = 0;
    header.aa = 0;
    header.opcode = 0;
    header.qr = 0;
    header.rcode = 0;
    header.z = 0;
    header.ra = 0;
    header.qdcount = htons(1);  
    header.ancount = htons(0);
    header.nscount = htons(0);
    header.arcount = htons(0);
	question.qclass = htons(1);
	question.qtype = htons(type_check(type));
	
	if (strncmp(proto, "TCP", 3) == 0) 
	{
		/*tcp报文头部 比dns报文多两个八位组用来表示接下来要发送的长度 */
		unsigned short length ;
		length = htons(sizeof(dns_header_t) + sizeof(domain) + sizeof(dns_question_t));									
		memcpy(buffer, &length, sizeof(unsigned short));
		offset += sizeof(unsigned short);
	}
	memcpy(buffer + offset, &header, sizeof(header));
	offset += sizeof(header);
	memcpy(buffer + offset, domain, sizeof(domain));
	offset += sizeof(domain);
	memcpy(buffer + offset, &question, sizeof(dns_question_t));
	offset += sizeof(dns_question_t);
	
	return offset;
}

/* 取得服务器的响应包，返回的是错误代码 */
int get_dns_response(char *sendbuf, unsigned char * recv_buf, int sendbuf_len, char *proto, char *port)
{
	int sockfd;
	int ret;
	struct sockaddr_in addr;
	struct timeval tv;
	char server_ip[128];
	
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(port));
	if (read_dns_server_ip(server_ip, "/etc/resolv.conf") == -1)
	{
		return GET_DNS_SERVER_IP_ERROR;
	}
	addr.sin_addr.s_addr = inet_addr(server_ip);
	tv.tv_usec = 0;
	tv.tv_sec = 5;
	
	if(strncmp(proto, "TCP", 3) == 0)
	{
		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		if (sockfd < 0)
		{
			return SOCKET_ERROR;
		}
		setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv));
		setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof (tv));
		
		ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(struct sockaddr));
		if (ret < 0)
		{
			return TCP_CONNECT_ERROR;	
		}
		
		ret = write(sockfd, sendbuf, sendbuf_len);
		if (ret < 0)
		{
			return QUARY_SEND_ERROR;	
		}
		
		memset(sendbuf, 0, BUFFER_MAX_SIZE);
		ret = read(sockfd, recv_buf, BUFFER_MAX_SIZE);
		if (ret < 0)
		{
			return RESPONSE_RECV_ERROR;
		}
	}
	else
	{
		socklen_t len;
		sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (sockfd < 0)
		{
			return SOCKET_ERROR;
		}
		setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof (tv));
		setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof (tv));
		
		ret = sendto(sockfd, sendbuf, sendbuf_len, 0, (struct sockaddr*)&addr, sizeof(struct sockaddr_in));
		if (ret < 0)
		{
			return QUARY_SEND_ERROR;
		}
		
		memset(sendbuf, 0, BUFFER_MAX_SIZE);
	
		ret = recvfrom(sockfd, recv_buf, BUFFER_MAX_SIZE, 0, (struct sockaddr*)&addr, &len);
		if (ret < 0)
		{
			return RESPONSE_RECV_ERROR;
		} 
	}

	close(sockfd);
	return DNS_CHECK_SUCCESS;
}

/* 打印资源记录信息 */
int print_dns_rr(unsigned char *data, int type, unsigned char *recv_buf, int offset)
{
	switch (type)
	{
		case 1:
		{
			printf("%-10s%i.%i.%i.%i\n", "A", data[0], data[1], data[2], data[3]);
			break;	
		}				
		case 5:
		{
			char cname[DOMAIN_MAX_SIZE]={0};
			get_domain(offset, cname, recv_buf);
			printf("%-10s%-s\n", "CNAME", cname);
			break;	
		}		
		case 2:
		{
			char ns_name[DOMAIN_MAX_SIZE];
			get_domain(offset, ns_name, recv_buf);
			printf("%-10s%-s\n", "NS", ns_name);
			break;
		}
		case 6:
		{
			char mname[100] = {0};
			char rname[100] = {0};
			unsigned int serial, refresh, retry, expire, minimum; 
			int n1 = get_domain(offset, mname, recv_buf);
			n1 = get_domain(n1, rname, recv_buf);
			serial = *(unsigned int*) (data + n1);
			n1 += 4;
			refresh = *(unsigned int *) (data + n1);
			n1 += 4;
			retry = *(unsigned int *) (data + n1);
			n1 += 4;
			expire = *(unsigned int *) (data + n1);
			n1 += 4;
			minimum = *(unsigned int *) (data + n1);
			printf("SOA %s %s %u %u %u %u %u n",
					mname, rname, ntohl(serial), ntohl(refresh),
					ntohl(retry), ntohl(expire), ntohl(minimum));
			break;
		}
			
		case 15:
		{
			int preference = *(unsigned short*) data;
			char exchange[100];
			get_domain(offset + 2, exchange, recv_buf);
			printf("MX\t%i\t%s\n", ntohs(preference), exchange);
			break;
		}
		case 16:
			printf("TXT\t%s\n", data + 1);
			break;
		case 28:
		{
			printf("%-10s","AAAA");
			int i=0;
			while(i < 7)
			{
				printf("%02x%02x:", data[2*i],data[2*i+1]);
				i++;
			}
			printf("%02x%02x\n",data[14], data[15]);
			break;	
		}			
		default:
			printf("\n");	
	}
	return 0;
}

/* 打印dns响应包，返回服务器健康情况，*/
int unpacket(unsigned char *recv_buf,char *proto, char *type)
{
	int result = DNS_SERVER_NOT_HEALTH; /*dns服务器是否健康， 1表示健康， 0 表示有问题 */
	char domain[DOMAIN_MAX_SIZE];
	memset(domain, 0, sizeof(domain));
	int rr_no;
	dns_header_t header;
	dns_question_t question;
	int offset = 0;
	
	if(strncmp(proto, "TCP", 3) == 0)
	{
		/* 去掉tcp头部的表示长度的块 */
		memcpy(recv_buf, recv_buf + 2, BUFFER_MAX_SIZE-2);
	}
	memcpy(&header, recv_buf + offset, sizeof(dns_header_t));
	offset += sizeof(dns_header_t);
	
	get_domain(offset, domain, recv_buf);
	offset += strlen(domain) + 1;

	memcpy(&question, recv_buf + offset, sizeof(dns_question_t));
	offset += sizeof(dns_question_t);
	
	rr_no = ntohs(header.ancount) + ntohs(header.nscount) + ntohs(header.arcount);
	if (rr_no > 0)
	{
		printf(";;QUESTION: \n");
		printf(";%-32s%-10s%s\n", domain, "IN", type);
	}
	
	if (ntohs(header.ancount) > 0)
	{
		printf("\n;;ANSWER SECTION:\n");    
	}
	dns_rr_t rr;
	unsigned char data[DNS_RR_MAX_SIZE];
	while (rr_no > 0)
	{
		memset(domain, 0, sizeof(domain));
		memset(data, 0, sizeof(data));
		offset = get_domain(offset, domain, recv_buf);
		memcpy(&rr, recv_buf + offset, sizeof(dns_rr_t));
		offset += sizeof(dns_rr_t);
		memcpy(data, recv_buf + offset, ntohs(rr.rdlength));
		
		int type = ntohs(rr.type);
		if (type == 1 ||type == 2 ||type == 5 ||type == 28|| type == 6 || type == 15 || type == 16)
		{
			if (type == htons(question.qtype))
				result = DNS_SERVER_HEALTH;
			
			printf("%-25s%-8d%-10s",domain, ntohl(rr.ttl),"IN");
			print_dns_rr(data, type, recv_buf, offset);
		}
		offset += ntohs(rr.rdlength);
		rr_no--;
		if (rr_no == ntohs(header.nscount) + ntohs(header.arcount) && ntohs(header.nscount) > 0) 
		{
		 printf("\n;;AUTHORITY SECTION:\n");
		}
		if (rr_no == ntohs(header.arcount) && ntohs(header.arcount) > 0) 
		{
			printf("\n;;ADDITIONAL SECTION:\n");
		}
	}
	printf("\n");
	return result;
}

int dns_health_check(char *domain, char *type, char *proto, char *port)
{
	
	int offset;
	int result;
	result = parameter_check(domain, type, proto, port);
	if (result == -1)
	{
		return PARAMETER_ERROR;
	}
	
	char sendbuf[BUFFER_MAX_SIZE];
	unsigned char recv_buf[BUFFER_MAX_SIZE];
	memset(sendbuf, 0, sizeof(sendbuf));
	memset(recv_buf,0, sizeof(recv_buf));
	
	offset = gen_dns_packet(sendbuf, domain, type, proto);
	result = get_dns_response(sendbuf, recv_buf, offset, proto, port);
	if (result != DNS_CHECK_SUCCESS)
	{
		return result;
	}
	result = unpacket(recv_buf, proto, type);
	
	return result;
}