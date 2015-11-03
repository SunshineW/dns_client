#include <stdio.h>

#include "dns_health_check.h"

#define DNS_CHECK_SUCCESS 0
#define DNS_SERVER_HEALTH 1
#define DNS_SERVER_NOT_HEALTH 2

#define PARAMETER_ERROR -1
#define GET_DNS_SERVER_IP_ERROR -2
#define QUARY_SEND_ERROR -3
#define RESPONSE_RECV_ERROR -5
#define TCP_CONNECT_ERROR -4
#define SOCKET_ERROR -6

int main(int argc, char **argv)
{
	int result;
	result = dns_health_check("www.baidu.com", "A", "UDP", "53");
	switch(result)
	{
		case DNS_SERVER_HEALTH:
			printf("DNS_SERVER_HEALTH\n");	break;
		case DNS_SERVER_NOT_HEALTH :          
			printf("DNS_SERVER_NOT_HEALTH\n");break;  
		case PARAMETER_ERROR :                 
			printf("PARAMETER_ERROR\n");break;
		case GET_DNS_SERVER_IP_ERROR :          
			printf("GET_DNS_SERVER_IP_ERROR\n");break;
		case QUARY_SEND_ERROR :                
			printf("QUARY_SEND_ERROR\n");break;
		case RESPONSE_RECV_ERROR :              
			printf("RESPONSE_RECV_ERROR\n");break;
		case TCP_CONNECT_ERROR :                
			printf("TCP_CONNECT_ERROR\n");break;
		case SOCKET_ERROR :                     
			printf("SOCKET_ERROR\n");break;	
	}
	return 0;
}