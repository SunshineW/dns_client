a simple dns client send a quary message and explain response

/* 已测试平台：centos6.7 64位环境 */

函数：dns_health_check(char *server_ip, char *domain, char *type, char *proto, char *port)

参数：	server_ip	:	要检查的服务器ip地址
		domain		:	要查询的域名
		type		:	要查询的域名类型 A NS NAME MX SOA AAAA TXT
		proto		：	通过什么方式查询 TCP或者UDP
		port		:	dns服务器端口

返回值：DNS_SERVER_HEALTH 1      	服务器健康 
		DNS_SERVER_NOT_HEALTH 2		服务器不健康
        
        PARAMETER_ERROR -1			参数有误
        QUARY_SEND_ERROR -3			发送查询包错误
        RESPONSE_RECV_ERROR -5		接受响应超时
        TCP_CONNECT_ERROR -4		TCP CONNECT失败
        SOCKET_ERROR -6				创建套接字失败

		
注意：参数全部以字符串形式传入
	  eg:result = dns_health_check("127.0.0.1", "www.baidu.com", "A", "UDP", "53");
	     result = dns_health_check("114.114.114.114", "163.com", "MX", "TCP", "53");