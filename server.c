#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/select.h>
#include <unistd.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/time.h> 
#include <signal.h> 
#include <sys/socket.h> 
#include <sys/un.h> 
#include <sys/mman.h>

#define UNIX_DOMAIN "./tmp.sock"
#define MAX_SIZE 100

int read_fd_message(int sockfd, char *buf, int buflen, int *fds, int max_fds,      
                int *fd_num);
struct payload {
	int a;
	int b;
};

struct mymsg {
	int size;
	struct payload pl;
	int fd[2];
};

void main()
{
	socklen_t clt_addr_len; 
	char *addr;
	int listen_fd; 
	int com_fd; 
	int ret=0; 
	int i; 
	char buf_r[20];
	
	int len, fd_num, size; 
	struct sockaddr_un clt_addr; 
	struct sockaddr_un srv_addr; 

	struct mymsg mm;
/*
	struct msghdr msg;
	msg.msg_name = NULL;
	struct iovec io;
	io.iov_base = buf;
	io.iov_len = MAX_SIZE;
	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
*/

	listen_fd=socket(AF_UNIX,SOCK_STREAM,0); 
	if(listen_fd<0)	{ 
		printf("cannot create listening socket"); 
		return;
	} else {
		srv_addr.sun_family=AF_UNIX; 
		strncpy(srv_addr.sun_path,"/home/euler/docker/src/test/iovec-test/tmp.sock",sizeof(srv_addr.sun_path)-1); 
		ret=bind(listen_fd,(struct sockaddr*)&srv_addr,sizeof(srv_addr.sun_family)+strlen(srv_addr.sun_path)); 
		if(ret==-1) { 
			printf("cannot bind server socket"); 
			close(listen_fd); 
			return;
		} 
		ret=listen(listen_fd,128); 
		if(ret==-1) { 
			printf("cannot listen the client connect request"); 
			close(listen_fd); 
			return; 
		} 
		// chmod(UNIX_DOMAIN,00777);//设置通信文件权限
		while(1) {
			len=sizeof(clt_addr); 
			//com_fd=accept(listen_fd,(struct sockaddr*)&clt_addr,&len); 
			com_fd=accept(listen_fd, NULL, NULL); 
			if(com_fd<0) { 
				printf("cannot accept client connect request"); 
				close(listen_fd); 
				return;
			} 

			// XXX:
			ret=read_fd_message(com_fd, (char *)&mm, 4, mm.fd, 2, &fd_num);
			if (ret<=0) {
				printf("read fd message failed\n");
				close(com_fd);
				close(listen_fd);
				return;
			}
			printf("read fd message ret is %d, payload size is %d\n", ret, mm.size);
			printf("get msg --fdnum is %d, fd0 is %d, fd1 is %d\n",fd_num, mm.fd[0], mm.fd[1]);
			ret = read(com_fd, &mm.pl, mm.size);	
			if (ret<=0) {
				printf("read msg payload failed\n");
				close(com_fd);
				close(listen_fd);
				return;
			}
			printf("get msg -- a is %d, b is %d\n", mm.pl.a, mm.pl.b);
			
			// XXX:
			if (fd_num != 2) {
				printf("recv fd num not match,get %d\n", fd_num);
				return;
			}

			/*
			addr = mmap(NULL, 7, PROT_READ,  MAP_PRIVATE, mm.fd[0], 0);
			printf("file1 content -- %s, addr is %p\n", addr, &addr);
			*/
			void *result = mmap(0, 10, PROT_READ | PROT_WRITE, MAP_SHARED, mm.fd[0], 0);
			printf("fd 0 get string %s\n", (char *)result);
			void *result2 = mmap(0, 10, PROT_READ | PROT_WRITE, MAP_SHARED, mm.fd[1], 0);
			printf("fd 1 get string %s\n", (char *)result2);

			/*
			lseek(mm.fd[0], 0, SEEK_SET);
			len = read(mm.fd[0], buf_r, 6);
			if (len < 0) {
				printf("read file content from msg fd failed\n");
				close(mm.fd[0]);
				close(com_fd);
				close(listen_fd);
				return;
			}
			printf("file1 content -- %s\n", buf_r);
			lseek(mm.fd[1], 0, SEEK_SET);
			len = read(mm.fd[1], buf_r, 6);
			if (len < 0) {
				printf("read file content from msg fd failed\n");
				close(mm.fd[1]);
				close(com_fd);
				close(listen_fd);
				return;
			}
			printf("file2 content -- %s\n", buf_r);
			*/
		}
	}
}
	
int read_fd_message(int sockfd, char *buf, int buflen, int *fds, int max_fds,      
                int *fd_num)                                                   
{                                                                              
        struct iovec iov;                                                      
        struct msghdr msgh;                                                    
        char control[CMSG_SPACE(max_fds * sizeof(int))];                       
        struct cmsghdr *cmsg;                                                  
        int got_fds = 0;                                                       
        int ret;                                                               
                                                                               
        *fd_num = 0;                                                           
                                                                               
        memset(&msgh, 0, sizeof(msgh));                                        
        iov.iov_base = buf;                                                    
        iov.iov_len  = buflen;                                                 
                                                                               
        msgh.msg_iov = &iov;                                                   
        msgh.msg_iovlen = 1;                                                   
        msgh.msg_control = control;                                            
        msgh.msg_controllen = sizeof(control);                                 
                                                                               
        ret = recvmsg(sockfd, &msgh, 0);                                       
        if (ret <= 0) {                                                        
                printf("recvmsg failed\n");                
                return ret;                                                    
        }                                                                      
                                                                               
        if (msgh.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {                       
                printf("truncted msg\n");                  
                return -1;                                                     
        }                                                                      
                                                                               
        for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg != NULL;                        
                cmsg = CMSG_NXTHDR(&msgh, cmsg)) {                             
                if ((cmsg->cmsg_level == SOL_SOCKET) &&                        
                        (cmsg->cmsg_type == SCM_RIGHTS)) {                     
                        got_fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
                        *fd_num = got_fds;                                     
                        memcpy(fds, CMSG_DATA(cmsg), got_fds * sizeof(int));   
                        break;                                                 
                }                                                              
        }                                                                      
                                                
        /* Clear out unused file descriptors */ 
        while (got_fds < max_fds)               
                fds[got_fds++] = -1;            
                                                
        return ret;                             
}                                               
