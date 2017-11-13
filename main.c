//
//  main.c
//  NS-HW3
//
//  Created by Ritu Prajapati on 10/29/17.
//  Copyright © 2017 Ritu Prajapati. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <netdb.h>
#include <netinet/in.h>

#include <openssl/rand.h>
#include <openssl/aes.h>

#include <string.h>
#include <fcntl.h>
#include <pthread.h>

#define client 1
#define server 2
#define BUFFER_SIZE 4096

typedef struct {
    int file_dc;
    unsigned char *key;
    struct sockaddr_in address;
} new_thread;

typedef struct {
    unsigned int num;
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char ecount[AES_BLOCK_SIZE];
} CTR_128;

typedef struct data{
    unsigned char buffer[BUFFER_SIZE];
    struct data *next;
}dataL;
/******************************************************************************/
/*  INIT CTR_128                                                              */
/******************************************************************************/

void init_ctr(CTR_128 *state, const unsigned char iv[16])
{
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);
    memset(state->ecount+8, 0, 8);
    memcpy(state->iv, iv, 16);
}

/******************************************************************************/
/*  gen_key                                                                   */
/******************************************************************************/

unsigned char* gen_key(char* file)
{
    FILE *fptr = fopen(file, "rb");
    long len;
    unsigned char *buff = NULL;
    
    if(fptr == NULL){
        fprintf(stderr, "Error - Cannot open key file\n");
        return NULL;
    }
    
    fseek(fptr, 0, SEEK_END);
    len = ftell(fptr);
    fseek(fptr, 0, SEEK_SET);
    buff = malloc(len);
    
    if(buff)
    {
        fscanf(fptr, "%s", buff);
    }
    fclose (fptr);
    return buff;
}

/******************************************************************************/
/*  Read from client and write to ssh_server                                  */
/******************************************************************************/


int readClient_writeSsh(int ssh_fd, int sock_FD, new_thread *thread_p, AES_KEY aesKey){
    unsigned char buffer[BUFFER_SIZE], buffer2[BUFFER_SIZE];
    bzero(buffer, BUFFER_SIZE);
    bzero(buffer2, BUFFER_SIZE);
    int read_status, send_status;
    unsigned char iv[8];
    CTR_128 ctr_state;
    int32_t read = 0;
    int to_read;
    int total_bytes, next_bytes;
    while((read_status = recv(sock_FD, &read, sizeof(read), MSG_DONTWAIT)) >= 0){
	
	if(read_status == 0){
            fprintf(stderr, "Client closed conection\n");
            return -1;
        }
	to_read = ntohl(read);
	if(to_read < 8){
        	fprintf(stderr, "Packet length smaller than 8\n");
        	close(sock_FD);
        	return -1;
         }
	total_bytes = 0;
	while(total_bytes < to_read){
                next_bytes = recv(sock_FD, buffer2, to_read-total_bytes, MSG_DONTWAIT);
                if(next_bytes < 0) continue;
                memcpy(buffer + total_bytes, buffer2, next_bytes);
                total_bytes += next_bytes;
            }
	
        memcpy(iv, buffer, 8);
        unsigned char decryption[total_bytes-8];
        init_ctr(&ctr_state, iv);
        AES_ctr128_encrypt(buffer+8, decryption, total_bytes-8, &aesKey, ctr_state.iv, ctr_state.ecount, &ctr_state.num);
        send_status = send(ssh_fd, decryption, total_bytes-8, MSG_NOSIGNAL);
    }
    
    return 1;
}
/******************************************************************************/
/*  Read from ssh and write to client                                  */
/******************************************************************************/

int readSsh_writeClient(int ssh_fd, int sock_FD, new_thread *thread_p, AES_KEY aesKey){
    
    unsigned char buffer[BUFFER_SIZE];
    bzero(buffer, BUFFER_SIZE);
    unsigned char buffer2[BUFFER_SIZE];
    bzero(buffer2, BUFFER_SIZE);
    int read_status, send_status, next_bytes, total_bytes;
    unsigned char iv[8];
    CTR_128 ctr_state;
    int32_t length;
    while((read_status = recv(ssh_fd, buffer, BUFFER_SIZE-8,MSG_DONTWAIT)) >= 0){
        
        if(read_status == 0){
            fprintf(stderr, "Server closed the connection\n");
            return -1;
        }
        
        length = htonl(read_status+8);
        send_status = send(sock_FD, &length, sizeof(length), MSG_NOSIGNAL);
        total_bytes = read_status;
        
        if(!RAND_bytes(iv, 8)) {
            fprintf(stderr, "Error - Generating IV\n");
            exit(1);
        }
        char *tmp_data = (char*)malloc(total_bytes + 8);
        memcpy(tmp_data, iv, 8);
        unsigned char encryption[total_bytes];
        init_ctr(&ctr_state, iv);
        AES_ctr128_encrypt(buffer, encryption, total_bytes, &aesKey, ctr_state.iv, ctr_state.ecount, &ctr_state.num);
        memcpy(tmp_data+8, encryption, total_bytes);
        send_status = send(sock_FD, tmp_data, total_bytes + 8, MSG_NOSIGNAL);
        free(tmp_data);
    }
    return 1;
}

/******************************************************************************/
/*  process_S_thread                                                          */
/******************************************************************************/

void* process_S_thread(void *ptr)
{
    int ssh_fd;
    unsigned char buffer[BUFFER_SIZE];
    bzero(buffer, BUFFER_SIZE);
    
    if(!ptr){
        fprintf(stderr, "Invalid Thread\n");
        pthread_exit(0);
    }
    
    new_thread *thread_p = (new_thread *)ptr;
    struct sockaddr_in sshAddr = thread_p->address;
    int sock_FD = thread_p->file_dc;
    unsigned char *ED_key = thread_p->key;
    ssh_fd = socket(AF_INET, SOCK_STREAM, 0);
    
    //attempt to make a connection on a socket
    int connect_status = connect(ssh_fd, (struct sockaddr *)&sshAddr, sizeof(sshAddr));
    
    if(connect_status < 0){
        fprintf(stderr, "Error in Establishing a new ssh connection on socket\n");
        pthread_exit(0);
    }
    else
        fprintf(stderr, "New SSH Connection established\n");
    
    //Get the file status flags and file access modes, for the file description associated with sock_FD.
    int status_flags = fcntl(sock_FD, F_GETFL);
    
    if(status_flags == -1){
        fprintf(stderr, "Error capturing the FD status flags - Closing Connection\n");
        close(sock_FD);
        close(ssh_fd);
        free(thread_p);
        pthread_exit(0);
    }
    
    //Set the file status flags for sock_FD
    fcntl(sock_FD, F_SETFL, status_flags | O_NONBLOCK);
    
    //Get the file status flags and file access modes, for the file description associated with ssh_FD.
    status_flags = fcntl(ssh_fd, F_GETFL);
    
    if (status_flags == -1) {
        fprintf(stderr, "Error capturing the file status flags - Closing Connection\n");
        close(sock_FD);
        close(ssh_fd);
        free(thread_p);
        pthread_exit(0);
    }
    
    fcntl(ssh_fd, F_SETFL, status_flags | O_NONBLOCK);
    AES_KEY aesKey;
    int aes_set_status = AES_set_encrypt_key(ED_key, 128, &aesKey);
    if(aes_set_status < 0){
        fprintf(stderr, "AES_set_encrypt_key error!\n");
        exit(1);
    }
    
    while(1){
        if(readClient_writeSsh(ssh_fd, sock_FD, thread_p, aesKey) == -1)
            break;
        
        if(readSsh_writeClient(ssh_fd, sock_FD, thread_p, aesKey) == -1)
            pthread_exit(0);
    }
    
    fprintf(stderr, "Exiting thread!\n");
    close(sock_FD);
    close(ssh_fd);
    free(thread_p);
    pthread_exit(0);
}


/******************************************************************************/
/*  proxyServer                                                               */
/******************************************************************************/

int proxyServer(u_char *key, struct sockaddr_in sshAddr, struct sockaddr_in socketAddr)
{
    
    struct sockaddr_in  address;
    socklen_t length = sizeof(address);
    new_thread *th;
    pthread_t thread;
    int file_dc, next_file_dc, bind_res;
    
    //create an endpoint for communication
    file_dc = socket(AF_INET, SOCK_STREAM, 0);
    
    if(file_dc < 0){
        fprintf(stderr, "Could not open a new socket for Server-Proxy\n");
        return -1;
    }
    //bind a name to a socket
    bind_res = bind(file_dc, (struct sockaddr*) &socketAddr, sizeof(socketAddr));
    
    if(bind_res < 0){
        fprintf(stderr, "Unable to bind socket file descriptor with Socket address");
        return -1;
    }
    
    //Start listening on Socket
    listen(file_dc, 5);
    
    while(1){
        
        th = (new_thread *)malloc(sizeof(new_thread));
        
        //accept a new connection on a socket
        next_file_dc = accept(file_dc, (struct sockaddr *) &address, &length);
        
        if(next_file_dc < 0){
            fprintf(stderr, "Error in Accept - New Thread\n");
            free(th);
            return -1;
        }
        th->file_dc = next_file_dc;
        th->address = sshAddr;
        th->key = key;
        
        pthread_create(&thread, 0, process_S_thread, (void *)th);
        pthread_detach(thread);
    }
    return 0;
}

/******************************************************************************/
/*  ProxyClient                                                               */
/******************************************************************************/

int proxyClient(struct sockaddr_in server_addr, unsigned char *key)
{
    unsigned char buffer[BUFFER_SIZE];
    unsigned char buffer2[BUFFER_SIZE];
    
    int sock_file_dc;
    sock_file_dc = socket(AF_INET, SOCK_STREAM, 0);
    if(sock_file_dc < 0){
        fprintf(stderr, "ERROR opening Client socket\n");
        return 1;
    }
    
    int connect_status = connect(sock_file_dc, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if(connect_status < 0){
        fprintf(stderr, "Error establishing a new connection to Pbproxy Server\n");
        return 1;
    }
    
    fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
    
    int status_flags = fcntl(sock_file_dc, F_GETFL);
    
    if(status_flags == -1) {
        fprintf(stderr, "Flag Error\n");
        close(sock_file_dc);
        return 1;
    }
    
    fcntl(sock_file_dc, F_SETFL, status_flags | O_NONBLOCK);
    bzero(buffer, BUFFER_SIZE);
    CTR_128 ctr_state;
    unsigned char iv[8];
    AES_KEY aesKey;
    
    int aes_set_status = AES_set_encrypt_key(key, 128, &aesKey);
    if(aes_set_status < 0){
        fprintf(stderr, "Error - AES_set_encrypt_key\n");
        return 1;
    }
    
    int read_bytes, next_bytes, total_bytes;
    
    while(1){
     
        int32_t length;
	int send_status;
        while((read_bytes = read(STDIN_FILENO, buffer, BUFFER_SIZE-8)) > 0){

            length = htonl(read_bytes+8);    
	    send_status = send(sock_file_dc, &length, sizeof(length), MSG_NOSIGNAL);

            if(!RAND_bytes(iv, 8)){
                fprintf(stderr, "Unable to generate Initializing Vector\n");
                return 1; 
            }
            unsigned char encrypt[read_bytes];
            char *data = (char*)malloc(read_bytes + 8);
            memcpy(data, iv, 8);
            init_ctr(&ctr_state, iv);
            AES_ctr128_encrypt(buffer, encrypt, read_bytes, &aesKey, ctr_state.iv, ctr_state.ecount, &ctr_state.num);
            memcpy(data + 8, encrypt, read_bytes);
            send_status = send(sock_file_dc, data, read_bytes + 8, 0);
	    //fprintf(stderr, "Bytes sent to server: %d", send_status);
            free(data);
        }
        
        int32_t read = 0;
        int to_read;
        while(recv(sock_file_dc, &read, sizeof(read), MSG_DONTWAIT) > 0){
            
            to_read = ntohl(read);
            if(to_read < 8){
                fprintf(stderr, "Packet length smaller than 8\n");
                close(sock_file_dc);
                return 1;
            }
            
            total_bytes = 0;
            //usleep(100);
            while(total_bytes < to_read){
                next_bytes = recv(sock_file_dc, buffer2, to_read-total_bytes, MSG_DONTWAIT);
                if(next_bytes < 0) continue;
                memcpy(buffer + total_bytes, buffer2, next_bytes);
                total_bytes += next_bytes;
            }
            
            memcpy(iv, buffer, 8);
            unsigned char decrypt[total_bytes - 8];
            init_ctr(&ctr_state, iv);
            AES_ctr128_encrypt(buffer + 8, decrypt, total_bytes - 8, &aesKey, ctr_state.iv, ctr_state.ecount, &ctr_state.num);
            write(STDOUT_FILENO, decrypt, total_bytes - 8);
        }
    }
    return 0;

}


/******************************************************************************/
/*  Main                                                                      */
/******************************************************************************/

int main(int argc, const char * argv[]) {
    int p, sPort = 0, dPort = 0;
    const char *dAddr_url = NULL;
    unsigned char *key = NULL;
    int party = client;
    
    struct sockaddr_in socket, ssh; 
    struct hostent *host;
    
    bzero(&socket, sizeof(socket));
    bzero(&ssh, sizeof(ssh));
    
    
    while((p = getopt(argc, (char * const *)argv, "k:l:")) != -1) {
        switch (p){
            case 'l':
                party = server;
                sPort = (int)strtol(optarg, NULL, 10);
                break;
            case 'k':
                key = gen_key(optarg);
                
                if(!key){
                    fprintf(stderr, "KeyFile Invalid\n");
                    return 0;
                }
                break;
            default:
                fprintf(stderr, "Invalid option\n");
                return 1;
        }
    }
    
    if(optind+2 != argc){
        fprintf(stderr, "Provide all the necessary arguments\n");
        return 1;
    }
    
    if(!key){
        fprintf(stderr, "keyfile is necessary for a secure connection\n");
        return 1;
    }
    
    dAddr_url = argv[optind];
    
    const char *tmp = argv[optind + 1];
    dPort =  atoi(tmp);
    host = gethostbyname(dAddr_url);
    if(!host){
        fprintf(stderr, "Host name could not be resolved\n");
        return 1;
    }
    if(party == server){
        
        socket.sin_family = AF_INET;
        socket.sin_addr.s_addr = htons(INADDR_ANY);
        socket.sin_port = htons(sPort);
        
        bzero((char *) &ssh, sizeof(ssh));
        bcopy((char *)host->h_addr, (char *)&ssh.sin_addr.s_addr, host->h_length);
        ssh.sin_family = AF_INET;
        ssh.sin_port = htons(dPort);
        
        printf("PbProxy Server started\n");
        proxyServer(key, ssh, socket);
    }
    else{
        socket.sin_family = AF_INET;
        socket.sin_addr.s_addr = ((struct in_addr*)(host->h_addr))->s_addr;
        socket.sin_port = htons(dPort);
        printf("PbProxy Client Started\n");
        proxyClient(socket, key);
    }
    free(key);
    return 0;
}


