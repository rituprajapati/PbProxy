

Network Security Homework-3 Report
Name: Ritu Prajapati
Sbu ID: 111485620

==================================================================================================================================================================================


1. Test Environments

Ubuntu 16.04.3 LTS (Linux 4.4.0-97-generic x86_64)
Ubuntu 16.04.2 LTS (Linux 4.4.0-81-generic x86_64)
Ubuntu 15.04 (Linux 3.19.0-84-generic x86_64)



2. Compiler and its version

gcc version 5.4.0 20160609
gcc version 4.9.2



3. Command lines to run the application

3.1) #make


3.2) ssh connection:

server: ./pbproxy -l <port> -k mykey localhost 22
Client: ssh -o “ProxyCommand ./pbproxy -k mykey <server_ip> <port>” localhost

<server_ip> name of the server running pbproxy server
<port> any random port number(should be same in client and server <port> value)
To close the connection: type “exit” on client side and hit enter(standard method of closing ssh connection).


3.3) nc connection

Server: 
terminal 1: nc -l -p <port_1> 
terminal 2: ./pbproxy -l <port_2> -k mykey localhost <port_1>

Client: ./pbproxy -k mykey <server_IP> <port_2>

<port_1> <port_2> any two different random ports
To close the connection: press ctrl+C on client side (Note: this will also close the nc on terminal 1)


3.4) sftp Connection

server: ./pbproxy -l <port> -k mykey localhost 22
Client: sftp -o “ProxyCommand ./pbproxy -k mykey <server_ip> <port>” localhost


<server_ip> name of the server running pbproxy server
<port> any random port number(should be same in client and server <port> value)
To close the connection: type “bye” on client side and hit enter(standard method of closing sftp connection).


4. Design of pbproxy


PbProxy application is developed for the purpose of adding another layer of protection to publicly accessible network services. Client will connect to pbproxy instead of connecting directly to a TCP service. 


Basic workflow of pbproxy:

4.1) Server starts pbproxy with the command such as “./pbproxy -l <port> -k mykey localhost 22”, here -k option tells pbproxy that the name of file where the key is “mykey”. If -k option is not mentioned in the command line, pbproxy will exit as key is important for secure communication. -l option tells pbproxy that is has to listen on port <port> and accept any connection coming to this port. Localhost and “22” tells the TCP service to which pbproxy has to connect client to.

4.2) Client start its pbproxy using command like “ssh -o “ProxyCommand ./pbproxy -k mykey <server_ip> <port>” localhost”, the same rules apply here for key hare as in the server. The <server> and <port> tells pbproxy the socket of server to connect. Pbproxy uses connect() function to establish a connection to the server.

4.3) Server runs in a loop to keep listening if there is new connection on the socket. If there is a connection pbproxy server accepts the connection using accept() function. Pbproxy server now will start a new thread to handle the communication over this connection independently. Pbproxy allows a maximum of 5 connection requests in the queue. If the queue is already full the client will receive an error.

4.4) Client -> server

- Client send the data to pbproxy application through STDIN.
- Pbproxy receives the data using recv() function. 
- pbProxy calculate the length of data collected and send it to server.
- Pbproxy generates a random IV and attach this at the beginning of the data.
- pbProxy now encrypt the data using AES_ctr128_encrypt()/openssl.
- Using send() function pbproxy will send the data to PbProxy server.
- Sevrer keeps a loop to check if there is data on the socket connection. It will first read the length of the packet sent from the client and initialize its to_read parameter so that it reads exactly the same length of bytes sent by the clients. It will run in a while loop until data is received unto to_read.
- Pbproxy server now will extract the first 8 bytes of IV and use it to decrypt the rest of the data AES_ctr128_encrypt function.
- Pbproxy server sends the decrypted data to the TCP service.

4.5) Server -> client

- TCP service sends the data to pbproxy application through the established connection.
- Pbproxy receives the data using recv() function. 
- pbProxy calculate the length of data collected and send it to client application.
- pbProxy now encrypt the data using AES_ctr128_encrypt()/openssl.
- Pbproxy generates a random IV and attach this at the beginning of the encrypted data.
- Using send() function pbproxy server will send the data to PbProxy client.
- client keeps a loop to check if there is data on the socket connection. It will first read the length of the packet sent from the server and initialize its to_read parameter so that it reads exactly the same length of bytes sent by the server. It will run in a while loop until data is received upto to_read.
- Pbproxy client now will extract the first 8 bytes of IV and use it to decrypt the rest of the data AES_ctr128_encrypt function.
- Pbproxy server sends the decrypted data to STDOUT.



5. References

http://www.cs.dartmouth.edu/~campbell/cs50/socketprogramming.html

https://stackoverflow.com/questions/238603/how-can-i-get-a-files-size-in-c

https://stackoverflow.com/questions/9140409/transfer-integer-over-a-socket-in-c

http://stefan.buettcher.org/cs/conn_closed.html

https://stackoverflow.com/questions/13656702/sending-and-receiving-strings-over-tcp-socket-separately

http://www.geeksforgeeks.org/multithreading-c-2/
