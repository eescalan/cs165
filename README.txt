README
1) Compile with provided makefile, then separate 
client and server executables in two folders.
2) Organize as follows
-Client folder:
	-client
	-rsapublickey.pem
	-rsaprivatekey.pem (if testing decryption)
		-testing purposes only!
-Server folder:
	-server
	-rsaprivatekey.pem
	-rsapublickey.pem
	-Escalante.txt (or other test file)
3) Run
$	client [ip]:[port] [file name]
$	server [port]

NOTES
-Assumed files are text files and will open with
gedit.
-Client cannot work in same folder as server.
The client will obviously open and write a blank 
file of the same name that is requested, deleting the
original file (!).
If same-folder configuration is desired, uncomment
line 286-287 and comment out 288. Output file will
be "test.txt" instead.
-File size limit is 1024 bytes (as defined BUFFER_SIZE).

KNOWN BUG(S)
-Generated hash from client is inconsistent/random after 
running client executable for the first time. However, 
server generated hash is always correct/consistent.
In other words, client generated hash is only correct on 
fresh, un-run, first-run client executable. For this reason,
authentication check is always assumed true, but it is 
implemented as comments for testing's sake.
If want to check authentication everytime, then deletion 
of client executable and recompiling is necessary, along
with uncommenting if-else authentication check at lines 
232-235 of client.cpp.
Interstingly, this did not occur over NX from a remote 
machine; occurred in lab machines, so bug was caught late.
