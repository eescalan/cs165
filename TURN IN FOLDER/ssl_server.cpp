//----------------------------------------------------------------------------
// File: ssl_server.cpp
// Description: Implementation of an SSL-secured server that performs
//              secure file transfer to a single client over a single
//              connection.
//----------------------------------------------------------------------------
#include <string>
#include <time.h>
#include <sstream>
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>

#include "utils.h"

//-----------------------------------------------------------------------------
// Function: main()
//-----------------------------------------------------------------------------
int main(int argc, char** argv)
{
    //-------------------------------------------------------------------------
    // initialize
	ERR_load_crypto_strings();
	SSL_load_error_strings();
    SSL_library_init();
    
    setbuf(stdout, NULL); // disables buffered output

	// Handle commandline arguments
	// Useage: client -server serveraddress -port portnumber filename
	if (argc < 2)
	{
		printf("Useage: server portnumber\n");
		exit(EXIT_FAILURE);
	}
	char* port = argv[1];

	printf("------------\n");
	printf("-- SERVER --\n");
	printf("------------\n");

    //-------------------------------------------------------------------------
	// 1. Allow for a client to establish an SSL connection
	printf("1. Allowing for client SSL connection...\n");
		printf("SERVER STEP 1: WAIT FOR CLIENT CONNECTION REQUEST AND ESTABLISH\n");
		/*		Wait for client to request connection		*/

	// Setup DH object and generate Diffie-Helman Parameters
	DH* dh = DH_generate_parameters(128, 5, NULL, NULL);
	int dh_err;
	DH_check(dh, &dh_err);
	if (dh_err != 0)
	{
		printf("Error during Diffie-Helman parameter generation.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup server context
	SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_SINGLE_DH_USE);
	SSL_CTX_set_tmp_dh(ctx, dh);
	if (SSL_CTX_set_cipher_list(ctx, "ALL") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the BIO
	BIO* server = BIO_new(BIO_s_accept());
	BIO_set_accept_port(server, port);
	BIO_do_accept(server);

	// Setup the SSL
	SSL* ssl = SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	SSL_set_accept_state(ssl);
	SSL_set_bio(ssl, server, server);
	if (SSL_accept(ssl) <= 0)
	{
		printf("Error doing SSL_accept(ssl).\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	printf("DONE.\n");
	printf("    (Now listening on port: %s)\n", port);

    //-------------------------------------------------------------------------
	// 2. Receive a random number (the challenge) from the client
	printf("2. Waiting for client to connect and send challenge...\n");
		printf("SERVER STEP 2: RECEIVE ENCRYPTED CHALLENGE AND DECRYPT WITH PRIVATE KEY\n");
		/*		Decrypt the received challenge			*/
    
    //SSL_read
    string randomNumber="";

	FILE *pubfile = fopen("rsapublickey.pem", "r");
	RSA* pubkey = PEM_read_RSA_PUBKEY(pubfile, NULL, NULL, NULL);
    
    	unsigned char* buf = (unsigned char*)malloc(RSA_size(pubkey));
    	int bufsize = 128;
    		//printf("size of buf: %i\n", sizeof(buf));
	SSL_read(ssl, buf, bufsize);
		//for(int x = 0; x < bufsize; x++){
		//	printf("%c", buf[x]);
		//	randomNumber = randomNumber + buf[x];
		//}
	
    
	printf("DONE.\n");
	printf("    (Challenge: \"%i\")\n", buf[0]);
	

	FILE *privfile = fopen("rsaprivatekey.pem", "r");
	RSA* privkey = PEM_read_RSAPrivateKey(privfile, NULL, NULL, NULL);
	unsigned char* dec = (unsigned char*)malloc(RSA_size(privkey));
	
	if (RSA_private_decrypt(RSA_size(privkey), (unsigned char*)buf, (unsigned char*)dec, privkey, RSA_PKCS1_PADDING) == -1){
		printf("Failed decryption!\n");
		fprintf(stderr, "OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
		RSA_free(privkey);
		exit(EXIT_FAILURE);
	}
	
		printf("Decrypted value: %i\n", dec[0]);
	

    //-------------------------------------------------------------------------
	// 3. Generate the SHA1 hash of the challenge
	printf("3. Generating SHA1 hash...\n");
		printf("SERVER STEP 3: GENERATE HASH FROM CHALLENGE SHA1\n");
		/*		Hash un-encrypted challenged with SHA1			*/

	//BIO_new(BIO_s_mem());
	//BIO_write
	//BIO_new(BIO_f_md());
	//BIO_set_md;
	//BIO_push;
	//BIO_gets;
	
	int deChallenge = dec[0];
	stringstream ss;
	ss << deChallenge;
	string challengeNumber = ss.str();
		//string challengeNumber = "230";
		printf("hashing: %s\n", challengeNumber.c_str());
	
	unsigned char obuf[20];
	SHA1((unsigned char*)challengeNumber.c_str(), sizeof(challengeNumber.c_str()), obuf);
	
	printf("hash:\n");
	for (int i = 0; i < 20; i++){
		printf("%02x ", obuf[i]);
	}

    int mdlen=0;
	string hash_string = "";

	printf("SUCCESS.\n");
	//printf("    (SHA1 hash: \"%s\" (%d bytes))\n", hash_string.c_str(), mdlen);

    //-------------------------------------------------------------------------
	// 4. Sign the key using the RSA private key specified in the
	//     file "rsaprivatekey.pem"
	printf("4. Signing the key...\n");
		printf("SERVER STEP 4: SIGNING THE HASH WITH PRIVATE KEY\n");
		/*		Signing hash with private key for authentication client-side		*/
    //PEM_read_bio_RSAPrivateKey
    //RSA_private_encrypt
    
    //!!		SHA1 BUG; INCONSISTENT AT CLIENT
	
	unsigned char* signature = (unsigned char*)malloc(RSA_size(privkey));
    
	int siglen = RSA_private_encrypt(strlen((const char*)obuf), (unsigned char*)obuf, (unsigned char*)signature, privkey, RSA_PKCS1_PADDING);
	if (siglen == -1){
    		printf("Failed sign!\n");
		fprintf(stderr, "OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
	    	RSA_free(privkey);
		exit(EXIT_FAILURE);
	}

    printf("DONE.\n");
    printf("    (Signed key length: %d bytes)\n", siglen);
    printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)signature, siglen).c_str(), siglen);

    //-------------------------------------------------------------------------
	// 5. Send the signature to the client for authentication
	printf("5. Sending signature to client for authentication...\n");
		printf("SERVER STEP 5: SEND SIGNED HASH TO CLIENT\n");
		/*	Send hashed value to client for authentication		*/

	//BIO_flush
	//SSL_write
	SSL_write(ssl, signature, siglen);

    printf("DONE.\n");
    
    //-------------------------------------------------------------------------
	// 6. Receive a filename request from the client
	printf("6. Receiving file request from client...\n");
		printf("SERVER STEP 6: RECEIVING FILE REQUEST FROM CLIENT\n");
		/*		Get the name of the requested file from client			*/

    //SSL_read
    char file[BUFFER_SIZE];
    memset(file,0,sizeof(file));
    printf("RECEIVED.\n");
    
    unsigned char* filename = (unsigned char*)malloc(16);
    SSL_read(ssl, filename, 16);
    	//printf("filename: %s\n", filename);
    	
    //printf("    (File requested: \"%s\"\n", file);
    printf("    (File requested: \"%s\"\n", filename);

    //-------------------------------------------------------------------------
	// 7. Send the requested file back to the client (if it exists)
	printf("7. Attempting to send requested file to client...\n");
		printf("SERVER STEP 7: SEND ENTIRE FILE TO CLIENT\n");
		/*		Send entire file to client		*/

	PAUSE(2);
	//BIO_flush
	//BIO_new_file
	//BIO_puts(server, "fnf");
    //BIO_read(bfile, buffer, BUFFER_SIZE)) > 0)
	//SSL_write(ssl, buffer, bytesRead);

	BIO* bp;
	bp = BIO_new_file((const char*)filename, "r");
	
	
	int fileSize = BIO_read(bp, file, BUFFER_SIZE); 
	//int fileSize = 0;
	//while(BIO_read(bp, file, 1) > 0){
	//	fileSize++;
	//}
		//printf("filesize: %i\n", fileSize);

	
    //int bytesSent=0;
    
    	SSL_write(ssl, file, fileSize);
    
    printf("SENT.\n");
    //printf("    (Bytes sent: %d)\n", bytesSent);
	printf("    (Bytes sent: %d)\n", fileSize);

    //-------------------------------------------------------------------------
	// 8. Close the connection
	printf("8. Closing connection...\n");
		printf("SERVER STEP 8: CLOSING CONNECTION\n");
		/*		Closing server SSL connection		*/

	//SSL_shutdown
	SSL_shutdown(ssl);
    //BIO_reset
    BIO_reset(bp);
    printf("DONE.\n");

    printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");
	
    //-------------------------------------------------------------------------
	// Freedom!
    
	BIO_free_all(server);
	return EXIT_SUCCESS;
}
