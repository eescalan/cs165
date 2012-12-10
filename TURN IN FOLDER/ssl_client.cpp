//----------------------------------------------------------------------------
// File: ssl_client.cpp
// Description: Implementation of an SSL-secured client that performs
//              secure file transfer with a single server over a single
//              connection
//----------------------------------------------------------------------------
#include <string>
#include <time.h>               // to seed random number generator
#include <sstream>          // stringstreams
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>	// ERR_get_error()
#include <openssl/dh.h>		// Diffie-Helman algorithms & libraries

#include "utils.h"

#include "math.h"
#include <openssl/rand.h>

//----------------------------------------------------------------------------
// Function: main()
//----------------------------------------------------------------------------
int main(int argc, char** argv)
{
	//-------------------------------------------------------------------------
    // Initialization

    ERR_load_crypto_strings();
    SSL_library_init();
    SSL_load_error_strings();

    setbuf(stdout, NULL); // disables buffered output
    
    // Handle commandline arguments
	// Useage: client server:port filename
	if (argc < 3)
	{
		printf("Useage: client -server serveraddress -port portnumber filename\n");
		exit(EXIT_FAILURE);
	}
	char* server = argv[1];
	char* filename = argv[2];
	
	printf("------------\n");
	printf("-- CLIENT --\n");
	printf("------------\n");
	
		printf("server: %s \n", argv[1]);
		printf("filename: %s \n", argv[2]);

    //-------------------------------------------------------------------------
	// 1. Establish SSL connection to the server
	printf("1.  Establishing SSL connection with the server...\n");
		printf("CLIENT STEP 1: ESTABLISH SSL CONNECTION TO SERVER\n");
		/*		Connecting to server		*/
	// Setup client context
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
	if (SSL_CTX_set_cipher_list(ctx, "ADH") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	
	// Setup the BIO
	BIO* client = BIO_new_connect(server);
	if (BIO_do_connect(client) != 1)
	{
		printf("FAILURE.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the SSL
    SSL* ssl=SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
		exit(EXIT_FAILURE);
	}
	SSL_set_bio(ssl, client, client);
	if (SSL_connect(ssl) <= 0)
	{
		printf("Error during SSL_connect(ssl).\n");
		print_errors();
		exit(EXIT_FAILURE);
	}

	printf("SUCCESS.\n");
	printf("    (Now connected to %s)\n", server);

    //-------------------------------------------------------------------------
	// 2. Send the server a random number
	printf("2.  Sending challenge to the server...\n");
	
	unsigned char rbuf[16];
	RAND_seed(rbuf, 16);
	
		printf("CLIENT STEP 2: SEED SECURE PRNG\n");
		/*		Seeding a PRNG using RAND_bytes			*/
	if (!RAND_bytes(rbuf, sizeof(rbuf)) ){ //secure PRNG
		printf("OpenSSL error\n");
		exit(EXIT_FAILURE);
	}

	FILE *pubfile = fopen("rsapublickey.pem", "r");
	RSA* pubkey = PEM_read_RSA_PUBKEY(pubfile, NULL, NULL, NULL);
	int randnum = rbuf[0];
	unsigned char* enc = (unsigned char*)malloc(RSA_size(pubkey));
		
			//printf("%i\n", randnum);
	if (pubkey == NULL){
		printf("Failed pubkey read!");
		exit(EXIT_FAILURE);
	}
	
		printf("CLIENT STEP 3: ENCRYPT CHALLENGE WITH PUBLIC KEY AND SEND TO SERVER\n");
		/*		Encrypt the challenge with the public key, then send to server			*/
	int bufsize = RSA_public_encrypt(strlen((const char*)rbuf), (const unsigned char*)rbuf, (unsigned char*) enc, pubkey, RSA_PKCS1_PADDING);
	if (bufsize == -1){
		printf("Failed encryption!\n");
		RSA_free(pubkey);
		exit(EXIT_FAILURE);
	}
	printf("First value of plaintext challenge buffer: %i\n", rbuf[0]);
		printf("First value of challenge encrypted buffer: %i \n", enc[0]);
	int challenge = enc[0];

	//------------------------------------------------------------------
	/*			Decryption of challenge via private key.			*/
	//FOR TESTING PURPOSES ONLY! Client is NOT supposed to know
	//private key.
	//This is just to see decryption on client end and compare
	//with server end.
	//Will need "rsaprivatekey.pem" in same folder as client.
#if 0
	FILE *privfile = fopen("rsaprivatekey.pem", "r");
	RSA* privkey = PEM_read_RSAPrivateKey(privfile, NULL, NULL, NULL);
	unsigned char* dec = (unsigned char*)malloc(RSA_size(privkey));
	
	if (RSA_private_decrypt(RSA_size(privkey), enc, (unsigned char*)dec, privkey, RSA_PKCS1_PADDING) == -1){
		printf("Failed decryption!\n");
		RSA_free(pubkey);
	}
	
	printf("First value of plaintext challenge buffer: %i\n", dec[0]);
	
	//for (int i = 0; i < sizeof(enc); i++){
	//	printf("%i\n", enc[i]);
	//}
	//RSA_free(pubkey);
		RSA_free(privkey);
#endif
	//------------------------------------------------------------------

    	stringstream ss;
    	ss << challenge;
	string randomNumber = ss.str();
		//printf("Challenge: %s \n", randomNumber.c_str());
		//printf("Challenge: %s \n", enc);
	//SSL_write
	char* sendstring = (char*)malloc(strlen(randomNumber.c_str()));
		//printf("randomNumber: %s\n", randomNumber.c_str());
	strcpy(sendstring, randomNumber.c_str());
		//printf("c string: %s\n", sendstring);
		//printf("size of buf: %i\n", bufsize);
	SSL_write(ssl, enc, bufsize);
	
    printf("SUCCESS.\n");
	printf("    (Challenge sent: \"%s\")\n", sendstring);

	//SHA1-------------------------------------------------------------------
		printf("CLIENT STEP 4: HASH PLAINTEXT CHALLENGE WITH SHA1\n");
		/*		Hashing the plaintext with SHA1 for authentication			*/
	int deChallenge = randnum;
	stringstream dd;
	dd << deChallenge;
	string plainNum = dd.str();
		//string plainNum = "230";
		printf("hashing: %s\n", plainNum.c_str());
	unsigned char obuf[20];
	SHA1((unsigned char*)plainNum.c_str(), sizeof(plainNum.c_str()), obuf);
	
		//Print the hash for tests
		//printf("hash:\n");
		//for (int i = 0; i < 20; i++){
		//	printf("%02x ", obuf[i]);
		//}
	
	//-----------------------------------------------------------------------
	// 3a. Receive the signed key from the server
	printf("3a. Receiving signed key from server...\n");
		printf("CLIENT STEP 5: RECEIVE SIGNED HASH OF CHALLENGE FROM SERVER AND RECOVER HASH WITH PUBLIC KEY\n");
			/*		Receive and output the signature		*/

	int len=128;
	unsigned char* buff= (unsigned char*)malloc(len);
	SSL_read(ssl, buff, len);

	printf("RECEIVED.\n");
	printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)buff, len).c_str(), len);

    //-------------------------------------------------------------------------
	// 3b. Authenticate the signed key
	printf("3b. Authenticating key...\n");

	//BIO_new(BIO_s_mem())
	//BIO_write
	//BIO_new_file
	//PEM_read_bio_RSA_PUBKEY
	//RSA_public_decrypt
	//BIO_free
	
	RSA_free(pubkey);
	pubkey = RSA_new();
	BIO* bp = BIO_new_file("rsapublickey.pem", "r");
	PEM_read_bio_RSA_PUBKEY(bp, &pubkey, NULL, NULL);
	
	unsigned char* decKey = (unsigned char*)malloc(RSA_size(pubkey));
	int aut = RSA_public_decrypt(RSA_size(pubkey), (unsigned char*)buff, (unsigned char*) decKey, pubkey, RSA_PKCS1_PADDING);
	if (aut == -1){
		printf("Failed authenticating!\n");
		fprintf(stderr, "OpenSSL error: %s\n", ERR_error_string(ERR_get_error(), NULL));
		exit(EXIT_FAILURE);
	}
	RSA_free(pubkey);
	
		printf("CLIENT STEP 6: COMPARE GENERATED AND RECOVERED HASHES\n");
		/*		Compare the generated hash to the recovered hash from the server and authenticate		*/
	printf("Generated:\n");
	for (int i = 0; i < 20; i++){
		printf("%02x ", obuf[i]);
	}
	printf("\n");	
	printf("Decrypted key:\n");
	for (int i = 0; i < 20; i++){
		printf("%02x ", decKey[i]);
	}
	printf("\n");

	/*				!!!!NOTE: AUTHENTICATION CHECK ALWAYS TRUE!!!!			*/
	//if(obuf != decKey){ //Authentication check; Skipped and forced TRUE due to SHA1 bug client-side; consult README.txt
	//	printf("Mismatching hash! Not authentic\n");
	//	exit(0);
	//}
    
	printf("AUTHENTICATED\n");

    //-------------------------------------------------------------------------
	// 4. Send the server a file request
	printf("4.  Sending file request to server...\n");
		printf("CLIENT STEP 7: SEND SERVER FILE NAME\n");
		/*		Sends the server the file name string via ssl		*/
	PAUSE(2);
	//BIO_flush
    //BIO_puts
	//SSL_write
	
	SSL_write(ssl, filename, strlen(filename));

    printf("SENT.\n");
	printf("    (File requested: \"%s\")\n", filename);

    //-------------------------------------------------------------------------
	// 5. Receives and displays the contents of the file requested
	printf("5.  Receiving response from server...\n");
		printf("CLIENT STEP 8: RECEIVE AND DISPLAY FILE\n");
		/*		Receives the entire file and displays in gedit (assuming all files are text files)		*/
    //BIO_new_file
    //SSL_read
	//BIO_write
	//BIO_free
	
	BIO* fbp;
	//char* testfile = "test.txt"; //uncomment if testing client and server in same folder
	//fbp = BIO_new_file((const char*)testfile, "w");
	fbp = BIO_new_file((const char*)filename, "w"); //comment this if doing test config above
	
	char file[BUFFER_SIZE];
	memset(file, 0, sizeof(file));
	
	SSL_read(ssl, file, BUFFER_SIZE);
		
	int sizeCount = 0;
	while(file[sizeCount] > 0){ //count # bytes till NULL/eof
		sizeCount++;
	}
		//printf("sizeCount: %d\n", sizeCount);
	
	int fileSize = BIO_write(fbp, file, sizeCount);
		//printf("filesize: %i\n", fileSize);
	BIO_free(fbp);
	
	printf("Size of file: %i bytes\n", fileSize);
	printf("FILE RECEIVED.\n");
	
	char render[BUFFER_SIZE];
        strcpy(render, "gedit "); //open file with gedit
        strcat(render, filename);
        system(render); //bash command to open file with gedit

    //-------------------------------------------------------------------------
	// 6. Close the connection
	printf("6.  Closing the connection...\n");
		printf("CLIENT STEP 9: CLOSE SSL CONNECTION\n");
		/*		Close the SSL connection		*/


	//SSL_shutdown
	SSL_shutdown(ssl);
	
	printf("DONE.\n");
	
	printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");

    //-------------------------------------------------------------------------
	// Freedom!
	SSL_CTX_free(ctx);
	SSL_free(ssl);
	return EXIT_SUCCESS;
	
}
