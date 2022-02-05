#include<openssl/conf.h>
#include<openssl/evp.h>
#include<openssl/err.h>
#include<string.h>
#include<openssl/aes.h>
#include<openssl/rand.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h> 
#include<unistd.h>

#define IV_SIZE 16

void checkNoOfArguments(int noOfArgs)
{
	if(noOfArgs<3 || noOfArgs>5)
	{
		printf("\nERROR: Invalid number of arguments entered.");
		printf("\nThe correct format is : ./ufsend <input file> [-d < IP-addr:port >][-l] \n");
		exit(0);
	}
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int isLocalDecryption(char* arg)
{
	if(strcmp(arg,"-l")==0)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}
int isSocketDecryption(char* arg)
{
	if(strcmp(arg,"-d")==0)
	{
		return 1;
	}
	else
		return 0;
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *aad,
	int aad_len, unsigned char *tag, unsigned char *key, unsigned char *IV,
	unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int len=0, plaintext_len=0, ret;

	//Create and initialise the context
	if(!(ctx = EVP_CIPHER_CTX_new())) 
		handleErrors();

	//Initialise the decryption operation.
	if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		handleErrors();

	//Set IV length
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
		handleErrors();

	//Initialise key and IV
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, IV)) 
		handleErrors();

	//Provide AAD data if applicable
	if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
		handleErrors();

	//Provide the message to be decrypted, and obtain the plaintext output.
	 while(plaintext_len<=ciphertext_len-16)
	 {
	 	if(1!=EVP_DecryptUpdate(ctx, plaintext+plaintext_len, &len, ciphertext+plaintext_len, 16))
	 	handleErrors();

	 	plaintext_len+=len;
	 }

	 if(1!=EVP_DecryptUpdate(ctx, plaintext+plaintext_len, &len, ciphertext+plaintext_len, ciphertext_len-plaintext_len))
	 	handleErrors();
	 plaintext_len+=len;

	//Set expected tag value
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
		handleErrors();

	/* Finalise the decryption. ret > 0 indicates success,
	 * anything else is a failure
	 */
	ret = EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &len);

	// Clean up
	EVP_CIPHER_CTX_free(ctx);

	if(ret > 0)
	{
		//If successfull
		plaintext_len += len;
		return plaintext_len;
	}
	else
	{
		//Unsuccessful
		return -1;
	}
}



int main (int argc, char* argv [])
{	
	//Check if correct number of arguments have been given while execution of the program
	checkNoOfArguments(argc);
	char *inputFileName;
	char *outputFileName ;
	inputFileName = argv[1];
    int isSocket=0;

	if(isLocalDecryption(argv[2]))
	{ 	
		//Replace .ufsec from extension
		int newFileNameLength = strlen(inputFileName)-6;
		outputFileName=malloc(sizeof(char) *  newFileNameLength+1);
		strncpy(outputFileName, inputFileName, newFileNameLength);
		outputFileName[newFileNameLength]='\0';
		
	}
	else if(isSocketDecryption(argv[2])){ 
		//Keep output file name same as input file name
		isSocket=1; // enabling socket connection
		int newFileNameLength = strlen(inputFileName);
		outputFileName=malloc(sizeof(char) *  newFileNameLength+1);
		outputFileName=inputFileName;
		outputFileName[newFileNameLength]='\0';
	}

	FILE * doesFileAlreadyExist;
		doesFileAlreadyExist = fopen(outputFileName, "rb+");
		if (doesFileAlreadyExist){
			printf("\nERROR in Creating Output file: %s already exists\n", outputFileName);
			fclose(doesFileAlreadyExist);
			return 33;
		}

	if(isSocket==1)
	{
		printf("\nWaiting for connections. \n");  
		char socketBuffer[256];

		unsigned int destPORT=atoi(argv[3]); //Retrieve arrival port no. from args passed in command line
		struct sockaddr_in server, client;

		int socketID = socket(AF_INET, SOCK_STREAM, 0);
 		bzero((char *) &server, sizeof(server));
		
		server.sin_family= AF_INET;
		server.sin_port= htons(destPORT);
		server.sin_addr.s_addr= INADDR_ANY;
		
		bind(socketID, (struct sockaddr *)&server, sizeof(server));
		listen(socketID, 5);

		socklen_t clientLength=sizeof(client);
		int connectionID = accept(socketID, (struct sockaddr *)  &client, &clientLength);
		
		char *tempFileName="temp.txt"; //temp file to store the incoming buffer from socket
		FILE *tempSocketFile = fopen(tempFileName,"wb+");
		int receivedSize=0;
		
		while(1){
			// Write received data to temp file
			bzero(socketBuffer, 256);
			receivedSize = read(connectionID, socketBuffer, 256);
			if(receivedSize == 0){
				fclose(tempSocketFile);
				break;
			}
			fwrite(socketBuffer, sizeof(char), receivedSize, tempSocketFile);
		}
		close(socketID);
		printf("\nInbound file.\n");
		inputFileName=tempFileName;
	}
	
	//Initialize required values for decryption
	unsigned char IV[IV_SIZE];
    unsigned char aad[16]="abcdefghijklmnop";//Sample aad
    unsigned char* salt = (unsigned char*) "CalciumChloride";
    unsigned char tag[]="abcde";//Sample tag
    unsigned char password[32];

	//Key generation using Password Based Key Derivation Function 2
    printf("\nEnter password:\n");
    scanf("%s",password);
	unsigned char *key = password;
	if(!PKCS5_PBKDF2_HMAC(((const char*)key), strlen((char*)key),salt,strlen((const char*)(salt)),4096,EVP_sha512(),32,key))
	{
		printf("\nError in key generation\n");
		exit(1);
	}


	//Output resultant key to console
    printf("\nKey is: \n"); 
    for(int i=0;i<32;i++) 
    { 
        printf("%02X ", key[i]); 
    }


	FILE *ip_file = fopen(inputFileName, "rb+");
	char *buffer = NULL;
	int fileSize = 0;

	if(ip_file)
	{	
		//To find size of file to be decrypted
		fseek(ip_file, 0, SEEK_END);
		fileSize = ftell(ip_file);
		rewind(ip_file);
		buffer= (char *) malloc(sizeof(char) *  (fileSize));
		fread(buffer, sizeof(char), fileSize-IV_SIZE,ip_file); //Read file data into buffer
		fread(IV,sizeof(unsigned char),IV_SIZE,ip_file); //Read last 16 bytes of characters i.e. the IV
		printf("\n Contents of file:\n");
		BIO_dump_fp (stdout, (const char *)buffer, fileSize);
		fclose(ip_file);
	
	}

    //Buffer for the decrypted text
	unsigned char *ciphertext = (unsigned char *) buffer;
    unsigned char decryptedtext[fileSize-IV_SIZE];
    int decryptedtext_len;
	
		// Write to File
	FILE *op_file  = fopen(outputFileName, "wb+");

	//Function call for decryption
	decryptedtext_len = gcm_decrypt(ciphertext, fileSize-IV_SIZE, aad, sizeof(aad), tag, key, IV, decryptedtext);
	//Adding NULL terminator at the end
    decryptedtext[fileSize-IV_SIZE] = '\0';

    //Output decrypted text
    printf("\nDecrypted text is:\n");
    printf("%s\n", decryptedtext);
    fwrite(decryptedtext, fileSize-IV_SIZE, 1, op_file);

    fclose(ip_file);
    fclose(op_file);
	if(&isLocalDecryption)
	{
		printf("\nSuccessfully decrypted %s to %s (%d bytes written).\n", inputFileName, outputFileName, fileSize-IV_SIZE);
	}
	else 
	{
		printf("\nSuccessfully decrypted text from socket to %s (%d bytes written).\n", outputFileName, fileSize-IV_SIZE);
	}
    return 0;	


}
