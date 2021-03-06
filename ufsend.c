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
	if(noOfArgs<3 || noOfArgs>4)
	{
		printf("\nERROR: Invalid number of arguments entered.");
		printf("\nThe correct format is : ./ufsend <input file> [-d < IP-addr:port >][-l] \n");
		exit(0);
	}
}

int isLocalEncryption (char* arg)
{
	if(strcmp(arg,"-l")==0)
	{
		return 1;
	}
	else
		return 0;
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}


int gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *aad,
	int aad_len, unsigned char *key, unsigned char *IV,
	unsigned char *ciphertext, unsigned char *tag)
{
	EVP_CIPHER_CTX *ctx;

	int len=0, ciphertext_len=0;

	//Create and initialise the context
	if(!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	//Initialise the encryption operation.
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		handleErrors();

	//Set IV length
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
		handleErrors();

	//Initialise key and IV
	if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, IV)) 
		handleErrors();

	//Provide AAD data if applicable
	if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
		handleErrors();

	//Provide the message to be encrypted, and obtain the encrypted output.
	//encrypt in block lengths of 16 bytes
	 while(ciphertext_len<=plaintext_len-16)
	 {
	 	if(1 != EVP_EncryptUpdate(ctx, ciphertext+ciphertext_len, &len, plaintext+ciphertext_len, 16))
	 	handleErrors();

		ciphertext_len+=len;
	 }
	 if(1 != EVP_EncryptUpdate(ctx, ciphertext+ciphertext_len, &len, plaintext+ciphertext_len, plaintext_len-ciphertext_len))
	 	handleErrors();
         
	ciphertext_len+=len;
	//Finalise the encryption.
	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len))
		handleErrors();
	ciphertext_len += len;
	//Get the tag
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
		handleErrors();

	//Clean up
	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;

}



int main (int argc, char* argv [])
{	
	//Check if correct number of arguments have been given while execution of the program
	checkNoOfArguments(argc);
	char *inputFileName;
    inputFileName = argv[1];
    char *outputFileName;
    int isLocal = 0;

    if(isLocalEncryption(argv[2]))
	{
		isLocal=1;
		int outputFileNameLength = strlen(inputFileName)+6; //6 additional characters required for ".ufsec" extension
		outputFileName= malloc(sizeof(char) *  outputFileNameLength+1); ;
		strcpy(outputFileName, inputFileName);
		outputFileName[outputFileNameLength]='\0';
		strcat(outputFileName, ".ufsec");
		
		FILE * fileAlreadyExists;
		fileAlreadyExists = fopen(outputFileName, "rb+");
		
		if (fileAlreadyExists)
		{
			printf("\nERROR in Creating Output file: %s exists \n", outputFileName);
			fclose(fileAlreadyExists);
			return 33;
		}
		else
		{
			printf("\nEmpty output file %s created successfully.\n",outputFileName);
		}
	}

	// Key generation using Password Based Key Derivation Function 2
	unsigned char password[32];
    unsigned char* salt = (unsigned char*) "CalciumChloride";
	printf("\nEnter password:\n");
    scanf("%s",password);
	unsigned char *key = password;
	if(!PKCS5_PBKDF2_HMAC(((const char*)key), strlen((char*)key),salt,strlen((const char*)(salt)),4096,EVP_sha512(),32,key))
	{
		printf("\nError in key generation\n");
		exit(1);
	}


	//Output resultant key to console
	printf("\nKey is:\n");
	for(int i=0;i<32;i++)
	{
	printf("%02X ", key[i]);
	}

	//Find size of the input file
    FILE *ip_file = fopen(inputFileName, "rb+");
    char* buffer = NULL;
	int fileSize=0;
	if(ip_file)
	{
	fseek(ip_file, 0, SEEK_END);
	fileSize = ftell(ip_file);
	rewind(ip_file);
	buffer = (char *) malloc(sizeof(char) *  (fileSize));
	fread(buffer, sizeof(char), fileSize,ip_file);
	fclose(ip_file);
	}
    
	//Initialize required values for encryption
	unsigned char aad[16]="abcdefghijklmnop"; //sample aad
	unsigned char tag[]="abcde"; //sample tag
	unsigned char IV[IV_SIZE];
	// unsigned char IV[16]="abcdefghijklmnop"; //sample IV

	//Assign randomly generated bytes to IV
	if(!RAND_bytes(IV, sizeof(IV)))
	{
		fprintf(stderr, "ERROR: RAND_bytes error: %s\n", strerror(errno));
        return errno;
	}

	// printf("\n IV: %s",IV);
    unsigned char ciphertext[fileSize];
    unsigned char *plaintext = (unsigned char *) buffer;
	int ciphertext_len;

	//Function call for encryption
    ciphertext_len = gcm_encrypt(plaintext, fileSize, aad, sizeof(aad), key, IV, ciphertext, tag);

    if(isLocal == 1)
	{ 
	//Write to .ufsec output file
	FILE *op_file  = fopen(outputFileName, "wb+");
    printf("\nCiphertext is:\n");
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len); //Dumps the contents of buffer into console
    fwrite(ciphertext,ciphertext_len,1,op_file);
	//Append IV at the end of file
	fwrite(IV,IV_SIZE,1,op_file);
    printf("\nSuccessfully encrypted %s to %s\n",  inputFileName, outputFileName);
	}
	else
	{	
	char * dest = argv[3]; //Stores the destination to a string
	char *destIP=strsep(&dest, ":"); // removes the IP part from the string
	unsigned int destPORT=atoi(strsep(&dest, ":")); // removes the PORT from the string

	//Initialize socket
	struct sockaddr_in remoteSocket;
	int sourceSocket = socket(AF_INET, SOCK_STREAM, 0);
	remoteSocket.sin_family= AF_INET;
	remoteSocket.sin_port= htons(destPORT);
	remoteSocket.sin_addr.s_addr= inet_addr(destIP);
	printf("\nTransmitting to %s",argv[3]);
	connect(sourceSocket, (struct sockaddr *)  &remoteSocket, sizeof(remoteSocket)); // connect to socket
	write(sourceSocket, ciphertext, ciphertext_len); //write buffer to port
	write(sourceSocket,IV,IV_SIZE);//Append IV at the end of file
	close(sourceSocket);
	printf("\nSuccessfully received by %s\n",argv[3]);
	}
}
