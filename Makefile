
CC              = gcc #Compiler used for compiling the program
INCLUDES 		= -I/usr/local/opt/openssl@1.1/include -lcrypto #For including openSSL libraries/headers
LFLAGS          = -L/usr/local/opt/openssl@1.1/lib 
filenames 		:= example.txt.ufsec example ufsend ufrec #files to be removed on $make clean
files 			:= $(strip $(foreach f,$(filenames),$(wildcard $(f))))
EXEC 			= ufsend ufrec #names of the executable files

all : $(EXEC)
ufsend: 
	$(CC) ufsend.c -o ufsend $(LFLAGS) $(INCLUDES)
ufrec:
	$(CC) ufrec.c -o ufrec $(LFLAGS) $(INCLUDES)
clean:
ifneq ($(files),)   #if any of the files mentioned in "filenames" exist, remove them
	rm -f $(files)
endif
