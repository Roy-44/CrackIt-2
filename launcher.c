#include "include.h"

int getDecryptersNumber(int argc, char* argv[]);
void launchServer();
void launchDecrypters(int decryptersNumber, int decrypterRounds);
int getdecrypterRounds(int argc, char* argv[]);
void waitAll();
BOOL isPlainDataLenValid();

int main(int argc, char* argv[]){
    int decrypterRounds = getdecrypterRounds(argc, argv);
    int decryptersNumber = getDecryptersNumber(argc, argv);

    launchServer();
    if(isPlainDataLenValid()){
        usleep(500);    //if semaphore was learned in the course we would have use it instead of usleep
        launchDecrypters(decryptersNumber, decrypterRounds);
    }
    
    waitAll();
}

BOOL isPlainDataLenValid(){
    return PLAIN_DATA_LEN % BASE_DATA_LEN == 0;
}

void waitAll(){
    while(wait(NULL) != -1);
}

int getdecrypterRounds(int argc, char* argv[]){
    int decrypterRounds = UNINITIALIZED;
    BOOL isDecrypterRoundsExist = FALSE;

    for(int i = 1; i < argc - 1; ++i){
        if(strcmp(argv[i] , "-n") == 0 && argv[i+1] != NULL){
            isDecrypterRoundsExist = TRUE;
            decrypterRounds = atoi(argv[i+1]);
        }
    }

    if(decrypterRounds <= 0 && isDecrypterRoundsExist==TRUE){
        printf("[Server]\tInvalid decrypter rounds parameter!\n");
        exit(INVALID_ARGUMENT);
    }

    return decrypterRounds;
}

void launchDecrypters(int decryptersNumber, int decrypterRounds){
    for(int i = 0; i < decryptersNumber; ++i){
        if(fork() == 0){
            char decrypterIdString[10];
            sprintf(decrypterIdString,"%d",i+1);

            if(decrypterRounds != UNINITIALIZED){
                char decrypterRoundsString[10];
                sprintf(decrypterRoundsString,"%d",decrypterRounds);
                char* myArgv[] = {DECRYPTER_PROG, decrypterIdString, "-n", decrypterRoundsString, NULL};

                execv(DECRYPTER_PROG, myArgv);
                exit(EXECV_FAILURE);
            }
            else{
                char* myArgv[] = {DECRYPTER_PROG, decrypterIdString, NULL};

                execv(DECRYPTER_PROG, myArgv);
                exit(EXECV_FAILURE);
            }
        }
    } 
}

void launchServer(){
    if(vfork() == 0){
        char* myArgv[] = {SERVER_PROG, NULL};

        execv(SERVER_PROG, myArgv);
        exit(EXECV_FAILURE);
    }
}

int getDecryptersNumber(int argc, char* argv[]){
     if(argc < 2 ){
        printf("[Server]\tDecrypters number was not entered!\n");
        exit(NOT_ENOUGHT_ARGUMENTS);
    }
    
    int decryptersNumber = atoi(argv[1]);
    if(decryptersNumber <= 0 ){
        printf("[Server]\tInvalid decrypters number!\n");
        exit(INVALID_ARGUMENT);
    }

    return decryptersNumber;
}