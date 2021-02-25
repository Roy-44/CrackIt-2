#include "include.h"

extern int errno;

int getdecrypterRounds(int argc, char* argv[]);
int getDecrypterId(int argc, char* argv[]);
void openMQ(mqd_t* mq, char* mqName, int decrypterId);
void openServerMq(mqd_t* serverMq, int decrypterId);
void sendConnectionRequest(mqd_t serverMq, int decrypterId, char* mqName);
void sendDisconnectRequest(mqd_t serverMq, int decrypterId, mqd_t mq);
void decrypt(mqd_t serverMq, mqd_t mq, int decrypterId,char* encryptedData, int encryptedDataLen, int* decrypterRounds);
void getLatestEncryptedData(mqd_t mq,char* encryptedData, int* encryptedDataLen,int decrypterId);
void randKey(char* key);
void printCryptError(MTA_CRYPT_RET_STATUS status, int decrypterId);
BOOL isPrintableData(char* decryptedData,int decryptedDataLen);
void sendDecryptedData(mqd_t serverMq,char* decryptedData,int decryptedDataLen,int decrypterId);
void decryptForever(mqd_t mq, int decrypterId, mqd_t serverMq);
void decryptByRounds(int* decrypterRounds, mqd_t mq, int decrypterId, mqd_t serverMq);

int main(int argc, char* argv[]){
    mqd_t mq, serverMq;
    int decrypterId = getDecrypterId(argc,argv);
    int decrypterRounds = getdecrypterRounds(argc, argv);
    int encryptedDataLen;
    char mqName[32], encryptedData[MAX_DATA_LEN];
    sprintf(mqName,DECRYPTER_MQ,decrypterId);

    openMQ(&mq, mqName, decrypterId);
    openServerMq(&serverMq, decrypterId);
    sendConnectionRequest(serverMq, decrypterId, mqName);

    if(decrypterRounds == UNINITIALIZED){
        decryptForever(mq, decrypterId, serverMq);
    }
    else{
        decryptByRounds(&decrypterRounds, mq, decrypterId, serverMq);
    }

    printf("[Decrypter #%d]\tMy work here is done!\n",decrypterId);
    sendDisconnectRequest(serverMq, decrypterId, mq);

    mq_unlink(mqName);
}

void decryptForever(mqd_t mq, int decrypterId, mqd_t serverMq){
    char encryptedData[MAX_DATA_LEN];
    int encryptedDataLen;

    while(TRUE){
        getLatestEncryptedData(mq, encryptedData, &encryptedDataLen, decrypterId);

        printf("[Decrypter #%d]\tGot encrypted data from server!\n",decrypterId);

        decrypt(serverMq, mq, decrypterId, encryptedData, encryptedDataLen, NULL);
    }
}

void decryptByRounds(int* decrypterRounds, mqd_t mq, int decrypterId, mqd_t serverMq){
    char encryptedData[MAX_DATA_LEN];
    int encryptedDataLen;

    for(int i=0; i < *decrypterRounds; ++i){        
        getLatestEncryptedData(mq, encryptedData, &encryptedDataLen, decrypterId);

        printf("[Decrypter #%d]\tGot encrypted data from server!\n", decrypterId);
        
        decrypt(serverMq, mq, decrypterId, encryptedData, encryptedDataLen, decrypterRounds);
    }
}

void decrypt(mqd_t serverMq, mqd_t mq, int decrypterId, char* encryptedData, int encryptedDataLen, int* decrypterRounds){
    char key[PLAIN_DATA_LEN / BASE_DATA_LEN];
    char decryptedData[MAX_DATA_LEN];

    int decryptedDataLen;
    MTA_CRYPT_RET_STATUS status;

    struct mq_attr attr = {0};

    do{
        randKey(key);

        do{
            status = MTA_decrypt(key, PLAIN_DATA_LEN / BASE_DATA_LEN, encryptedData, encryptedDataLen, decryptedData, &decryptedDataLen);
            if(status != MTA_CRYPT_RET_OK){
                printCryptError(status,decrypterId);
            }
        }while(status != MTA_CRYPT_RET_OK);

        mq_getattr(mq, &attr);

        if(attr.mq_curmsgs != 0){
            if(decrypterRounds != NULL){
                (*decrypterRounds)++;
            }

            printf("[Decrypter #%d]\tStop trying to decrypt the old password!\n", decrypterId);
            return;
        }

    }while(isPrintableData(decryptedData, decryptedDataLen) == FALSE);

    sendDecryptedData(serverMq, decryptedData, decryptedDataLen, decrypterId);
}

void sendDecryptedData(mqd_t serverMq,char* decryptedData,int decryptedDataLen,int decrypterId){
    MqMSG* msg = (MqMSG*)malloc(sizeof(MqMSG) + sizeof(DecryptedData));

    msg->type = DECRYPTED_DATA;
    ((DecryptedData*)msg->data)->decrypterId = decrypterId;
    memcpy(((DecryptedData*)msg->data)->plainData,decryptedData,decryptedDataLen);
    ((DecryptedData*)msg->data)->plainDataLen = decryptedDataLen;

    char* decryptedDataString = (char*)malloc(sizeof(char) * (decryptedDataLen + 1));
    memcpy(decryptedDataString, decryptedData, decryptedDataLen);
    decryptedDataString[decryptedDataLen] = '\0';
    printf("[Decrypter #%d]\tSending decrypted data to server. Decrypted data: %s!\n", decrypterId, decryptedDataString);

    if(mq_send(serverMq, (char*)msg, SERVER_MQ_MAX_MSG_SIZE, 0) == -1){
        printf("[Decrypter #%d]\tSending decrypted data to server failed!\n", decrypterId);
    }

    free(decryptedDataString);
    free(msg);
}

BOOL isPrintableData(char* decryptedData, int decryptedDataLen){
    for(int i = 0; i < decryptedDataLen; ++i){
        if(isprint(decryptedData[i]) == FALSE){
            return FALSE;
        }
    }

    return TRUE;
}

void printCryptError(MTA_CRYPT_RET_STATUS status, int decrypterId){
	char* errors[8] = {"MTA_CRYPT_RET_OK","MTA_CRYPT_RET_ERROR", "MTA_CRYPT_RET_NULL_PTR_RECEIVED",
		"MTA_CRYPT_RET_DATA_ZERO_LENGTH", "MTA_CRYPT_RET_DATA_MAX_LENGTH_EXCEEDED",
		"MTA_CRYPT_RET_KEY_ZERO_LENGTH", "MTA_CRYPT_RET_KEY_MAX_LENGTH_EXCEEDED",
		"MTA_CRYPT_RET_NOT_8_BYTE_MULTIPLICATION"};

	printf("[Decrypter #%d]\tAn error occurred while decrypting data: %s\n",decrypterId,errors[status]);

	if(status >= 2){
		exit(MTA_CRYPT_ERROR);
	}
}

void randKey(char* key){
    MTA_get_rand_data(key, PLAIN_DATA_LEN / BASE_DATA_LEN);
}

void getLatestEncryptedData(mqd_t mq,char* encryptedData, int* encryptedDataLen,int decrypterId){
    struct mq_attr attr = {0};
    MqMSG* msg = (MqMSG*)malloc(DECRYPTER_MQ_MAX_MSG_SIZE);
    
    do{
        if(mq_receive(mq,(char*)msg,DECRYPTER_MQ_MAX_MSG_SIZE,NULL) == -1){
            printf("[Decrypter #%d]\tReceiving data was failed!\n", decrypterId);
        }
        mq_getattr(mq, &attr);

        if(attr.mq_curmsgs == 0){
            *encryptedDataLen = ((EncryptedData*)msg->data)->encryptedDataLen;
            memcpy(encryptedData, ((EncryptedData*)msg->data)->encryptedData, *encryptedDataLen);
        }
    }while(attr.mq_curmsgs != 0);

    free(msg);
}

void sendDisconnectRequest(mqd_t serverMq, int decrypterId, mqd_t mq){
    MqMSG* msg = (MqMSG*)malloc(sizeof(MqMSG) + sizeof(DisconnectionRequest));

    msg->type = DISCONNECTION_REQUEST;
    ((DisconnectionRequest*)msg->data)->id = decrypterId;
    ((DisconnectionRequest*)msg->data)->mq = mq;

    printf("[Decrypter #%d]\tSending disconnection request!\n", decrypterId);
    
    if(mq_send(serverMq, (char*)msg, SERVER_MQ_MAX_MSG_SIZE, 0) == -1){
        printf("[Decrypter #%d]\tSending disconnection request failed!\n", decrypterId);
    }

    free(msg);
}

void sendConnectionRequest(mqd_t serverMq, int decrypterId, char* mqName){
    MqMSG* msg = (MqMSG*)malloc(sizeof(MqMSG) + sizeof(ConnectionRequest));

    msg->type = CONNECTION_REQUEST;
    ((ConnectionRequest*)msg->data)->id = decrypterId;
    memcpy(((ConnectionRequest*)msg->data)->mqName,mqName,strlen(mqName));

    printf("[Decrypter #%d]\tSending connection request to server!\n", decrypterId);
    
    if(mq_send(serverMq,(char*)msg,SERVER_MQ_MAX_MSG_SIZE,0) == -1){
        printf("[Decrypter #%d]\tSending connection request was failed!\n",decrypterId);
    }

    free(msg);
}

void openServerMq(mqd_t* serverMq, int decrypterId){
    *serverMq = mq_open(SERVER_MQ, O_WRONLY);
    if(*serverMq == -1){
        printf("[Decrypter #%d]\tAn error occurred while opening server MQ!\n",decrypterId);
        exit(MQ_OPEN_ERROR);
    }
}

void openMQ(mqd_t* mq, char* mqName, int decrypterId){
    struct mq_attr attr = {0};
    attr.mq_maxmsg = DECRYPTER_MQ_MAX_SIZE;
    attr.mq_msgsize = DECRYPTER_MQ_MAX_MSG_SIZE;

    mq_unlink(mqName);

    if((*mq = mq_open(mqName, O_CREAT | O_EXCL, S_IRWXU | S_IRWXG, &attr)) == -1){
        if(errno == EEXIST){
            printf("[Error]\t\tDecrypter with id #%d is already exist!\n", decrypterId);
        }
        else{
            printf("[Decrypter #%d]\tAn error occurred while opening MQ!\n",decrypterId);
        }
        exit(MQ_OPEN_ERROR);
    }
}

int getdecrypterRounds(int argc, char* argv[]){
    int decrypterRounds = UNINITIALIZED;
    BOOL isDecrypterRoundsExist = FALSE;

    for(int i =1 ; i < argc-1; ++i){
        if(strcmp(argv[i] , "-n") == 0 && argv[i+1] != NULL){
            isDecrypterRoundsExist = TRUE;
            decrypterRounds = atoi(argv[i+1]);
        }
    }

    if(decrypterRounds <= 0 && isDecrypterRoundsExist==TRUE){
        printf("[Error]\t\tInvalid decrypter rounds parameter!\n");
        exit(INVALID_ARGUMENT);
    }

    return decrypterRounds;
}

int getDecrypterId(int argc, char* argv[]){
     if( argc < 2 ){
        printf("[Error]\t\tDecrypters number was not entered!\n");
        exit(NOT_ENOUGHT_ARGUMENTS);
    }
    
    int decrypterId = atoi(argv[1]);
    if( decrypterId <= 0 ){
        printf("[Error]\t\tInvalid decrypter ID!\n");
        exit(INVALID_ARGUMENT);
    }

    return decrypterId;
}