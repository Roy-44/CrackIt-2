#include "include.h"

extern int errno;

void openMQ(mqd_t* mq);
void generateEncryptedData(char* encryptedData, int* encryptedDataLen, char* plainData);
void printCryptError(MTA_CRYPT_RET_STATUS status);
void randPlainData(char* plainData);
void randKey(char* key);
void sendEncryptedData(char* encryptedData,int encryptedDataLen ,Decrypter* decrypters,
                        int decryptersLogicalSize);
void handleRecivedMessages(mqd_t mq ,char* encryptedData,int encryptedDataLen,Decrypter** decrypters,int* decryptersLogicalSize,
                            int* decryptersPhysicalSize, char* plainData);
void connectNewDecrypter(ConnectionRequest* req, char* encryptedData,int encryptedDataLen,Decrypter** decrypters,int* decryptersLogicalSize,
                            int* decryptersPhysicalSize);
BOOL isAvailableId(int decrypterId,Decrypter* decrypters,int decryptersLogicalSize );
void disconnectDecrypter(DisconnectionRequest* req, Decrypter** decrypters,int* decryptersLogicalSize, int* decryptersPhysicalSize);
BOOL isCorrectDecryption(DecryptedData* decryptedData,char* plainData);
void enlargeDecryptersArrayIfNeeded(Decrypter** decrypters,int decryptersLogicalSize, int* decryptersPhysicalSize);
void cleanMq(mqd_t mq,char* encryptedData,int encryptedDataLen,Decrypter** decrypters,
                int* decryptersLogicalSize,int* decryptersPhysicalSize);
void sendEncryptedDataToDecrypter(Decrypter* decrypters,int decryptersLogicalSize,int decrypterId, char* encryptedData,int encryptedDataLen);
void setPriority();

int main(int argc, char* argv[]){
    mqd_t mq;
    char encryptedData[MAX_DATA_LEN], plainData[PLAIN_DATA_LEN];
    int encryptedDataLen;
    int decryptersLogicalSize = 0, decryptersPhysicalSize = 32;
    Decrypter* decrypters = (Decrypter*)malloc(sizeof(Decrypter) * decryptersPhysicalSize);

    setPriority();

    openMQ(&mq);

    while(TRUE){
        generateEncryptedData(encryptedData, &encryptedDataLen, plainData);
        sendEncryptedData(encryptedData, encryptedDataLen, decrypters, decryptersLogicalSize);
        handleRecivedMessages(mq, encryptedData, encryptedDataLen, &decrypters, &decryptersLogicalSize, &decryptersPhysicalSize, plainData);
    }

    mq_unlink(SERVER_MQ);
    free(decrypters);
    free(encryptedData);
}

void setPriority(){
    struct sched_param max_prio = {sched_get_priority_max(SCHED_FIFO)};
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &max_prio);
}

void handleRecivedMessages(mqd_t mq, char* encryptedData, int encryptedDataLen, Decrypter** decrypters, int* decryptersLogicalSize,
                            int* decryptersPhysicalSize, char* plainData){
    BOOL isDecryptionSucceeded = FALSE;

    MqMSG* msg = (MqMSG*)malloc(SERVER_MQ_MAX_MSG_SIZE);                          
    do{
        mq_receive(mq,(char*)msg,SERVER_MQ_MAX_MSG_SIZE,NULL);

        if(msg->type == CONNECTION_REQUEST){
            connectNewDecrypter((ConnectionRequest*)msg->data,encryptedData,encryptedDataLen,decrypters,decryptersLogicalSize,decryptersPhysicalSize);            
        }
        else if(msg ->type == DISCONNECTION_REQUEST){
            disconnectDecrypter((DisconnectionRequest*)msg->data, decrypters, decryptersLogicalSize, decryptersPhysicalSize);
        }
        else if(msg->type == DECRYPTED_DATA){
            printf("[Server]\tDecrypted data has been recived from decrypter #%d!\n", ((DecryptedData*)msg->data)->decrypterId);

            isDecryptionSucceeded = isCorrectDecryption((DecryptedData*)msg->data,plainData);
            if(isDecryptionSucceeded == FALSE){
                printf("[Server]\tThe decryted data that recived from decrypter #%d is incorrect!\n", ((DecryptedData*)msg->data)->decrypterId);

                sendEncryptedDataToDecrypter(*decrypters,*decryptersLogicalSize,((DecryptedData*)msg->data)->decrypterId,encryptedData, encryptedDataLen);
            } else {
                printf("[Server]\tThe decryted data that recived from decrypter #%d is correct!\n", ((DecryptedData*)msg->data)->decrypterId);
            }            
        }
    }while(isDecryptionSucceeded == FALSE);

    cleanMq(mq,encryptedData,encryptedDataLen,decrypters,decryptersLogicalSize,decryptersPhysicalSize);

    free(msg);
}

void sendEncryptedDataToDecrypter(Decrypter* decrypters, int decryptersLogicalSize, int decrypterId, char* encryptedData, int encryptedDataLen){
    MqMSG* msg = (MqMSG*)malloc(sizeof(MqMSG) + sizeof(EncryptedData));
    msg->type = ENCRYPTED_DATA;
    memcpy(((EncryptedData*)msg->data)->encryptedData,encryptedData,encryptedDataLen);
    ((EncryptedData*)msg->data)->encryptedDataLen = encryptedDataLen;

    for(int i =0; i < decryptersLogicalSize; ++i){
        if(decrypters[i].id == decrypterId){
            printf("[Server]\tSending encrypted data to decrypter #%d!\n",decrypterId);

            if(mq_send(decrypters[i].mq, (char*)msg, DECRYPTER_MQ_MAX_MSG_SIZE, 0) == -1){
                printf("[Server]\tSending encrypted data to decrypter #%d failed!\n",decrypterId);
            }
        }
    }
    
    free(msg);
}

void cleanMq(mqd_t mq, char* encryptedData, int encryptedDataLen, Decrypter** decrypters,
                int* decryptersLogicalSize,int* decryptersPhysicalSize){
    struct mq_attr attr = {0};
    mq_getattr(mq,&attr);
    MqMSG* msg = (MqMSG*)malloc(SERVER_MQ_MAX_MSG_SIZE);  

    while(attr.mq_curmsgs != 0){
        if(mq_receive(mq, (char*)msg, SERVER_MQ_MAX_MSG_SIZE, NULL) == -1){
            printf("[Server]\tReceiving message failed!\n");
        }

        if(msg->type == CONNECTION_REQUEST){
            connectNewDecrypter((ConnectionRequest*)msg->data,encryptedData,encryptedDataLen,decrypters,decryptersLogicalSize,decryptersPhysicalSize);
        }
        else if(msg ->type == DISCONNECTION_REQUEST){
            disconnectDecrypter((DisconnectionRequest*)msg->data,decrypters,decryptersLogicalSize,decryptersPhysicalSize);
        }
        
        mq_getattr(mq,&attr);
    }

    free(msg);
}

BOOL isCorrectDecryption(DecryptedData* decryptedData,char* plainData){
    return decryptedData->plainDataLen == PLAIN_DATA_LEN && memcmp(decryptedData->plainData,plainData,decryptedData->plainDataLen) == 0;
}

void disconnectDecrypter(DisconnectionRequest* req, Decrypter** decrypters, int* decryptersLogicalSize, int* decryptersPhysicalSize){
    for(int i = 0; i < *decryptersLogicalSize; ++i){
        if((*decrypters)[i].id == req->id){
            mq_close((*decrypters)[i].mq);

            (*decrypters)[i] = (*decrypters)[(*decryptersLogicalSize) - 1];
            --(*decryptersLogicalSize);

            if((*decryptersLogicalSize) * 2 < *decryptersPhysicalSize){
                (*decryptersPhysicalSize) /= 2;
                *decrypters = (Decrypter*)realloc(*decrypters, (*decryptersPhysicalSize) * sizeof(Decrypter));
            }

            printf("[Server]\tDecrypter #%d disconnected\n", req->id);

            return;
        }        
    }
}

void connectNewDecrypter(ConnectionRequest* req, char* encryptedData, int encryptedDataLen, Decrypter** decrypters, int* decryptersLogicalSize,
                            int* decryptersPhysicalSize){
    if(isAvailableId(req->id,*decrypters,*decryptersLogicalSize) == FALSE){
        printf("[Server]\tDetected an imposter of decrypter with id #%d\n", req->id);
        return;
    }

    enlargeDecryptersArrayIfNeeded(decrypters, *decryptersLogicalSize, decryptersPhysicalSize);

    Decrypter newDecrypter;
    newDecrypter.id = req->id;
    newDecrypter.mq = mq_open(req->mqName, O_WRONLY);

    (*decrypters)[(*decryptersLogicalSize)] = newDecrypter;
    (*decryptersLogicalSize)++;

    printf("[Server]\tDecrypter with id #%d has been connected!\n",req->id);

    MqMSG* msg = (MqMSG*)malloc(sizeof(MqMSG) + sizeof(EncryptedData));
    msg->type = ENCRYPTED_DATA;
    memcpy(((EncryptedData*)msg->data)->encryptedData,encryptedData,encryptedDataLen);
    ((EncryptedData*)msg->data)->encryptedDataLen = encryptedDataLen;

    printf("[Server]\tSending encrypted data to decrypter #%d!\n",req->id);

    if(mq_send(newDecrypter.mq, (char*)msg, DECRYPTER_MQ_MAX_MSG_SIZE, 0) == -1){
        printf("[Server]\tSending encrypted data to decrypter #%d failed!\n",req->id);
    }

    free(msg);
}

void enlargeDecryptersArrayIfNeeded(Decrypter** decrypters,int decryptersLogicalSize, int* decryptersPhysicalSize){
    if(decryptersLogicalSize == *decryptersPhysicalSize){
        *decryptersPhysicalSize *= 2;
        *decrypters = (Decrypter*)realloc(*decrypters,*decryptersPhysicalSize);
    }
}

BOOL isAvailableId(int decrypterId,Decrypter* decrypters,int decryptersLogicalSize ){
    for(int i =0; i<decryptersLogicalSize; ++i){
        if(decrypters[i].id == decrypterId){
            return FALSE;
        }
    }

    return TRUE;
}

void sendEncryptedData(char* encryptedData,int encryptedDataLen,Decrypter* decrypters,int decryptersLogicalSize){
    MqMSG* msg = (MqMSG*)malloc(sizeof(MqMSG) + sizeof(EncryptedData));
    msg->type = ENCRYPTED_DATA;
    memcpy(((EncryptedData*)msg->data)->encryptedData, encryptedData, encryptedDataLen);
    ((EncryptedData*)msg->data)->encryptedDataLen = encryptedDataLen;

    for(int i = 0; i < decryptersLogicalSize; ++i){

        printf("[Server]\tSending encrypted data to decrypter #%d!\n",decrypters[i].id);

        if(mq_send(decrypters[i].mq ,(char*)msg ,DECRYPTER_MQ_MAX_MSG_SIZE,0) == -1){
            printf("[Server]\tSending encrypted data to decrypter #%d failed!\n",decrypters[i].id);
        }
    }

    free(msg);
}

void generateEncryptedData(char* encryptedData, int* encryptedDataLen,char* plainData){
    if(PLAIN_DATA_LEN % BASE_DATA_LEN != 0){
        printf("[Server]\tData length is not a multiplication of 8!\n");
        exit(INVALID_ARGUMENT);
    }

    char key[PLAIN_DATA_LEN / BASE_DATA_LEN];
    char plainDataAsString[PLAIN_DATA_LEN + 1];
    MTA_CRYPT_RET_STATUS status;

    randPlainData(plainData);
    randKey(key);   

    do{
        status = MTA_encrypt(key,PLAIN_DATA_LEN/BASE_DATA_LEN,
                                                plainData,PLAIN_DATA_LEN,encryptedData,encryptedDataLen);
        if(status != MTA_CRYPT_RET_OK){
            printCryptError(status);
        }
    }while(status != MTA_CRYPT_RET_OK);

    memcpy(plainDataAsString,plainData,PLAIN_DATA_LEN);
    plainDataAsString[PLAIN_DATA_LEN] = '\0';
    printf("[Server]\tNew password was generated. The password is: %s\n", plainDataAsString);
}

void randKey(char* key){
    MTA_get_rand_data(key,PLAIN_DATA_LEN/BASE_DATA_LEN);
}

void randPlainData(char* plainData){
    char ch;
    for(int i =0; i<PLAIN_DATA_LEN; ++i){
        do{
            ch = MTA_get_rand_char();
        }while(isprint(ch) == 0);

        plainData[i] = ch;
    }
}

void printCryptError(MTA_CRYPT_RET_STATUS status){
	char* errors[8] = {"MTA_CRYPT_RET_OK","MTA_CRYPT_RET_ERROR", "MTA_CRYPT_RET_NULL_PTR_RECEIVED",
		"MTA_CRYPT_RET_DATA_ZERO_LENGTH", "MTA_CRYPT_RET_DATA_MAX_LENGTH_EXCEEDED",
		"MTA_CRYPT_RET_KEY_ZERO_LENGTH", "MTA_CRYPT_RET_KEY_MAX_LENGTH_EXCEEDED",
		"MTA_CRYPT_RET_NOT_8_BYTE_MULTIPLICATION"};
	printf("[Server]\tAn error occurred: %s\n", errors[status]);
	if(status >= 2){
		exit(MTA_CRYPT_ERROR);
	}
}

void openMQ(mqd_t* mq){
    struct mq_attr attr = {0};
    attr.mq_maxmsg = SERVER_MQ_MAX_SIZE;
    attr.mq_msgsize = SERVER_MQ_MAX_MSG_SIZE;

    mq_unlink(SERVER_MQ);
    *mq = mq_open(SERVER_MQ, O_CREAT | O_RDWR, S_IRWXU | S_IRWXG, &attr);
    if(*mq == (mqd_t)-1){
        printf("[Server]\tAn error occurred while opening MQ!\n");

        exit(MQ_OPEN_ERROR);
    }
}