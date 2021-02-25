#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <mqueue.h>
#include <ctype.h>
#include <errno.h>
#include <sys/wait.h>
#include <sched.h>
#include <pthread.h>
#include "mta_crypt.h"
#include "mta_rand.h"

#define PLAIN_DATA_LEN 16
#define MAX_DATA_LEN 256
#define BASE_DATA_LEN 8

#define NOT_ENOUGHT_ARGUMENTS -1
#define INVALID_ARGUMENT -2
#define EXECV_FAILURE -3
#define MQ_OPEN_ERROR -4
#define MTA_CRYPT_ERROR -5
#define UNINITIALIZED -1

#define SERVER_PROG "./server.out"
#define DECRYPTER_PROG "./decrypter.out"

#define BOOL int
#define TRUE 1
#define FALSE 0

#define SERVER_MQ "/server_mq"
#define SERVER_MQ_MAX_SIZE 10
#define SERVER_MQ_MAX_MSG_SIZE sizeof(MqMSG) + sizeof(DecryptedData)

#define DECRYPTER_MQ "/decrypter_%d_q"
#define DECRYPTER_MQ_MAX_SIZE 10
#define DECRYPTER_MQ_MAX_MSG_SIZE sizeof(MqMSG) + sizeof(EncryptedData)

typedef struct Decrypter_{
    int id;
    mqd_t mq;
}Decrypter;


typedef enum{
    CONNECTION_REQUEST,
    DISCONNECTION_REQUEST,
    ENCRYPTED_DATA,
    DECRYPTED_DATA
}MQ_MSG_TYPE;

typedef struct MqMSG_{
    MQ_MSG_TYPE type;
    char data[];
}MqMSG;

typedef struct ConnectionRequest_{
    int id;
    char mqName[MAX_DATA_LEN];
}ConnectionRequest;

typedef Decrypter DisconnectionRequest;

typedef struct EncryptedData_{
    char encryptedData[MAX_DATA_LEN];
    int encryptedDataLen;
}EncryptedData;

typedef struct DecryptedData_{
    char plainData[MAX_DATA_LEN];
    int plainDataLen;
    int decrypterId;
}DecryptedData;