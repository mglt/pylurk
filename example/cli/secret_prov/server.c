/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Labs */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "secret_prov.h"

//#define PORT "4433"
//static uint16_t PORT; 
#define EXPECTED_STRING "MORE"
#define FIRST_SECRET "FIRST_SECRET"
#define SECOND_SECRET "42" /* answer to ultimate question of life, universe, and everything */

// #define SRV_CRT_PATH "../ssl/server.crt"
// #define SRV_KEY_PATH "../ssl/server.key"

// #define SECRET_PATH "../ssl/_Ed25519PrivateKey-ed25519-pkcs8.der"
//#define SECRET_SIZE_MAX 10000

#define ENFORCE_VALIDATION  1
//#define EXPECTED_MRENCLAVE "dac61ce6d1763f1875e5b486126ebe42ed7003f1c8e52938f18af508ee1b430a"
static char EXPECTED_MRENCLAVE[ 65 ];
//#define EXPECTED_MRSIGNER "e725999b742f47419e5a074b32d8c869711d68d20d059dc987e5c87424cb37a9"
static char EXPECTED_MRSIGNER[ 65 ];
//#define EXPECTED_ISV_PROD_ID 0
static uint16_t EXPECTED_ISV_PROD_ID; 
//#define EXPECTED_ISV_SVN 0
static uint16_t EXPECTED_ISV_SVN; 


static pthread_mutex_t g_print_lock;

static void hexdump_mem(const void* data, size_t size) {
    uint8_t* ptr = (uint8_t*)data;
    for (size_t i = 0; i < size; i++)
        printf("%02x", ptr[i]);
    printf("\n");
}

char * bytes_to_str( uint8_t* data, size_t size, char* output_str) {
  char *ptr = output_str ;	  
  for (size_t i = 0; i < size; i++)
    ptr += sprintf(ptr, "%02x", data[i] );
  output_str[ 2 * size  ] =  '\0';
  return 0;  
}
      
/* our own callback to verify SGX measurements during TLS handshake */
static int verify_measurements_callback(const char* mrenclave, const char* mrsigner,
                                        const char* isv_prod_id, const char* isv_svn) {
    int ret = 0;
    char report_str[ 2 * 32 + 1 ]; /* mrsigner and mrenclave are 32 byte long */ 
    assert(mrenclave && mrsigner && isv_prod_id && isv_svn);

    pthread_mutex_lock(&g_print_lock);
    puts("Received the following measurements from the client:");
    printf("  - MRENCLAVE:   "); hexdump_mem(mrenclave, 32);
    printf("  - MRSIGNER:    "); hexdump_mem(mrsigner, 32);
    printf("  - ISV_PROD_ID: %hu\n", *((uint16_t*)isv_prod_id));
    printf("  - ISV_SVN:     %hu\n", *((uint16_t*)isv_svn));
    if ( ENFORCE_VALIDATION == 1 ) {
      printf("Comparing with provided values:\n" );
      bytes_to_str( (uint8_t*) mrenclave, 32, report_str ); 
      if( strcmp( EXPECTED_MRENCLAVE, report_str ) != 0 ) {
        printf( "  - ERROR Expecting MRENCLAVE:   %s\n", EXPECTED_MRENCLAVE );
        ret = 1;	
      }
      bytes_to_str( (uint8_t*) mrsigner, 32, report_str ); 
      if( strcmp( EXPECTED_MRSIGNER, report_str ) != 0 ) {
        printf( "  - ERROR Expecting MRSIGNER:   %s\n",  EXPECTED_MRSIGNER );
        ret = 1;	
      }
      if( EXPECTED_ISV_PROD_ID != *((uint16_t*)isv_prod_id) ){
        printf( "  - ERROR Expecting ISV_PROD_ID:   %hu\n", (uint16_t) EXPECTED_ISV_PROD_ID );
        ret = 1;	
      }
      if( EXPECTED_ISV_SVN != *((uint16_t*)isv_svn) ){
        printf( "  - ERROR Expecting ISV_SVN:   %hu\n", (uint16_t) EXPECTED_ISV_SVN );
        ret = 1;	
      }
    } 
    else {
      puts("[ WARNING: In reality, you would want to compare against expected values! ]");
    }
    pthread_mutex_unlock(&g_print_lock);

    return ret;
}

/* this callback is called in a new thread associated with a client; be careful to make this code
 * thread-local and/or thread-safe */
static int communicate_with_client_callback(struct ra_tls_ctx* ctx) {
    int ret;

    /* if we reached this callback, the first secret was sent successfully */
    printf("--- Sent secret1 ---\n");

    /* let's send another secret (just to show communication with secret-awaiting client) */
    uint8_t buf[sizeof(EXPECTED_STRING)] = {0};

    ret = secret_provision_read(ctx, buf, sizeof(buf));
    if (ret < 0) {
        if (ret == -ECONNRESET) {
            /* client doesn't want another secret, shutdown communication gracefully */
            return 0;
        }

        fprintf(stderr, "[error] secret_provision_read() returned %d\n", ret);
        return -EINVAL;
    }

    if (memcmp(buf, EXPECTED_STRING, sizeof(EXPECTED_STRING))) {
        fprintf(stderr, "[error] client sent '%s' but expected '%s'\n", buf, EXPECTED_STRING);
        return -EINVAL;
    }

    ret = secret_provision_write(ctx, (uint8_t*)SECOND_SECRET, sizeof(SECOND_SECRET));
    if (ret < 0) {
        fprintf(stderr, "[error] secret_provision_write() returned %d\n", ret);
        return -EINVAL;
    }

    printf("--- Sent secret2 = '%s' ---\n", SECOND_SECRET);
    return 0;
}


//int main(void) {
int secret_file_provisionning_server( /* The following variables are used to 
					 initiates static global variables */
	                              char *mrenclave_str, 
		                      char *mrsigner_str, 
				      uint16_t isv_prod_id, 
				      uint16_t isv_svn,
				      /* The following variables are only used within
				         this function */
				      char *PORT, 
				      char *SRV_CRT_PATH, 
				      char *SRV_KEY_PATH, 
				      char *SECRET_PATH ){

    int ret = pthread_mutex_init(&g_print_lock, NULL);
    if (ret < 0)
        return ret;
//    char *mrenclave_str = "dac61ce6d1763f1875e5b486126ebe42ed7003f1c8e52938f18af508ee1b430a";
//    char *mrsigner_str = "e725999b742f47419e5a074b32d8c869711d68d20d059dc987e5c87424cb37a9";
//#define PORT "4433"
//    char *PORT = "4433";
    uint16_t SECRET_SIZE_MAX = 10000; 
    strcpy( EXPECTED_MRENCLAVE, mrenclave_str ); 
    strcpy( EXPECTED_MRSIGNER, mrsigner_str );
    EXPECTED_ISV_PROD_ID = 0;
    EXPECTED_ISV_SVN = 0; 

    /* reading FIRST_SECRET from file */
    FILE* fptr1;
    uint8_t secret_bytes[SECRET_SIZE_MAX];
    char c;
    int i = 0;
    int secret_len = 0;
    fptr1 = fopen(SECRET_PATH, "r");
  
    if (fptr1 == NULL) {
        fprintf(stderr, "[error] unable to open secret path\n");
        return 1;
    }

    c = fgetc(fptr1);
    secret_len += 1;
    for (i = 0; i <= SECRET_SIZE_MAX && c != EOF; i++) {
        //printf("c: %X", (uint8_t) c );
        secret_bytes[i] = (uint8_t) c;
        c = fgetc(fptr1);
	secret_len += 1;
    }
    // Print the bytes as string
    printf("secret_key [%d bytes]:\n", secret_len);
    for (i = 0; i <= secret_len; i++) {
        printf("%X ", secret_bytes[ i ]  );
    }
    printf("\n" );
    // Close the file
    fclose(fptr1);
   

    //puts("--- Starting the Secret Provisioning server on port " PORT " ---");
    printf("--- Starting the Secret Provisioning server on port %s ---\n", PORT);
    /*ret = secret_provision_start_server((uint8_t*)FIRST_SECRET, 
              sizeof(FIRST_SECRET),
              PORT, SRV_CRT_PATH, SRV_KEY_PATH,
              verify_measurements_callback,
              communicate_with_client_callback);*/
    ret = secret_provision_start_server(secret_bytes,
            secret_len,
            PORT, SRV_CRT_PATH, SRV_KEY_PATH,
            verify_measurements_callback,
            communicate_with_client_callback);
    if (ret < 0) {
        fprintf(stderr, "[error] secret_provision_start_server() returned %d\n", ret);
        return 1;
    }

    pthread_mutex_destroy(&g_print_lock);
    return 0;
}


int main( int argc, char** argv ) {
  //char *mrenclave_str = "dac61ce6d1763f1875e5b486126ebe42ed7003f1c8e52938f18af508ee1b430a";
  char *mrenclave_str = argv[1];
  //char *mrsigner_str = "e725999b742f47419e5a074b32d8c869711d68d20d059dc987e5c87424cb37a9";
  char *mrsigner_str = argv[2]; 
  //uint16_t isv_prod_id = 0; 
  uint16_t isv_prod_id = *argv[3]; 
  //uint16_t isv_svn = 0; 
  uint16_t isv_svn = *argv[4]; 
  //char *PORT = "4433";
  char *PORT = argv[ 5 ];
  //char *SRV_CRT_PATH = "../ssl/server.crt"; 
  char *SRV_CRT_PATH = argv[ 6 ]; 
  //char *SRV_KEY_PATH = "../ssl/server.key";
  char *SRV_KEY_PATH = argv[ 7 ];
  //char *SECRET_PATH = "../ssl/_Ed25519PrivateKey-ed25519-pkcs8.der"; 
  char *SECRET_PATH = argv[ 8 ]; 
//  strcpy( mrenclave_str, argv[1] ); 

//#define SRV_CRT_PATH "../ssl/server.crt"
//#define SRV_KEY_PATH "../ssl/server.key"

//#define SECRET_PATH "../ssl/_Ed25519PrivateKey-ed25519-pkcs8.der"
//#define SECRET_SIZE_MAX 10000
//#define PORT "4433"



   secret_file_provisionning_server( /* The following variables are used to 
					 initiates static global variables */
	                              mrenclave_str, 
		                      mrsigner_str, 
				      isv_prod_id, 
				      isv_svn,
				      /* The following variables are only used within
				         this function */
				      PORT, 
				      SRV_CRT_PATH, 
				      SRV_KEY_PATH, 
				      SECRET_PATH );

}	
