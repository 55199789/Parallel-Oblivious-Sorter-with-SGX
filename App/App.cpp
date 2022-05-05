/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <math.h>
# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "sgx_tcrypto.h"
#include "App.h"
#include <sgx_uswitchless.h>
#include "Enclave_u.h"
#include <algorithm>
#include <execution>
#include <chrono>
#include <thread>
#include "threads_conf.h"
/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
    {
        SGX_ERROR_NDEBUG_ENCLAVE,
        "The enclave is signed as product enclave, and can not be created as debuggable enclave.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

void loop(int tid) {
    sgx_status_t ret = ecall_loop(global_eid, tid);
}

static std::thread threads[THREAD_NUM];
void threads_init() {
    printf("Thread num = %d\n", THREAD_NUM);
    for (uint32_t i = 1; i < THREAD_NUM; i++) {
        // threads[i] = std::thread(loop, i);
        threads[i] = std::thread([](int tid){
            ecall_loop(global_eid, tid);
        }, i);
    }
}

void threads_finish() {
    sgx_status_t ret = ecall_threads_down(global_eid);
    for (uint32_t i = 1; i < THREAD_NUM; i++)
        threads[i].join();
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(const sgx_uswitchless_config_t* us_config)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    const void* enclave_ex_p[32] = { 0 };

    enclave_ex_p[SGX_CREATE_ENCLAVE_EX_SWITCHLESS_BIT_IDX] = (const void*)us_config;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave_ex(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL, SGX_CREATE_ENCLAVE_EX_SWITCHLESS, enclave_ex_p);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    printf("%s", str);
}

void merge(int A[], uint32_t left, uint32_t right, uint32_t end, int B[])
{
    uint32_t i = left; 
    uint32_t j = right; 
    uint32_t k = left;
    for(;j<end && i<right; k++)
        if (A[i]<=A[j])
            B[k] = A[i++];
        else 
            B[k] = A[j++];
    if(i<right) memcpy(B+k, A+i, sizeof(int)*(right-i));
    else if(j<end) memcpy(B+k, A+j, sizeof(int)*(end-j));
}

void mergeSort(int A[], int B[], uint32_t n) 
{
    for(uint32_t width = 1; width<n;width<<=1)
    {
        for(uint32_t i = 0;i<n;i+=2*width)
            merge(A, i, std::min(i+width, n), std::min(i+2*width, n), B);
        // for(uint32_t i=0;i<n;i++) 
        //     A[i] = B[i];
        memcpy(A, B, sizeof(int)*n);
    }
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);
    if(argc!=2){
        printf("./app N\n");
        return -1;
    }
    uint32_t N = atoi(argv[1]);
    uint32_t N_ = (N*4)%16==0?N: ((N*4)/16*16+16)/4;

    sgx_uswitchless_config_t us_config = SGX_USWITCHLESS_CONFIG_INITIALIZER;
    us_config.num_uworkers = 1;
    us_config.num_tworkers = 1;

    /* Initialize the enclave */
    if(initialize_enclave(&us_config) < 0)
    {
        printf("Error: enclave initialization failed\n");
        return -1;
    }
 
    threads_init();

    using std::chrono::high_resolution_clock;
    using std::chrono::duration_cast;
    using std::chrono::duration;
    using std::chrono::milliseconds;

    double epsilon = 1;

    printf("Size of plaintext array: %lf MB\n", sizeof(int)*N_*1.0/1024/1024);
    srand(time(NULL));
    int *pArr = new int[N_];
    int *cArr = new int[N_];
    int *cArr2 = new int[N_];
    int *buffer = new int[N_];
    for(uint32_t i=0;i<N;i++)pArr[i]=rand();
    // for(uint32_t i=0;i<N;i++)pArr[i] = N-i-1;
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    auto t1 = high_resolution_clock::now();
    auto t2 = high_resolution_clock::now();
    duration<double, std::milli> ms_double = t2 - t1;

    ecallEncryptArr(global_eid, &ret, (uint8_t*)pArr, (uint8_t*)cArr,  N*sizeof(int));
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    t1 = high_resolution_clock::now();

    ecallEncryptArr(global_eid, &ret, (uint8_t*)pArr, (uint8_t*)cArr2,  N*sizeof(int));
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    ecallDecryptArr(global_eid, &ret,(uint8_t*)cArr, (uint8_t*)cArr,  N*sizeof(int));
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }
    
    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    printf("encryption/decryption time\t\t\t%lf ms\n", ms_double.count() );


    t1 = high_resolution_clock::now();

    ecall_OneByOne(global_eid, pArr, buffer, N);

    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    printf("block by block encryption/decryption time\t%lf ms\n", ms_double.count() );


    for(uint32_t i=0;i<N;i++)
        if(cArr[i]!=pArr[i])
        {
            printf("Encryption/Decryption has bugs!\n");
            goto FAIL;
        }
    printf("Encryption/Decryption test passed!\n");
    ecallEncryptArr(global_eid, &ret, (uint8_t*)pArr, (uint8_t*)cArr,  N*sizeof(int));
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    t1 = high_resolution_clock::now();

    std::sort(pArr, pArr+N);

    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    printf("std::sort\t\t%lf ms\n", ms_double.count() );
    
    ret = ecallDecryptArr(global_eid, &ret,(uint8_t*)cArr, (uint8_t*)pArr,  N*sizeof(int));
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }
    t1 = high_resolution_clock::now();
    // std::sort(std::execution::par_unseq, pArr, pArr+N);
    mergeSort(pArr, buffer, N);

    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    printf("Merge sort\t\t%lf ms\n", ms_double.count() );
    for(uint32_t i=1;i<N;i++)
        if(pArr[i]<pArr[i-1])
        {
            printf("Error: pArr[%u] = %u , cArr[%u] = %u!\n", i, pArr[i], i, cArr[i]);
            goto FAIL;
        }


    ret = ecallDecryptArr(global_eid, &ret,(uint8_t*)cArr, (uint8_t*)pArr,  N*sizeof(int));
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }
    t1 = high_resolution_clock::now();

    // std::sort(std::execution::par_unseq, pArr, pArr+N);
    std::make_heap(pArr, pArr+N);
    for(int i = 0;i<N-1; i++)
        std::pop_heap(pArr, pArr+N-i);

    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    printf("Heap sort\t\t%lf ms\n", ms_double.count() );

    t1 = high_resolution_clock::now();

    ret = ecall_ObliviousSort(global_eid, cArr, N);

    t2 = high_resolution_clock::now();
    ms_double = t2 - t1;
    printf("Ecall bitonic sort\t%lf ms\n", ms_double.count() );

    // t1 = high_resolution_clock::now();

    // if (N<2000000) ret = ecall_DPSort(global_eid, cArr2, N, epsilon);

    // t2 = high_resolution_clock::now();
    // ms_double = t2 - t1;
    // printf("Ecall differentially oblivious sort\t%lf ms\n", ms_double.count());


    ecallDecryptArr(global_eid, &ret,(uint8_t*)cArr, (uint8_t*)cArr, N*sizeof(int));

    for(uint32_t i=0;i<N;i++)
        if(cArr[i]!=pArr[i])
        {
            printf("Error: pArr[%u] = %u , cArr[%u] = %u!\n", i, pArr[i], i, cArr[i]);
            goto FAIL;
        }
    printf("Ecall bitonic sort test passed!\n");
    // if (N>=2000000) 
    //     goto FAIL;
    // ecallDecryptArr(global_eid, &ret,(uint8_t*)cArr2, (uint8_t*)cArr2, N*sizeof(int));
    // for(int i=0;i<10;i++)printf("%u ", cArr2[i]);
    // printf("\n");

    // for(uint32_t i=0;i<N;i++)
    //     if(cArr2[i]!=pArr[i])
    //     {
    //         printf("Error: pArr[%u] = %u , cArr2[%u] = %u!\n", i, pArr[i], i, cArr2[i]);
    //         goto FAIL;
    //     }
    // printf("Ecall differentially oblivious sort test passed!\n");

FAIL:
    printf("\033[34mThreads_finish \033[0m\n");
    threads_finish();

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    printf("Info: Cxx11DemoEnclave successfully returned.\n");
    return 0;
}

