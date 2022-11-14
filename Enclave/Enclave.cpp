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
#include <math.h>
#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <string.h>
#include <thread>
#include <algorithm>
#include <chrono>
#include <random>
#include "sgx_eid.h"
#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include "sgx_thread.h"
#include "sgx_tseal.h"
#include "Enclave.h"
#include "Enclave_t.h"  /* print_string */
#include "../App/threads_conf.h"
/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
sgx_aes_ctr_128bit_key_t* p_key = NULL;
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

// multi-threading
bool volatile is_exit = false;
std::atomic<bool> sync_flag_[THREAD_NUM];
std::function<void()> fun_ptrs[THREAD_NUM];

const uint32_t secureBufSize = 96*1000*1000;
uint8_t *buf = new uint8_t[secureBufSize];;

void task_notify(int threads) {
    for (int i = 1; i < threads; i++) {
        sync_flag_[i] = true;
    }
}

void ecall_loop(int tid) {

    while(true) {
        {
            while(sync_flag_[tid] == false);
            if (is_exit == true) 
                return;
            if (fun_ptrs[tid] == NULL)
                printf("[ecall_loop][%d][func is null]\n", tid);
            fun_ptrs[tid]();
            fun_ptrs[tid] = NULL;
            sync_flag_[tid] = false;
        }
    }
}

void task_wait_done(int threads) {
    for (int i = 1; i < threads; i++) {
        while(sync_flag_[i] == true);
    }
}


void ecall_threads_down() {
    is_exit = true;
    for (int i = 1; i < THREAD_NUM; i++)
        sync_flag_[i] = true;
    delete[] buf;
}

void ctr128_inc_for_bytes(uint8_t *ctr, uint64_t len) {

    uint64_t inc_num = (len / 16) + (len % 16 ? 1 : 0);

    uint8_t rev_ctr[16];
    for (int i = 0; i < 16; i++) {
        rev_ctr[i] = ctr[15-i];
    }

    uint64_t *lo = (uint64_t *)(rev_ctr);
    uint64_t *hi = (uint64_t *)(rev_ctr + 8);

    uint64_t tmp_lo = *lo;
    *lo = *lo + inc_num;
    if (*lo < tmp_lo)
        *hi = *hi + 1;
    
    for (int i = 0; i < 16; i++) {
        ctr[i] = rev_ctr[15-i];
    }
}


void ctr128_inc_for_count(unsigned char *ctr, uint64_t count) {

    uint64_t inc_num = count;

    unsigned char rev_ctr[16];
    for (int i = 0; i < 16; i++) {
        rev_ctr[i] = ctr[15-i];
    }

    uint64_t *lo = (uint64_t *)(rev_ctr);
    uint64_t *hi = (uint64_t *)(rev_ctr + 8);

    uint64_t tmp_lo = *lo;
    *lo = *lo + inc_num;
    if (*lo < tmp_lo)
        *hi = *hi + 1;
    
    for (int i = 0; i < 16; i++) {
        ctr[i] = rev_ctr[15-i];
    }
}


sgx_status_t ecallEncryptArr(uint8_t* pSrc, uint8_t* pDst, const uint32_t cipher_len)
{
    sgx_status_t resp;
    if(p_key==NULL) 
    {
        const uint32_t len = sizeof(sgx_aes_ctr_128bit_key_t);
        p_key = (sgx_aes_ctr_128bit_key_t*)(new uint8_t[len]);
        resp = sgx_read_rand((uint8_t*)p_key, len);
        if (resp != SGX_SUCCESS)
            return resp;
    }

    uint8_t ctr[16]={0};
    resp = sgx_aes_ctr_encrypt(
        p_key,
        pSrc,
        cipher_len,
        ctr, 128,
        pDst);

    return resp;
}

sgx_status_t ecallDecryptArr(uint8_t* pSrc, uint8_t* pDst, uint32_t cipher_len)
{
    uint8_t ctr[16]={0};
    sgx_status_t resp = sgx_aes_ctr_decrypt(
        p_key,
        pSrc,
        cipher_len,
        ctr, 128,
        pDst);

    return resp;
}

template<typename Key>
static void bitonicMerge(Key a[], uint32_t low, uint32_t cnt, bool dir) 
{
    if (cnt<=1) return;
    uint32_t k = 1;
    while(k<cnt) k<<=1;
    k>>=1;
    for (uint32_t i=low; i<low+cnt-k; i++)
        if(dir==(a[i]>a[i+k]))
            std::swap(a[i], a[i+k]);
    bitonicMerge<Key>(a, low, k, dir);
    bitonicMerge<Key>(a, low+k, cnt-k, dir);
}

template<typename Key>
static inline uint32_t lowerBound(const uint32_t add) 
{
    return (((add*sizeof(Key))>>4)<<4)/sizeof(Key);
}

template<typename Key>
static inline uint32_t upperBound(const uint32_t add) 
{
    if((((add*sizeof(Key))>>4)<<4)==add*sizeof(Key)) return add; 
    return (((add*sizeof(Key))|15)+1)/sizeof(Key);
}

template<typename Key>
static void bitonicMergeEx(Key *secureBuf, uint32_t secureBufSize, 
                    Key *cArr, uint32_t low, uint32_t cnt, bool dir) 
{
    if (cnt<=1) return;
    uint32_t k = 1;
    while(k<cnt) k<<=1;
    k>>=1;

    uint32_t st = lowerBound<Key>(low);
    uint32_t ed = upperBound<Key>(low+cnt);
    if((ed-st)*sizeof(Key)<=secureBufSize)
    {
        uint8_t ctr_de[16] = {0};
        uint8_t ctr_en[16] = {0};
        ctr128_inc_for_bytes(ctr_de, sizeof(Key)*st);
        memcpy(ctr_en, ctr_de, 16);
        sgx_aes_ctr_decrypt(p_key, (uint8_t*)(cArr+st), 
                            (ed-st)*sizeof(Key), ctr_de, 128, (uint8_t*)secureBuf);

        low -= st;

        for (uint32_t i=low; i<low+cnt-k; i++)
            if(dir==(secureBuf[i]>secureBuf[i+k]))
                std::swap(secureBuf[i], secureBuf[i+k]);
        bitonicMerge<Key>(secureBuf, low, k, dir);
        bitonicMerge<Key>(secureBuf, low+k, cnt-k, dir);
        
        sgx_aes_ctr_encrypt(p_key, (uint8_t*)secureBuf, (ed-st)*sizeof(Key), 
                            ctr_en, 128, (uint8_t*)(cArr+st));
        return;
    }

    // Enforce it to be multiple of 16
    uint32_t batchCnt = (secureBufSize-1024)/(2*sizeof(Key));
    batchCnt = lowerBound<Key>(batchCnt);
    ed = upperBound<Key>(low+cnt-k);
    uint32_t epoch = (ed-st)/batchCnt + ((ed-st)%batchCnt!=0);
    uint32_t rSt = lowerBound<Key>(low+k);
    uint32_t rEd = 0;
    Key *leftArr = cArr+st; 
    Key *rightArr = cArr+rSt;
    uint32_t prevLeftLow = low; 
    uint32_t prevRightLow = low + k; 
    uint32_t _cnt = cnt; 
    uint8_t ctr_lDe[16] = {0};
    uint8_t ctr_rDe[16] = {0};
    uint8_t ctr_lEn[16] = {0};
    uint8_t ctr_rEn[16] = {0};
    ctr128_inc_for_bytes(ctr_lDe, sizeof(Key)*st);
    ctr128_inc_for_bytes(ctr_rDe, sizeof(Key)*rSt);
    memcpy(ctr_lEn, ctr_lDe, 16);
    memcpy(ctr_rEn, ctr_rDe, 16);
    for(uint32_t e = 0; e<epoch; e++) 
    {

        uint32_t leftCnt = std::min(batchCnt, ed - st); 
        leftCnt = lowerBound<Key>(leftCnt);
        uint32_t actualCnt = std::min(cnt-k, st + leftCnt - prevLeftLow);
        sgx_aes_ctr_decrypt(p_key, (uint8_t *)leftArr, 
            leftCnt*sizeof(Key), ctr_lDe, 128, (uint8_t *)secureBuf);

        rEd = upperBound<Key>(prevRightLow + actualCnt);
        uint32_t rightCnt = rEd - rSt; 
        sgx_aes_ctr_decrypt(p_key, (uint8_t *)rightArr, 
            rightCnt*sizeof(Key), ctr_rDe, 128, 
            (uint8_t *)(secureBuf+leftCnt));
        
        uint32_t lIdx = prevLeftLow - st;
        uint32_t rIdx = prevRightLow + leftCnt - rSt;
        for(uint32_t i=0;i<actualCnt; i++)
            if(dir==(secureBuf[lIdx + i]>secureBuf[rIdx + i]))
                std::swap(secureBuf[lIdx + i], secureBuf[rIdx + i]);
        
        sgx_aes_ctr_encrypt(p_key, (uint8_t *)secureBuf, 
            leftCnt*sizeof(Key), ctr_lEn, 128, (uint8_t *)leftArr);
        sgx_aes_ctr_encrypt(p_key, (uint8_t *)(secureBuf+leftCnt), 
            rightCnt*sizeof(Key), ctr_rEn, 128, (uint8_t *)rightArr);
        leftArr += leftCnt; 
        rightArr += rightCnt; 
        st += leftCnt; 
        rSt += rightCnt; 
        prevLeftLow = st;
        prevRightLow = rSt;
        cnt -= actualCnt;
    }

    bitonicMergeEx<Key>(secureBuf, secureBufSize, cArr, low, k, dir);
    bitonicMergeEx<Key>(secureBuf, secureBufSize, cArr, low+k, _cnt-k, dir);
}

template<typename Key> 
void bitonicSort(Key *arr, uint32_t low, uint32_t cnt, bool dir)
{
    if (cnt<=1) return;
    int k = cnt/2;
    bitonicSort<Key>(arr, low, k, !dir);
    bitonicSort<Key>(arr, low+k, cnt - k, dir);
    bitonicMerge<Key>(arr, low, cnt, dir);
}

template<typename Key>
void bitonicSortEx(Key *secureBuf, uint32_t secureBufSize, 
                    Key *cArr, uint32_t low, uint32_t cnt, bool dir)
{
    if (cnt<=1) return;
    uint32_t k = cnt>>1;
    uint32_t st = lowerBound<Key>(low);
    uint32_t ed = upperBound<Key>(low+cnt);
    if((ed-st)*sizeof(Key)<=secureBufSize)
    {
        uint8_t ctr[16] = {0};
        ctr128_inc_for_bytes(ctr, sizeof(Key)*st);
        sgx_aes_ctr_decrypt(p_key, (uint8_t*)(cArr+st), 
                            (ed-st)*sizeof(Key), ctr, 128, (uint8_t*)secureBuf);
        
        low -= st;
        bitonicSort<Key>(secureBuf, low, k, !dir);
        bitonicSort<Key>(secureBuf, low+k, cnt - k, dir);
        bitonicMerge<Key>(secureBuf, low, cnt, dir);

        memset(ctr, 0, sizeof(ctr));
        ctr128_inc_for_bytes(ctr, sizeof(Key)*st);
        sgx_aes_ctr_encrypt(p_key, (uint8_t*)secureBuf, (ed-st)*sizeof(Key), 
                            ctr, 128, (uint8_t*)(cArr+st));
        return;
    }
    bitonicSortEx<Key>(secureBuf, secureBufSize, cArr, low, k, !dir);
    bitonicSortEx<Key>(secureBuf, secureBufSize, cArr, low+k, cnt - k, dir);
    bitonicMergeEx<Key>(secureBuf, secureBufSize, cArr, low, cnt, dir);
}

template<typename Key>
void bitonicSortParallel(Key *secureBuf, uint32_t secureBufSize, 
                            Key *cArr, uint32_t cnt, 
                            const uint32_t maxThreadNum = THREAD_NUM)
{
    uint32_t threadNum = 1;
    uint32_t lvl = 0;
    while(threadNum<=maxThreadNum) 
    {
        threadNum<<=1;
        lvl++;
    }
    threadNum>>=1;
    // if(threadNum==1)
    // {
    //     bitonicSortEx<Key>(secureBuf, secureBufSize, cArr, 0, cnt, 1); 
    //     return;
    // }

    // bitonicSort each interval
    uint32_t st[threadNum];
    uint32_t actualCnt[threadNum];
    bool actualDir[threadNum];

    actualDir[0] = lvl&1;
    for(uint32_t tid=0;tid<threadNum-1;tid++)
    {
        for(uint32_t i = 0;i<(1<<tid);i++)
            actualDir[i+(1<<tid)]=!actualDir[i];
    }

    uint32_t subcnt = upperBound<int>(cnt/threadNum);
    uint32_t bufSizePerThread = secureBufSize/threadNum;
    for(uint32_t tid=0;tid<threadNum;tid++) 
    {
        st[tid] = lowerBound<int>(subcnt*tid);
        actualCnt[tid] = tid+1!=threadNum ? subcnt:(cnt-st[tid]);
        Key *curSecureBuf = (Key *)((uint8_t*)(secureBuf)+bufSizePerThread*tid);
        fun_ptrs[tid] = [curSecureBuf, bufSizePerThread, cArr, tid, &st, &actualCnt, &actualDir](){
            bitonicSortEx<Key>(curSecureBuf, bufSizePerThread, cArr, 
                st[tid], actualCnt[tid], actualDir[tid]);
        };
    }
    task_notify(threadNum);
    fun_ptrs[0]();
    task_wait_done(threadNum);
    
    // Merge 
    threadNum>>=1;
    while(threadNum)
    {
        bufSizePerThread = secureBufSize/threadNum;
        for(uint32_t tid=0;tid<threadNum;tid++) 
        {
            st[tid] = st[tid*2];
            actualCnt[tid] = actualCnt[tid*2] + actualCnt[tid*2+1];
            actualDir[tid] = !actualDir[tid*2];
        }
        // merge two intervals
        for(uint32_t tid=0;tid<threadNum;tid++) 
        {
            Key *curSecureBuf = (Key *)((uint8_t*)(secureBuf)+bufSizePerThread*tid);
            fun_ptrs[tid] = [curSecureBuf, bufSizePerThread, tid, cArr, &st, &actualCnt, &actualDir](){
                bitonicMergeEx<Key>(curSecureBuf, bufSizePerThread, cArr, 
                                    st[tid], actualCnt[tid], actualDir[tid]);
            };
        }
        task_notify(threadNum);
        fun_ptrs[0]();
        task_wait_done(threadNum);
        threadNum>>=1;
    }
}

void ecall_ObliviousSort(int cArr[], uint32_t cnt) 
{   
    // Does not allocate memory here since we exclude this part from timing 
    // const uint32_t secureBufSize = 80*1000*1000;
    // uint8_t *buf = new uint8_t[secureBufSize];
    bitonicSortParallel<int>((int*)buf, secureBufSize, cArr, cnt);
    // delete[] buf;
}

static double lap(double b)
{
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_real_distribution<double> unif(0.0, 1.0);
    double cdf = unif(gen);
    return -b*(cdf>0.5?1:-1)*log(1-2*abs(cdf-0.5));
}


template<typename Key>
static void _bitonicMerge(Key a[], int low, int cnt, uint32_t bit, bool dir) 
{
    if (cnt>1) 
    {
        int k = 1;
        while(k<cnt) k<<=1;
        k>>=1;
        for (int i=low; i<low+cnt-k; i++)
            if(
                dir==( (a[i]&bit) > (a[i+k]&bit) ) 
            )
                std::swap(a[i], a[i+k]);
        _bitonicMerge<Key>(a, low, k, bit, dir);
        _bitonicMerge<Key>(a, low+k, cnt-k, bit, dir);
    }
}

template<typename Key>
void _bitonicSort(Key *arr, uint32_t low, uint32_t cnt, uint32_t bit, bool dir)
{
    if (cnt>1)
    {
        int k = cnt/2;
        _bitonicSort<Key>(arr, low, k, bit, !dir);
        _bitonicSort<Key>(arr, low+k, cnt - k, bit, dir);
        _bitonicMerge<Key>(arr, low, cnt, bit, dir);
    }
}

template<class Key>
void dpSortBit(Key* secureBuf, Key *cArr, uint32_t cnt, uint32_t s, uint32_t bit, double epsilon) 
{
    uint32_t bufCnt = 0; 
    uint32_t targetCnt = 0;
    uint8_t ctr_de[16]={0};
    uint8_t ctr_en[16]={0};
    // For dp prefix sum computation 
    uint32_t dpPrefixSum = 0;
    std::vector<double> alpha(ceil(log2(cnt/s + 1))+1, 0);
    std::vector<double> alpha_(ceil(log2(cnt/s + 1))+1, 0);
    double prefixSumEpsilon = epsilon / (log2(cnt/s)+1); 
    Key *tArr = cArr;
    for(uint32_t i=0, k = 1;i<cnt;i+=s, k++)
    {
        uint32_t num = lowerBound<int>(std::min(s, cnt-i)); 
        sgx_aes_ctr_decrypt(p_key, (uint8_t *)cArr, num*sizeof(Key), ctr_de, 128, (uint8_t *)(secureBuf+bufCnt));

        cArr+=num;
        uint32_t zeroBalls = 0;
        for(uint32_t t = 0; t<num; t++)
            zeroBalls += ((bit&(secureBuf[t+bufCnt]))==0);

        bufCnt+=num;

        // _bitonicSort(secureBuf, 0, bufCnt, bit, 1);
        std::stable_sort(secureBuf, secureBuf+bufCnt, [bit](const Key &a, const Key &b)
        {
            return (a&bit)<(b&bit);
        });

        // Compute dp prefix sum 
        uint32_t h = 0;
        while((k&(1<<h))==0) ++h; 
        alpha[h] = 0;
        for(uint32_t t = 0; t<h; t++)
            alpha[h] += alpha[t];
        alpha[h] += zeroBalls;
        for(uint32_t t = 0; t<h; t++)
            alpha[t] = alpha_[t] = 0;
        alpha_[h] = alpha[h] + lap(1.0/prefixSumEpsilon);

        h = 0;
        double sum = 0; 
        while(k>>h) 
        {
            if(((k>>h)&1)==1) 
                sum += alpha_[h]; 
            ++h; 
        }
        dpPrefixSum = sum; 

        if(dpPrefixSum > targetCnt + s)
        {
            uint32_t curNum = std::min(bufCnt, dpPrefixSum - s - targetCnt);
            curNum = lowerBound<int>(curNum);
            sgx_aes_ctr_encrypt(p_key, (uint8_t*)secureBuf, curNum*sizeof(Key), 
                                ctr_en, 128, (uint8_t*)tArr);
            tArr += curNum;
            targetCnt += curNum;

            // Eliminate the first curNum elements in buffer
            bufCnt -= curNum; 
            for(uint32_t j = 0; j<bufCnt;j++)
                secureBuf[j] = secureBuf[j+curNum]; 
        }
        
        if(bufCnt>2*s) bufCnt = 2*s;
    }

    if(0 != bufCnt) 
    {
        uint32_t curNum = upperBound<int>(bufCnt); 
        sgx_aes_ctr_encrypt(p_key, (uint8_t*)secureBuf, bufCnt*sizeof(Key), 
                            ctr_en, 128, (uint8_t*)tArr);
    }
}

void ecall_DPSort(int *cArr, uint32_t cnt, double epsilon) 
{
    // ecallDecryptArr((uint8_t *)cArr, (uint8_t *)buf, cnt*sizeof(int));
    uint32_t bitNum = 31; 
    uint32_t s = lowerBound<int>(uint32_t(pow(log2(cnt), 3))); 
    for(int k = 0; k<bitNum; k++) 
    {
        dpSortBit<int>((int *)buf, cArr, cnt, s, 1<<k, epsilon);
    }
}

void ecall_OneByOne(int *pArr, int *cArr, 
                    uint32_t cnt)
{
    uint8_t ctr[16] = {0};
    uint32_t K = pow(log2(cnt), 2);
    for(int i=0;i<cnt;i+=K)
    {
        sgx_aes_ctr_encrypt(p_key, (uint8_t*)pArr, K*sizeof(int), 
                    ctr, 128, (uint8_t *)cArr);
        pArr+=K; 
        cArr+=K; 
    }
}