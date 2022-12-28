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
#include <stdio.h> /* vsnprintf */
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
#include "Enclave_t.h" /* print_string */
/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
sgx_aes_ctr_128bit_key_t *p_key = NULL;
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

#define THREAD_NUM 32
const uint32_t secureBufSize = 800 * 1000 * 1000;
uint8_t *buf = new uint8_t[secureBufSize];

sgx_status_t ecallEncryptArr(uint8_t *pSrc, uint8_t *pDst, const uint32_t cipher_len)
{
    sgx_status_t resp;
    if (p_key == NULL)
    {
        const uint32_t len = sizeof(sgx_aes_ctr_128bit_key_t);
        p_key = (sgx_aes_ctr_128bit_key_t *)(new uint8_t[len]);
        resp = sgx_read_rand((uint8_t *)p_key, len);
        if (resp != SGX_SUCCESS)
            return resp;
    }

    uint8_t ctr[16] = {0};
    resp = sgx_aes_ctr_encrypt(
        p_key,
        pSrc,
        cipher_len,
        ctr, 128,
        pDst);

    return resp;
}

sgx_status_t ecallDecryptArr(uint8_t *pSrc, uint8_t *pDst, uint32_t cipher_len)
{
    uint8_t ctr[16] = {0};
    sgx_status_t resp = sgx_aes_ctr_decrypt(
        p_key,
        pSrc,
        cipher_len,
        ctr, 128,
        pDst);

    return resp;
}
/**
 * @brief Add counter by len bytes
 *
 * @param ctr 16-byte couter array
 * @param len the number of bytes to be incremented
 */
void ctr128_inc_for_bytes(uint8_t *ctr, uint64_t len)
{
    if (ctr == NULL || len == 0)
        return;
    uint64_t inc_num = (len / 16) + (len % 16 ? 1 : 0);

    uint8_t rev_ctr[16];
    for (int i = 0; i < 16; i++)
        rev_ctr[i] = ctr[15 - i];

    uint64_t *lo = (uint64_t *)(rev_ctr);
    uint64_t *hi = (uint64_t *)(rev_ctr + 8);

    uint64_t tmp_lo = *lo;
    *lo = *lo + inc_num;
    if (*lo < tmp_lo)
        *hi = *hi + 1;

    for (int i = 0; i < 16; i++)
        ctr[i] = rev_ctr[15 - i];
}

/**
 * @brief The largest address aligned with 16 byte <= add for 128-bit AES CTR en/decryption
 */
template <typename Key>
inline uint32_t lowerBound(uint32_t add)
{
    while (add * sizeof(Key) % 16 != 0)
        --add;
    return add;
}

/**
 * @brief The smallest address aligned with 16 byte >=add,
 *  combined with lowerBound as the region to be en/decrypted.
 */
template <typename Key>
inline uint32_t upperBound(uint32_t add)
{
    while (add * sizeof(Key) % 16 != 0)
        ++add;
    return add;
}

#define OMP_BITONIC_CNT (1 << 13)
/**
 * @brief Merge a bitonic sequence
 *
 * @tparam Key Key must support operator<()
 * @param a A decrypted array inside the enclave
 * @param low The starting index
 * @param cnt The number of elements
 * @param dir The direction, 1 is ascending, 0 is descending
 */
template <typename Key>
static void bitonicMerge(Key a[], uint32_t low, uint32_t cnt, bool dir)
{
    if (cnt <= 1)
        return;
    if (a == NULL)
        return;
    uint32_t k = 1;
    while (k < cnt)
        k <<= 1;
    k >>= 1;

    for (uint32_t i = low; i < low + cnt - k; i++)
        if (dir == (a[i] > a[i + k]))
            std::swap(a[i], a[i + k]);

    bitonicMerge<Key>(a, low, k, dir);
    bitonicMerge<Key>(a, low + k, cnt - k, dir);
}

/**
 * @brief Merge an encrypted bitonic array with the help of secure buffer of the given size
 *
 * @tparam Key Key must support operator<()
 * @param secureBuf a buffer inside the enclave
 * @param secureBufSize secure buffer size
 * @param cArr The encrypted array to be merged
 * @param low The start index
 * @param cnt The number of elements
 * @param dir 1 ascending, 0 descending
 */
template <typename Key>
static void bitonicMergeEx(const sgx_aes_ctr_128bit_key_t *p_key,
                           Key *secureBuf, uint32_t secureBufSize,
                           Key *cArr, uint32_t low, uint32_t cnt, bool dir)
{
    if (cnt <= 1)
        return;
    if (secureBuf == NULL || cArr == NULL)
        return;
    uint32_t k = 1;
    while (k < cnt)
        k <<= 1;
    k >>= 1;
    assert(k <= cnt);

    uint32_t st = lowerBound<Key>(low);
    uint32_t ed = upperBound<Key>(low + cnt);

    // If the region fits into the secure buffer, transform into the previous one
    if ((ed - st) * sizeof(Key) <= secureBufSize)
    {
        uint8_t ctr_de[16] = {0};
        uint8_t ctr_en[16] = {0};
        ctr128_inc_for_bytes(ctr_de, sizeof(Key) * st);
        memcpy(ctr_en, ctr_de, 16);
        sgx_aes_ctr_decrypt(p_key, (uint8_t *)(cArr + st),
                            (ed - st) * sizeof(Key), ctr_de, 128, (uint8_t *)secureBuf);

        low -= st;
        for (uint32_t i = low; i < low + cnt - k; i++)
            if (dir == (secureBuf[i] > secureBuf[i + k]))
                std::swap(secureBuf[i], secureBuf[i + k]);

        bitonicMerge<Key>(secureBuf, low, k, dir);
        bitonicMerge<Key>(secureBuf, low + k, cnt - k, dir);

        sgx_aes_ctr_encrypt(p_key, (uint8_t *)secureBuf, (ed - st) * sizeof(Key),
                            ctr_en, 128, (uint8_t *)(cArr + st));
        return;
    }

    // Enforce it to be multiple of 16
    const uint32_t batchCnt = lowerBound<Key>(secureBufSize / (2 * sizeof(Key)));
    ed = upperBound<Key>(low + cnt - k);
    uint32_t epoch = (ed - st) / batchCnt + ((ed - st) % batchCnt != 0);
    uint32_t rSt = lowerBound<Key>(low + k);
    uint32_t rEd = 0;
    Key *leftArr = cArr + st;
    Key *rightArr = cArr + rSt;
    uint32_t prevLeftLow = low;
    uint32_t prevRightLow = low + k;
    uint32_t _cnt = cnt;
    uint8_t ctr_lDe[16] = {0};
    uint8_t ctr_rDe[16] = {0};
    uint8_t ctr_lEn[16] = {0};
    uint8_t ctr_rEn[16] = {0};
    ctr128_inc_for_bytes(ctr_lDe, sizeof(Key) * st);
    ctr128_inc_for_bytes(ctr_rDe, sizeof(Key) * rSt);
    memcpy(ctr_lEn, ctr_lDe, 16);
    memcpy(ctr_rEn, ctr_rDe, 16);
    for (uint32_t e = 0; e < epoch; e++)
    {
        uint32_t leftCnt = std::min(batchCnt, ed - st);
        leftCnt = lowerBound<Key>(leftCnt);
        uint32_t actualCnt = std::min(cnt - k, st + leftCnt - prevLeftLow);
        rEd = upperBound<Key>(prevRightLow + actualCnt);
        uint32_t rightCnt = rEd - rSt;

        sgx_aes_ctr_decrypt(p_key, (uint8_t *)leftArr,
                            leftCnt * sizeof(Key), ctr_lDe, 128, (uint8_t *)secureBuf);
        sgx_aes_ctr_decrypt(p_key, (uint8_t *)rightArr,
                            rightCnt * sizeof(Key), ctr_rDe, 128,
                            (uint8_t *)(secureBuf + leftCnt));

        uint32_t lIdx = prevLeftLow - st;
        uint32_t rIdx = prevRightLow - rSt + leftCnt;

        for (uint32_t i = 0; i < actualCnt; i++)
            if (dir == (secureBuf[lIdx + i] > secureBuf[rIdx + i]))
                std::swap(secureBuf[lIdx + i], secureBuf[rIdx + i]);

        sgx_aes_ctr_encrypt(p_key, (uint8_t *)secureBuf,
                            leftCnt * sizeof(Key), ctr_lEn, 128, (uint8_t *)leftArr);
        sgx_aes_ctr_encrypt(p_key, (uint8_t *)(secureBuf + leftCnt),
                            rightCnt * sizeof(Key), ctr_rEn, 128, (uint8_t *)rightArr);

        leftArr += leftCnt;
        rightArr += rightCnt;
        st += leftCnt;
        rSt += rightCnt;
        prevLeftLow = st;
        prevRightLow = rSt;
        cnt -= actualCnt;
    }
    bitonicMergeEx<Key>(p_key, secureBuf, secureBufSize, cArr, low, k, dir);
    bitonicMergeEx<Key>(p_key, secureBuf, secureBufSize, cArr, low + k, _cnt - k, dir);
    return;
}

/**
 * @brief Sort a (small) decrypted array inside the enclave
 */
template <typename Key>
void bitonicSort(Key *arr, uint32_t low, uint32_t cnt, bool dir)
{
    if (cnt <= 1)
        return;
    if (arr == NULL)
        return;
    const uint32_t k = cnt >> 1;
#ifdef _OPENMP
#pragma omp taskgroup
    {
#pragma omp task if (k >= OMP_BITONIC_CNT)
#endif
        bitonicSort<Key>(arr, low, k, !dir);
#ifdef _OPENMP
#pragma omp task if (cnt - k >= OMP_BITONIC_CNT)
#endif
        bitonicSort<Key>(arr, low + k, cnt - k, dir);
#ifdef _OPENMP
#pragma omp taskyield
    }
#endif
    bitonicMerge<Key>(arr, low, cnt, dir);
}

/**
 * @brief Sort an encrypted array with the help of secure buffer of the given size
 *
 * @tparam Key Key must support operator<()
 * @param secureBuf a buffer inside the enclave
 * @param secureBufSize secure buffer size
 * @param cArr The encrypted array to be sorted
 * @param low The start index
 * @param cnt The number of elements
 * @param dir 1 ascending, 0 descending
 */
template <typename Key>
void bitonicSortEx(const sgx_aes_ctr_128bit_key_t *p_key,
                   Key *secureBuf, uint32_t secureBufSize,
                   Key *cArr, uint32_t low, uint32_t cnt, bool dir)
{
    if (cnt <= 1)
        return;
    if (secureBuf == NULL || cArr == NULL)
        return;
    const uint32_t k = cnt >> 1;
    const uint32_t st = lowerBound<Key>(low);
    const uint32_t ed = upperBound<Key>(low + cnt);
    if ((ed - st) * sizeof(Key) < secureBufSize)
    {
        uint8_t ctr[16] = {0};
        ctr128_inc_for_bytes(ctr, sizeof(Key) * st);
        sgx_aes_ctr_decrypt(p_key, (uint8_t *)(cArr + st),
                            (ed - st) * sizeof(Key), ctr, 128, (uint8_t *)secureBuf);
        low -= st;
#ifdef _OPENMP
#pragma omp taskgroup
        {
#pragma omp task
#endif
            bitonicSort<Key>(secureBuf, low, k, !dir);
#ifdef _OPENMP
#pragma omp task
#endif
            bitonicSort<Key>(secureBuf, low + k, cnt - k, dir);
#ifdef _OPENMP
#pragma omp taskyield
        }
#endif
        bitonicMerge<Key>(secureBuf, low, cnt, dir);

        memset(ctr, 0, sizeof(ctr));
        ctr128_inc_for_bytes(ctr, sizeof(Key) * st);
        sgx_aes_ctr_encrypt(p_key, (uint8_t *)secureBuf, (ed - st) * sizeof(Key),
                            ctr, 128, (uint8_t *)(cArr + st));
        return;
    }
    bitonicSortEx<Key>(p_key, secureBuf, secureBufSize, cArr, low, k, !dir);
    bitonicSortEx<Key>(p_key, secureBuf, secureBufSize, cArr, low + k, cnt - k, dir);
    bitonicMergeEx<Key>(p_key, secureBuf, secureBufSize, cArr, low, cnt, dir);
    return;
}

/**
 * @brief bitonically sort cnt elements in a[]
 *
 * @tparam Key must support operator<()
 * @param a plain array of type Key
 * @param low the start index
 * @param cnt the number of elements
 * @param maxThreadNum The maximum number of threads, which will be reduced to the exponential of 2
 */
template <typename Key>
void bitonicSortParallel(const sgx_aes_ctr_128bit_key_t *p_key,
                         Key *secureBuf, uint32_t secureBufSize,
                         Key *cArr, uint32_t cnt)
{
#pragma omp parallel
#pragma omp single
    bitonicSortEx<Key>(p_key, secureBuf, secureBufSize, cArr, 0u, cnt, true);
    return;
}

void ecall_ObliviousSort(int cArr[], uint32_t cnt)
{
    // Does not allocate memory here since we exclude this part from timing
    // const uint32_t secureBufSize = 80*1000*1000;
    // uint8_t *buf = new uint8_t[secureBufSize];
    // printf("Debug #1\n");
    bitonicSortParallel<int>(p_key, (int *)buf, secureBufSize, cArr, cnt);
    // delete[] buf;
    return;
}

static double lap(double b)
{
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_real_distribution<double> unif(0.0, 1.0);
    double cdf = unif(gen);
    return -b * (cdf > 0.5 ? 1 : -1) * log(1 - 2 * abs(cdf - 0.5));
}

template <typename Key>
static void _bitonicMerge(Key a[], int low, int cnt, uint32_t bit, bool dir)
{
    if (cnt > 1)
    {
        int k = 1;
        while (k < cnt)
            k <<= 1;
        k >>= 1;
        for (int i = low; i < low + cnt - k; i++)
            if (
                dir == ((a[i] & bit) > (a[i + k] & bit)))
                std::swap(a[i], a[i + k]);
        _bitonicMerge<Key>(a, low, k, bit, dir);
        _bitonicMerge<Key>(a, low + k, cnt - k, bit, dir);
    }
}

template <typename Key>
void _bitonicSort(Key *arr, uint32_t low, uint32_t cnt, uint32_t bit, bool dir)
{
    if (cnt > 1)
    {
        int k = cnt / 2;
        _bitonicSort<Key>(arr, low, k, bit, !dir);
        _bitonicSort<Key>(arr, low + k, cnt - k, bit, dir);
        _bitonicMerge<Key>(arr, low, cnt, bit, dir);
    }
}

template <class Key>
void dpSortBit(Key *secureBuf, Key *cArr, uint32_t cnt, uint32_t s, uint32_t bit, double epsilon)
{
    uint32_t bufCnt = 0;
    uint32_t targetCnt = 0;
    uint8_t ctr_de[16] = {0};
    uint8_t ctr_en[16] = {0};
    // For dp prefix sum computation
    uint32_t dpPrefixSum = 0;
    std::vector<double> alpha(ceil(log2(cnt / s + 1)) + 1, 0);
    std::vector<double> alpha_(ceil(log2(cnt / s + 1)) + 1, 0);
    double prefixSumEpsilon = epsilon / (log2(cnt / s) + 1);
    Key *tArr = cArr;
    for (uint32_t i = 0, k = 1; i < cnt; i += s, k++)
    {
        uint32_t num = lowerBound<int>(std::min(s, cnt - i));
        sgx_aes_ctr_decrypt(p_key, (uint8_t *)cArr, num * sizeof(Key), ctr_de, 128, (uint8_t *)(secureBuf + bufCnt));

        cArr += num;
        uint32_t zeroBalls = 0;
        for (uint32_t t = 0; t < num; t++)
            zeroBalls += ((bit & (secureBuf[t + bufCnt])) == 0);

        bufCnt += num;

        // _bitonicSort(secureBuf, 0, bufCnt, bit, 1);
        std::stable_sort(secureBuf, secureBuf + bufCnt, [bit](const Key &a, const Key &b)
                         { return (a & bit) < (b & bit); });

        // Compute dp prefix sum
        uint32_t h = 0;
        while ((k & (1 << h)) == 0)
            ++h;
        alpha[h] = 0;
        for (uint32_t t = 0; t < h; t++)
            alpha[h] += alpha[t];
        alpha[h] += zeroBalls;
        for (uint32_t t = 0; t < h; t++)
            alpha[t] = alpha_[t] = 0;
        alpha_[h] = alpha[h] + lap(1.0 / prefixSumEpsilon);

        h = 0;
        double sum = 0;
        while (k >> h)
        {
            if (((k >> h) & 1) == 1)
                sum += alpha_[h];
            ++h;
        }
        dpPrefixSum = sum;

        if (dpPrefixSum > targetCnt + s)
        {
            uint32_t curNum = std::min(bufCnt, dpPrefixSum - s - targetCnt);
            curNum = lowerBound<int>(curNum);
            sgx_aes_ctr_encrypt(p_key, (uint8_t *)secureBuf, curNum * sizeof(Key),
                                ctr_en, 128, (uint8_t *)tArr);
            tArr += curNum;
            targetCnt += curNum;

            // Eliminate the first curNum elements in buffer
            bufCnt -= curNum;
            for (uint32_t j = 0; j < bufCnt; j++)
                secureBuf[j] = secureBuf[j + curNum];
        }

        if (bufCnt > 2 * s)
            bufCnt = 2 * s;
    }

    if (0 != bufCnt)
    {
        uint32_t curNum = upperBound<int>(bufCnt);
        sgx_aes_ctr_encrypt(p_key, (uint8_t *)secureBuf, bufCnt * sizeof(Key),
                            ctr_en, 128, (uint8_t *)tArr);
    }
}

void ecall_DPSort(int *cArr, uint32_t cnt, double epsilon)
{
    // ecallDecryptArr((uint8_t *)cArr, (uint8_t *)buf, cnt*sizeof(int));
    uint32_t bitNum = 31;
    uint32_t s = lowerBound<int>(uint32_t(pow(log2(cnt), 3)));
    for (int k = 0; k < bitNum; k++)
    {
        dpSortBit<int>((int *)buf, cArr, cnt, s, 1 << k, epsilon);
    }
}

void ecall_OneByOne(int *pArr, int *cArr,
                    uint32_t cnt)
{
    uint8_t ctr[16] = {0};
    uint32_t K = pow(log2(cnt), 2);
    K = upperBound<int>(K);
    if (K == 0)
        K = 1;
    printf("Block size = %d\n", K);
    for (int i = 0; i < cnt; i += K)
    {
        if (K > cnt - i)
            printf("Remaining = %d\n", cnt - i);
        sgx_aes_ctr_encrypt(p_key, (uint8_t *)pArr, std::min(K, cnt - i) * sizeof(int),
                            ctr, 128, (uint8_t *)cArr);
        pArr += K;
        cArr += K;
    }
}