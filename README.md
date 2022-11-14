# Parallel Oblivious Sorter with SGX
Parallel bitonic sorter with limited Intel SGX enclave page cache (default 80MB). 

## Compile and Run 
* Compile
```
make clean && make
```
* Run 
```
./app numberOfRandomIntegers
```

## Remarks
* The ECall funcion supports only ``int`` type, however, the sorter does support any numeric types and self-defined class satisfying:
  * bool operator>(const Type &) const;
  * It does not contain any pointer pointing to the actual data, since we use sizeof to evaluate each element size, meanning that it does not support raw strings or STL containers. However, you could modify the implementation with small efforts. 
* It also outputs the running time of ``std::sort``, bottom-up ``merge sort``, and ``heap sort`` on plaintext arrays (with the same contents) for references. 
  * For single thread,it usually takes $5~7\times$ time of the ``std::sort``. 
  * For 4 threads, it only takes $2~3\times$ running time of ``std::sort``. 
* The actual number of threads it uses is the maximal 2 exponential of the macro THREAD_NUM (i.e., we actually use only 4 out of THREAD_NUM = 6). In addition, I did not figure out why it goes wrong when THREAD_NUM >=8. 
* The speed up factor is not proportional to the number of threads
* Temporarily, I believe the bitonic sorter is the best among all oblivious and differentially oblbvious sorters (under the setting combing SGX). All the other sorters are worse than bitonic sorter (but better theoritical guarantees), including 
  * [Bucket Oblivious Sort: An Extremely Simple Oblivious Sort](https://arxiv.org/abs/2008.01765)
    * I also implemented it (but only works for arrays smaller than 90MB) in another repo. Even the entire array fits into the EPC, the ORP key tagging/removing process is quite inefficient, and we also require the oblivious sort inside the enclave, i.e., $~2n\log n\log^2 Z running time. 
  * Oblivious sort based on oblivious heap: [Path Oblivious Heap: Optimal and Practical Oblivious Priority Queue](https://eprint.iacr.org/2019/274)
    * Not implement, but our implementation is already comparable to the plaintext heap sort, and the heap sort is not easy to be parallelized. Of course, the authors focus on the bandwidth costs rather the running time (since we have SGX). 
  * Differentially oblivious sorter: [Foundations of Differentially Oblivious Algorithms](https://eprint.iacr.org/2017/1033.pdf)
    * Firstly, the claimed upper bound $\mathcal{O}(k\cdot n\log\log n)$ where $k$ is the bit length of the key requires a *stable* oblivious sorter with $\mathcal{O}(n\log n)$ running time. However, such a sorter suffers from high constant overheads. The randomized shellsort has a non-negligible failing probability and is not stable either. And if we indeed use a bitonic sorter with inefficient stability transformation, its complexity becomes $\mathcal{O}(k\cdot n(\log\log n)^2)$. Even for 32-bit integer, it is about $10$ times slower. We have a draft implementation which does not scale well and does not sort correctly, (dp prefix sum seems wrong and we use a plaintext stable sort), it should be faster than the correct version, but it still much slower than the bitonic sort. 
  * AKS sort, Zig-zag sort, randomized shellsort. The former two have large constant overhead, the latter one does not have negligible failing probabiblity. Therefore, we did not try them. 
