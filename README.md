# CarpetFuzz-fuzzer # 

This repo is [CarpetFuzz](https://github.com/waugustus/CarpetFuzz-fuzzer)'s fuzzer component, which is based on the [AFLplusplus](https://github.com/AFLplusplus/AFLplusplus) repo (commit 96b774261172a2259ab98cc529eba3d7212375cb).

## Description ##

With this fuzzer, CarpetFuzz can fuzz each program with all the prioritized pruned option combinations. Specifically, this fuzzer will instrument the target program to allow it to read options from a file and let the fuzzer modify the file on the fly to switch the combinations in use. At the beginning of fuzzing, it will use all the given combinations to mutate the seed files and record the corresponding combination when generating a new test case. Then it use the corresponding combination to mutate each test case in the queue.

All changes we made can be searched with the pattern,
```
//CarpetFuzz modified
```

## AFL Version ##

We also provide a version of CarpetFuzz based on [AFL](https://github.com/google/AFL) (commit 61037103ae3722c8060ff7082994836a794f978). To obtain such version, you can switch to the branch with the command,

```
git checkout AFL_version
```