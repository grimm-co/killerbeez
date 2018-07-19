#pragma once

//Designated file descriptors for read/write to the forkserver
//and target process
#define FUZZER_TO_FORKSRV   198
#define FORKSRV_TO_FUZZER   199
#define MAX_FORKSRV_FD      200

//Commands that the fuzzer can send to the forkserver
#define EXIT       0
#define FORK       1
#define RUN        2
#define GET_STATUS 3
