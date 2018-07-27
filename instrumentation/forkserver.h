#pragma once

//Macros and fucntion definitions for use when instrumenting target programs
int __killerbeez_loop(void);
#define KILLERBEEZ_LOOP() __killerbeez_loop()
void __forkserver_init(void);
#define KILLERBEEZ_INIT() __forkserver_init()
