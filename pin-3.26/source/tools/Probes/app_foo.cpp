/*
 * Copyright (C) 2022-2022 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <sys/syscall.h>

#include <iostream>

/* 
 * This application simply calls a few functions and makes a few prints.
 * It also prints the ppid pid and tid since it is being used in a test
 * where this app is launched as a secondary application using different APIs.
 */
static void print_ppid_pid_tid() { printf("ppid %u ; pid %u ; tid %lu ; \t", getppid(), getpid(), syscall(SYS_gettid)); }

void foo_impl(int* counter)
{
    (*counter) *= 17;
    asm("nop");
    (*counter) *= 17;
    asm("nop");
    (*counter) *= 17;
    asm("nop");
}

extern "C" void foo(int* counter)
{
    print_ppid_pid_tid();
    std::cout << "  -> " << __FUNCTION__ << "()" << std::endl << std::flush;
    foo_impl(counter);
}
extern "C" void foo_1(int* counter)
{
    print_ppid_pid_tid();
    std::cout << "  -> " << __FUNCTION__ << "()" << std::endl << std::flush;
    foo_impl(counter);
}

extern "C" void bar(void)
{
    print_ppid_pid_tid();
    std::cout << "  -> " << __FUNCTION__ << "()" << std::endl << std::flush;
}

int main(int argc, char* argv[])
{
    int counter = 1;
    foo(&counter);
    foo_1(&counter);
    bar();
    return 0;
}
