#include <IOKit/IOKitLib.h>
#include <iokernelrw.h>
#include <mach/arm/kern_return.h>
#include <mach/kern_return.h>
#include <mach/mach_error.h>
#include <sys/errno.h>
#include <stdio.h>

#include "libkrw_plugin.h"

io_connect_t krw_client = IO_OBJECT_NULL;

int kbase_wrapper(uint64_t *to) {
    kern_return_t result_read;
    int result;

    if (krw_client == IO_OBJECT_NULL)
    {
        krw_client = iokernelrw_open();
    }

    result_read = iokernelrw_kbase(krw_client, to);

    if (result_read == KERN_SUCCESS)
    {
        result = 0;
    }
    else
    {
        result = EDEVERR;
    }

    return result;
}

int kread_wrapper(uint64_t from, void* to, size_t len)
{
    kern_return_t result_read;
    int result;

    if (krw_client == IO_OBJECT_NULL)
    {
        krw_client = iokernelrw_open();
    }

    result_read = iokernelrw_read(krw_client, from, to, len);

    if (result_read == KERN_SUCCESS)
    {
        result = 0;
    }
    else
    {
        result = EDEVERR;
    }

    return result;
}

int kwrite_wrapper(void* from, uint64_t to, size_t len)
{
    kern_return_t result_write;
    int result;

    if (krw_client == IO_OBJECT_NULL)
    {
        krw_client = iokernelrw_open();
    }

    result_write = iokernelrw_write(krw_client, from, to, len);

    if (result_write == KERN_SUCCESS)
    {
        result = 0;
    }
    else
    {
        result = EDEVERR;
    }

    return result;
}

int krw_initializer(krw_handlers_t handlers)
{
    iokernelrw_open();

    //handlers->version = TODO;
    handlers->kbase = kbase_wrapper;
    handlers->kread = kread_wrapper;
    handlers->kwrite = kwrite_wrapper;
    //handlers->kmalloc = TODO;
    //handlers->kdealloc = TODO;
    //handlers->kcall = TODO;
    //handlers->physread = TODO;
    //handlers->physwrite = TODO;

    return 0;
}