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

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#include "ErrorSupport.h"

#include "se_map.h"
#include "user_types.h"

#include "parserfactory.h"
#include <memory>

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        ret_error_support(ret);
        return -1;
    }

    return 0;
}

void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}

int open_file(const char *filepath)
{
    FILE* fp = fopen(filepath, "rb");
    if (fp == NULL)
        return THE_INVALID_HANDLE;
    return fileno(fp);
}

void close_handle(int fd)
{
    close(fd);
}

uint8_t* map_file(int fd, size_t *size)
{
    struct stat st;
    memset(&st, 0, sizeof(st));
    if (-1 == fstat(fd, &st))
        return NULL;
    
    map_handle_t *mh = (map_handle_t*)calloc(1, sizeof(map_handle_t));
    if (mh == NULL)
        return NULL;
    
    mh->base_addr = (uint8_t *)mmap(
        NULL, (size_t)st.st_size, 
        PROT_READ | PROT_WRITE, MAP_PRIVATE, 
        fd, 0
    );
    if (MAP_FAILED == mh->base_addr) {
        free(mh);
        printf("fail\n");
        return NULL;
    }

    mh->length = (size_t)st.st_size;
    if (size)
        *size = st.st_size;
    return (uint8_t*)mh;
}

int parse_enclave(const char *dllpath) {
    bool res = false;
    size_t file_size = 0;
    uint64_t quota = 0;
    bin_fmt_t bin_fmt = BF_UNKNOWN;

    int fh = open_file(dllpath);
    if (fh == THE_INVALID_HANDLE) 
    {
        printf("Failed to open file %s\n", dllpath);
        return -1;
    }

    map_handle_t *mh = (map_handle_t *)map_file(fh, &file_size);
    if (!mh)
    {
        close_handle(fh);
        return -1;
    }

    // Parse enclave
    std::unique_ptr<BinParser> parser(binparser::get_parser(mh->base_addr, file_size));
    assert(parser != NULL);

    sgx_status_t status = parser->run_parser();
    if (status != SGX_SUCCESS)
    {
        close_handle(fh);
        return -1;
    }

    close_handle(fh);
    return 0;
}
/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);


    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }

    if (parse_enclave("wasm_vm_enclave.signed.so") == -1)
    {
        printf("Failed to parse enclave\n");
        return -1;
    }

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    
    printf("Info: SampleEnclave successfully returned.\n");

    printf("Enter a character before exit ...\n");
    getchar();
    return 0;
}

