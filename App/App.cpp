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
#include "manage_metadata.h"
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

int compute_measurement(const char *dllpath, const char *xmlpath) {
    bool res = false;
    size_t file_size = 0;
    uint64_t quota = 0;
    bin_fmt_t bin_fmt = BF_UNKNOWN;
    xml_parameter_t parameter[] = {/* name,                 max_value          min_value,      default value,       flag */
                                   {"ProdID",               0xFFFF,                0,              0,                   0},
                                   {"ISVSVN",               0xFFFF,                0,              0,                   0},
                                   {"ReleaseType",          1,                     0,              0,                   0},
                                   {"IntelSigned",          1,                     0,              0,                   0},
                                   {"ProvisionKey",         1,                     0,              0,                   0},
                                   {"LaunchKey",            1,                     0,              0,                   0},
                                   {"DisableDebug",         1,                     0,              0,                   0},
                                   {"HW",                   0x10,                  0,              0,                   0},
                                   {"TCSNum",               0xFFFFFFFF,            TCS_NUM_MIN,    TCS_NUM_MIN,         0},
                                   {"TCSMaxNum",            0xFFFFFFFF,            TCS_NUM_MIN,    TCS_NUM_MIN,         0},
                                   {"TCSMinPool",           0xFFFFFFFF,            0,              TCS_NUM_MIN,         0},
                                   {"TCSPolicy",            TCS_POLICY_UNBIND,     TCS_POLICY_BIND,TCS_POLICY_UNBIND,   0},
                                   {"StackMaxSize",         ENCLAVE_MAX_SIZE_64/2, STACK_SIZE_MIN, STACK_SIZE_MAX,      0},
                                   {"StackMinSize",         ENCLAVE_MAX_SIZE_64/2, STACK_SIZE_MIN, STACK_SIZE_MIN,      0},
                                   {"HeapMaxSize",          ENCLAVE_MAX_SIZE_64/2, 0,              HEAP_SIZE_MAX,       0},
                                   {"HeapMinSize",          ENCLAVE_MAX_SIZE_64/2, 0,              HEAP_SIZE_MIN,       0},
                                   {"HeapInitSize",         ENCLAVE_MAX_SIZE_64/2, 0,              HEAP_SIZE_MIN,       0},
                                   {"ReservedMemMaxSize",   ENCLAVE_MAX_SIZE_64/2, 0,              RSRV_SIZE_MAX,       0},
                                   {"ReservedMemMinSize",   ENCLAVE_MAX_SIZE_64/2, 0,              RSRV_SIZE_MIN,       0},
                                   {"ReservedMemInitSize",  ENCLAVE_MAX_SIZE_64/2, 0,              RSRV_SIZE_MIN,       0},
                                   {"ReservedMemExecutable",1,                     0,              0,                   0},
                                   {"MiscSelect",           0x00FFFFFFFF,          0,              DEFAULT_MISC_SELECT, 0},
                                   {"MiscMask",             0x00FFFFFFFF,          0,              DEFAULT_MISC_MASK,   0},
                                   {"EnableKSS",            1,                     0,              0,                   0},
                                   {"ISVFAMILYID_H",        ISVFAMILYID_MAX,       0,              0,                   0},
                                   {"ISVFAMILYID_L",        ISVFAMILYID_MAX ,      0,              0,                   0},
                                   {"ISVEXTPRODID_H",       ISVEXTPRODID_MAX,      0,              0,                   0},
                                   {"ISVEXTPRODID_L",       ISVEXTPRODID_MAX,      0,              0,                   0},
                                   {"EnclaveImageAddress",  0xFFFFFFFFFFFFFFFF,    0x1000,         0,                   0},
                                   {"ELRangeStartAddress",  0xFFFFFFFFFFFFFFFF,    0,              0,                   0},
                                   {"ELRangeSize",          0xFFFFFFFFFFFFFFFF,    0x1000,         0,                   0},
				   {"PKRU",                 FEATURE_LOADER_SELECTS,                     FEATURE_MUST_BE_DISABLED,              FEATURE_MUST_BE_DISABLED,                   0}};
    size_t parameter_count = sizeof(parameter)/sizeof(parameter[0]);
    uint8_t metadata_raw[METADATA_SIZE];
    metadata_t *metadata = (metadata_t*)metadata_raw;
    uint8_t enclave_hash[SGX_HASH_SIZE] = {0};

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
    BinParser *parser = binparser::get_parser(mh->base_addr, file_size);
    assert(parser != NULL);

    sgx_status_t status = parser->run_parser();
    if (status != SGX_SUCCESS)
    {
        close_handle(fh);
        return -1;
    }

    // TODO: need to check init section?

    // generate metadata
    // Parse the xml file to get the metadata
    if(parse_metadata_file(xmlpath, parameter, (int)parameter_count) == false)
    {   
        return -1;
    }

    CMetadata meta(metadata, parser);
    if(meta.build_metadata(parameter) == false)
    {
        close_handle(fh);
        return false;
    }
    size_t metadata_size = sizeof(*metadata);

    // TODO: dumptextrel check

    // get elements of parser used in loader
    std::vector<uint8_t> bitmap;
    parser->get_reloc_bitmap(bitmap);
    size_t bitmap_size = bitmap.size();
    uint8_t bitmap_raw[bitmap_size];
    memcpy(bitmap_raw, bitmap.data(), bitmap_size);

    const uint8_t *parser_start_addr = parser->get_start_addr();
    uint64_t parser_enclave_max_size = parser->get_enclave_max_size();

    std::vector<Section *> parser_sections = parser->get_sections();
    size_t section_count = parser_sections.size();

    Section parser_section_data[section_count];
    for (size_t i = 0; i < section_count; ++i) {
        parser_section_data[i].m_start_addr = parser_sections[i]->m_start_addr;
        parser_section_data[i].m_raw_data_size = parser_sections[i]->m_raw_data_size;
        parser_section_data[i].m_virtual_size = parser_sections[i]->m_virtual_size;
        parser_section_data[i].m_rva = parser_sections[i]->m_rva;
        parser_section_data[i].m_si_flag = parser_sections[i]->m_si_flag;

    }

    int ecallret;
    if (SGX_SUCCESS != ecall_load_enclave(global_eid, &ecallret, bitmap_raw, bitmap_size, parser_start_addr, parser_enclave_max_size, (uint8_t*)metadata, metadata_size, (uint8_t*)parser_section_data, section_count, sizeof(Section) * section_count) || ecallret != 1)
        printf("fail\n");

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

    if (compute_measurement("wasm_vm_enclave.signed.so", "Enclave.config.xml") == -1)
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

