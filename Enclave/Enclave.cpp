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

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include "parserfactory.h"
#include "elfparser.h"
#include "elf64parser.h"
#include "metadata.h"
#include "loader.h"
#include "enclave_creator_sign.h"

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

int ecall_load_enclave(uint8_t *parser_bitmap, size_t bitmap_size, uint8_t **parser_section_raw, size_t section_count, const uint8_t *parser_start_addr, uint64_t parser_enclave_max_size, uint8_t *in_metadata)
{
    printf("success in\n");
    metadata_t* metadata = (metadata_t*)in_metadata;
    std::vector<uint8_t> bitmap(bitmap_size);
    for (size_t i = 0; i < bitmap_size; i++)
        bitmap[i] = parser_bitmap[i];
    std::vector<Section *> parser_sections(section_count);
    for (int i = 0; i < section_count; ++i)
        parser_sections[i] = reinterpret_cast<Section *>(parser_section_raw[i]);
    CLoader *ploader = new CLoader(bitmap, parser_sections, parser_start_addr, parser_enclave_max_size);
    printf("success initialize\n");
    ploader->load_enclave_ex(NULL, 0, metadata, NULL,  0, NULL);
    uint8_t enclave_hash[SGX_HASH_SIZE] = {0};
    EnclaveCreatorST* enclave_creator = dynamic_cast<EnclaveCreatorST*>(get_enclave_creator());
    for (int i = 0; i < SGX_HASH_SIZE; ++i)
        printf("%02x ", enclave_creator->m_enclave_hash[i]);
    printf("\n");
    // printf("%p\n", ploader);
    return 1;
}