// fuzz_crc_lzma.c - CRC32 gate + real 7-Zip LZMA decoder
//
// Input layout:
//   [0..3]   stored CRC32 of [4..N]  (arithmetic checksum gate)
//   [4..8]   LZMA properties header (5 bytes)
//   [9..N]   LZMA compressed stream
//
// This is the canonical "checksum problem" demonstration:
//   - raw mutation cannot solve the CRC32 gate (it's arithmetic, not a simple
//     byte comparison, so libFuzzer's value profiling cannot crack it)
//   - structure-aware seeds (recomputed CRC + valid LZMA stream) pass the
//     gate and reach the full LZMA decoder (~335 edges)
// Uses real 7-Zip code: 7zCrc.c (CRC32) + LzmaDec.c (decoder).

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "7zCrc.h"
#include "LzmaDec.h"

static void *SzAlloc(const ISzAlloc *p, size_t size) { (void)p; return malloc(size); }
static void SzFree(const ISzAlloc *p, void *address) { (void)p; free(address); }
static const ISzAlloc g_Alloc = { SzAlloc, SzFree };

#define OUT_CAP (1u << 20)

static uint32_t ReadUInt32(const Byte *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static int init_done = 0;
    if (!init_done) {
        CrcGenerateTable();
        init_done = 1;
    }

    if (size < 4 + LZMA_PROPS_SIZE)
        return 0;

    /* CRC32 gate */
    const uint32_t stored_crc = ReadUInt32(data);
    const uint32_t calc_crc = CrcCalc(data + 4, size - 4);
    if (calc_crc != stored_crc)
        return 0;

    /* deep: LZMA decode */
    const Byte *props = data + 4;
    const Byte *src = data + 4 + LZMA_PROPS_SIZE;
    SizeT srcLen = size - 4 - LZMA_PROPS_SIZE;

    Byte *dest = (Byte *)malloc(OUT_CAP);
    if (!dest)
        return 0;
    SizeT destLen = OUT_CAP;

    ELzmaStatus status;
    (void)LzmaDecode(dest, &destLen, src, &srcLen,
                     props, LZMA_PROPS_SIZE,
                     LZMA_FINISH_ANY, &status, &g_Alloc);

    free(dest);
    return 0;
}
