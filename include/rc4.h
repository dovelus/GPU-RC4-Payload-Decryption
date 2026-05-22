#ifndef RC4_GPU_H
#define RC4_GPU_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    RC4_GPU_OK              =  0,
    RC4_GPU_ERR_PARAM       = -1,
    RC4_GPU_ERR_DEVICE      = -2,
    RC4_GPU_ERR_SHADER      = -3,
    RC4_GPU_ERR_BUFFER      = -4,
    RC4_GPU_ERR_VIEW        = -5,
    RC4_GPU_ERR_READBACK    = -6,
    RC4_GPU_ERR_MEMORY      = -7,
} rc4_gpu_status_t;

/* RC4 on the GPU (D3D11 compute shader).
 *
 * Reads `ct_len` bytes from `ciphertext`, runs the cipher in VRAM, then
 * writes the plaintext into `plaintext` via the driver's staging buffer.
 * No intermediate CPU heap buffer for the data on our side — when key/ct
 * are 4-byte aligned, the inputs are handed directly to CreateBuffer.
 *
 *   key, key_len     RC4 key, 1..256 bytes
 *   ciphertext       const input (may live in .data / .rdata)
 *   ct_len           bytes
 *   plaintext        destination, at least ct_len bytes. May alias
 *                    `ciphertext` for in-place, or point at a VirtualAlloc'd
 *                    executable page for the direct-to-RWX loader pattern.
 */
rc4_gpu_status_t rc4_gpu_decrypt(
    const unsigned char *key,        size_t key_len,
    const unsigned char *ciphertext, size_t ct_len,
    unsigned char       *plaintext);

#ifdef __cplusplus
}
#endif

#endif /* RC4_GPU_H */
