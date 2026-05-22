#define COBJMACROS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <d3d11.h>
#include <d3dcompiler.h>
#include <string.h>
#include <stdlib.h>

#include "rc4.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "d3dcompiler.lib")

#define SAFE_RELEASE(p) do { if (p) { (p)->lpVtbl->Release((p)); (p) = NULL; } } while (0)

/* Shader sourcem - for single file referce, refeer to rc4.hlsl*/
static const char g_shader_src[] =
"cbuffer Params : register(b0) {                                                \n"
"    uint key_len; uint data_len; uint pad0; uint pad1;                         \n"
"};                                                                             \n"
"ByteAddressBuffer   key_buf  : register(t0);                                   \n"
"RWByteAddressBuffer data_buf : register(u0);                                   \n"
"uint  load_key_byte (uint i) {                                                 \n"
"    uint w = key_buf.Load(i & ~3u);                                            \n"
"    return (w >> ((i & 3u) * 8u)) & 0xFFu;                                     \n"
"}                                                                              \n"
"uint  load_data_byte(uint i) {                                                 \n"
"    uint w = data_buf.Load(i & ~3u);                                           \n"
"    return (w >> ((i & 3u) * 8u)) & 0xFFu;                                     \n"
"}                                                                              \n"
"void  store_data_byte(uint i, uint v) {                                        \n"
"    uint a = i & ~3u; uint s = (i & 3u) * 8u;                                  \n"
"    uint w = data_buf.Load(a);                                                 \n"
"    w = (w & ~(0xFFu << s)) | ((v & 0xFFu) << s);                              \n"
"    data_buf.Store(a, w);                                                      \n"
"}                                                                              \n"
"[numthreads(1,1,1)]                                                            \n"
"void CSMain(uint3 tid : SV_DispatchThreadID) {                                 \n"
"    if (tid.x != 0) return;                                                    \n"
"    uint S[256];                                                               \n"
"    for (uint i = 0; i < 256; ++i) S[i] = i;                                   \n"
"    uint j = 0;                                                                \n"
"    for (uint i2 = 0; i2 < 256; ++i2) {                                        \n"
"        uint k = load_key_byte(i2 % key_len);                                  \n"
"        j = (j + S[i2] + k) & 0xFF;                                            \n"
"        uint t = S[i2]; S[i2] = S[j]; S[j] = t;                                \n"
"    }                                                                          \n"
"    uint ii = 0; j = 0;                                                        \n"
"    for (uint b = 0; b < data_len; ++b) {                                      \n"
"        ii = (ii + 1) & 0xFF;                                                  \n"
"        j  = (j + S[ii]) & 0xFF;                                               \n"
"        uint t = S[ii]; S[ii] = S[j]; S[j] = t;                                \n"
"        uint ks = S[(S[ii] + S[j]) & 0xFF];                                    \n"
"        store_data_byte(b, load_data_byte(b) ^ ks);                            \n"
"    }                                                                          \n"
"}                                                                              \n";

rc4_gpu_status_t rc4_gpu_decrypt(const unsigned char *key,        size_t key_len,
                                 const unsigned char *ciphertext, size_t ct_len,
                                 unsigned char       *plaintext)
{
    if (!key || key_len == 0 || key_len > 256 ||
        !ciphertext || ct_len == 0 || !plaintext)
        return RC4_GPU_ERR_PARAM;

    rc4_gpu_status_t status = RC4_GPU_OK;
    HRESULT hr;

    ID3D11Device              *device     = NULL;
    ID3D11DeviceContext       *ctx        = NULL;
    ID3DBlob                  *shaderBlob = NULL;
    ID3DBlob                  *errBlob    = NULL;
    ID3D11ComputeShader       *cs         = NULL;
    ID3D11Buffer              *paramBuf   = NULL;
    ID3D11Buffer              *keyBuf     = NULL;
    ID3D11Buffer              *dataBuf    = NULL;
    ID3D11Buffer              *stagingBuf = NULL;
    ID3D11ShaderResourceView  *keySRV     = NULL;
    ID3D11UnorderedAccessView *dataUAV    = NULL;
    unsigned char             *padKey     = NULL;   /* allocated when key_len % 4 != 0 */
    unsigned char             *padCt      = NULL;   /* allocated when ct_len  % 4 != 0 */

    const size_t padKeyLen = (key_len + 3u) & ~(size_t)3u;
    const size_t padCtLen  = (ct_len  + 3u) & ~(size_t)3u;

    /* No CPU heap allocation when caller's buffers are already 4-byte aligned.
     * For aligned inputs the GPU buffer is initialised straight from the
     * caller's pointer (typically .data/.rdata), no staging copy on this side. */
    const void *keyInit = key;
    const void *ctInit  = ciphertext;
    if (padKeyLen != key_len) {
        padKey = (unsigned char *)calloc(1, padKeyLen);
        if (!padKey) { status = RC4_GPU_ERR_MEMORY; goto cleanup; }
        memcpy(padKey, key, key_len);
        keyInit = padKey;
    }
    if (padCtLen != ct_len) {
        padCt = (unsigned char *)calloc(1, padCtLen);
        if (!padCt) { status = RC4_GPU_ERR_MEMORY; goto cleanup; }
        memcpy(padCt, ciphertext, ct_len);
        ctInit = padCt;
    }

    // DEVICE
    D3D_FEATURE_LEVEL fl;
    hr = D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0,
                           NULL, 0, D3D11_SDK_VERSION,
                           &device, &fl, &ctx);
    if (FAILED(hr)) {
        hr = D3D11CreateDevice(NULL, D3D_DRIVER_TYPE_WARP, NULL, 0,
                               NULL, 0, D3D11_SDK_VERSION,
                               &device, &fl, &ctx);
        if (FAILED(hr)) { status = RC4_GPU_ERR_DEVICE; goto cleanup; }
    }

    // SHADER COMPILATION
    hr = D3DCompile(g_shader_src, sizeof(g_shader_src) - 1,
                    NULL, NULL, NULL, "CSMain", "cs_5_0",
                    0, 0, &shaderBlob, &errBlob);
    if (FAILED(hr)) { status = RC4_GPU_ERR_SHADER; goto cleanup; }

    hr = ID3D11Device_CreateComputeShader(
            device,
            ID3D10Blob_GetBufferPointer(shaderBlob),
            ID3D10Blob_GetBufferSize(shaderBlob),
            NULL, &cs);
    if (FAILED(hr)) { status = RC4_GPU_ERR_SHADER; goto cleanup; }

    // Constant buffer for Params
    struct { UINT key_len; UINT data_len; UINT pad0; UINT pad1; } params;
    params.key_len  = (UINT)key_len;
    params.data_len = (UINT)ct_len;
    params.pad0 = params.pad1 = 0;

    D3D11_BUFFER_DESC cbDesc;
    ZeroMemory(&cbDesc, sizeof(cbDesc));
    cbDesc.ByteWidth = sizeof(params);
    cbDesc.Usage     = D3D11_USAGE_DEFAULT;
    cbDesc.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
    D3D11_SUBRESOURCE_DATA cbInit = { &params, 0, 0 };
    hr = ID3D11Device_CreateBuffer(device, &cbDesc, &cbInit, &paramBuf);
    if (FAILED(hr)) { status = RC4_GPU_ERR_BUFFER; goto cleanup; }

    // Key ByteAddressBuffer (raw SRV)
    D3D11_BUFFER_DESC kbDesc;
    ZeroMemory(&kbDesc, sizeof(kbDesc));
    kbDesc.ByteWidth = (UINT)padKeyLen;
    kbDesc.Usage     = D3D11_USAGE_DEFAULT;
    kbDesc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
    kbDesc.MiscFlags = D3D11_RESOURCE_MISC_BUFFER_ALLOW_RAW_VIEWS;
    D3D11_SUBRESOURCE_DATA kbInit = { keyInit, 0, 0 };
    hr = ID3D11Device_CreateBuffer(device, &kbDesc, &kbInit, &keyBuf);
    if (FAILED(hr)) { status = RC4_GPU_ERR_BUFFER; goto cleanup; }

    D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc;
    ZeroMemory(&srvDesc, sizeof(srvDesc));
    srvDesc.Format              = DXGI_FORMAT_R32_TYPELESS;
    srvDesc.ViewDimension       = D3D11_SRV_DIMENSION_BUFFEREX;
    srvDesc.BufferEx.FirstElement = 0;
    srvDesc.BufferEx.NumElements  = (UINT)(padKeyLen / 4);
    srvDesc.BufferEx.Flags        = D3D11_BUFFEREX_SRV_FLAG_RAW;
    hr = ID3D11Device_CreateShaderResourceView(device, (ID3D11Resource *)keyBuf, &srvDesc, &keySRV);
    if (FAILED(hr)) { status = RC4_GPU_ERR_VIEW; goto cleanup; }

    // Data RWByteAddressBuffer (raw UAV)
    D3D11_BUFFER_DESC dbDesc;
    ZeroMemory(&dbDesc, sizeof(dbDesc));
    dbDesc.ByteWidth = (UINT)padCtLen;
    dbDesc.Usage     = D3D11_USAGE_DEFAULT;
    dbDesc.BindFlags = D3D11_BIND_UNORDERED_ACCESS;
    dbDesc.MiscFlags = D3D11_RESOURCE_MISC_BUFFER_ALLOW_RAW_VIEWS;
    D3D11_SUBRESOURCE_DATA dbInit = { ctInit, 0, 0 };
    hr = ID3D11Device_CreateBuffer(device, &dbDesc, &dbInit, &dataBuf);
    if (FAILED(hr)) { status = RC4_GPU_ERR_BUFFER; goto cleanup; }

    D3D11_UNORDERED_ACCESS_VIEW_DESC uavDesc;
    ZeroMemory(&uavDesc, sizeof(uavDesc));
    uavDesc.Format             = DXGI_FORMAT_R32_TYPELESS;
    uavDesc.ViewDimension      = D3D11_UAV_DIMENSION_BUFFER;
    uavDesc.Buffer.FirstElement = 0;
    uavDesc.Buffer.NumElements  = (UINT)(padCtLen / 4);
    uavDesc.Buffer.Flags        = D3D11_BUFFER_UAV_FLAG_RAW;
    hr = ID3D11Device_CreateUnorderedAccessView(device, (ID3D11Resource *)dataBuf, &uavDesc, &dataUAV);
    if (FAILED(hr)) { status = RC4_GPU_ERR_VIEW; goto cleanup; }

    //Staging (readback)
    D3D11_BUFFER_DESC sbDesc;
    ZeroMemory(&sbDesc, sizeof(sbDesc));
    sbDesc.ByteWidth      = (UINT)padCtLen;
    sbDesc.Usage          = D3D11_USAGE_STAGING;
    sbDesc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    hr = ID3D11Device_CreateBuffer(device, &sbDesc, NULL, &stagingBuf);
    if (FAILED(hr)) { status = RC4_GPU_ERR_BUFFER; goto cleanup; }

    //Bind + dispatch
    ID3D11DeviceContext_CSSetShader(ctx, cs, NULL, 0);
    ID3D11DeviceContext_CSSetConstantBuffers(ctx, 0, 1, &paramBuf);
    ID3D11DeviceContext_CSSetShaderResources(ctx, 0, 1, &keySRV);
    UINT initCount = 0;
    ID3D11DeviceContext_CSSetUnorderedAccessViews(ctx, 0, 1, &dataUAV, &initCount);
    ID3D11DeviceContext_Dispatch(ctx, 1, 1, 1);

    // Readback
    ID3D11DeviceContext_CopyResource(ctx, (ID3D11Resource *)stagingBuf, (ID3D11Resource *)dataBuf);
    D3D11_MAPPED_SUBRESOURCE mapped;
    ZeroMemory(&mapped, sizeof(mapped));
    hr = ID3D11DeviceContext_Map(ctx, (ID3D11Resource *)stagingBuf, 0, D3D11_MAP_READ, 0, &mapped);
    if (FAILED(hr)) { status = RC4_GPU_ERR_READBACK; goto cleanup; }
    memcpy(plaintext, mapped.pData, ct_len);
    ID3D11DeviceContext_Unmap(ctx, (ID3D11Resource *)stagingBuf, 0);

    // Unbind the UAV so the runtime doesn't complain on next dispatch.
    {
        ID3D11UnorderedAccessView *nullUAV = NULL;
        ID3D11DeviceContext_CSSetUnorderedAccessViews(ctx, 0, 1, &nullUAV, &initCount);
    }

cleanup:
    if (padKey) { SecureZeroMemory(padKey, padKeyLen); free(padKey); }
    if (padCt)  {                                       free(padCt);  }
    SAFE_RELEASE(stagingBuf);
    SAFE_RELEASE(dataUAV);
    SAFE_RELEASE(keySRV);
    SAFE_RELEASE(dataBuf);
    SAFE_RELEASE(keyBuf);
    SAFE_RELEASE(paramBuf);
    SAFE_RELEASE(cs);
    SAFE_RELEASE(errBlob);
    SAFE_RELEASE(shaderBlob);
    SAFE_RELEASE(ctx);
    SAFE_RELEASE(device);
    return status;
}
