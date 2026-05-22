// rc4.hlsl — DirectCompute RC4 (KSA + PRGA + XOR), single-threaded.
//
// As my knowledge and research i ended up findning that RC4 cannot be parallelised across the same key —
// each S-box swap depends on the previous state
// so we dispatch (1,1,1) and run the entire stream
// cipher in one thread.
//
//  if anyone has ideas on how to parallelise make a pull request
//
// Resource layout:
//   b0 : Params         — key_len + data_len (bytes)
//   t0 : ByteAddressBuffer key_buf   — key bytes, padded to 4-byte multiple
//   u0 : RWByteAddressBuffer data_buf — input/output, padded to 4-byte multiple

cbuffer Params : register(b0)
{
    uint key_len;
    uint data_len;
    uint pad0;
    uint pad1;
};

ByteAddressBuffer   key_buf  : register(t0);
RWByteAddressBuffer data_buf : register(u0);

uint load_key_byte(uint idx)
{
    uint w = key_buf.Load(idx & ~3u);
    return (w >> ((idx & 3u) * 8u)) & 0xFFu;
}

uint load_data_byte(uint idx)
{
    uint w = data_buf.Load(idx & ~3u);
    return (w >> ((idx & 3u) * 8u)) & 0xFFu;
}

void store_data_byte(uint idx, uint val)
{
    uint a = idx & ~3u;
    uint s = (idx & 3u) * 8u;
    uint w = data_buf.Load(a);
    w = (w & ~(0xFFu << s)) | ((val & 0xFFu) << s);
    data_buf.Store(a, w);
}

[numthreads(1, 1, 1)]
void CSMain(uint3 tid : SV_DispatchThreadID)
{
    if (tid.x != 0) return;

    uint S[256];
    for (uint i = 0; i < 256; ++i) S[i] = i;

    // KSA
    uint j = 0;
    for (uint i2 = 0; i2 < 256; ++i2)
    {
        uint k = load_key_byte(i2 % key_len);
        j = (j + S[i2] + k) & 0xFF;
        uint t = S[i2]; S[i2] = S[j]; S[j] = t;
    }

    // PRGA + XOR (in place)
    uint ii = 0;
    j = 0;
    for (uint b = 0; b < data_len; ++b)
    {
        ii = (ii + 1) & 0xFF;
        j  = (j + S[ii]) & 0xFF;
        uint t = S[ii]; S[ii] = S[j]; S[j] = t;
        uint ks = S[(S[ii] + S[j]) & 0xFF];
        store_data_byte(b, load_data_byte(b) ^ ks);
    }
}
