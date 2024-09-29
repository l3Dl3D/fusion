#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define __cdecl
#define __int8 char
#define _DWORD uint32_t
#define _WORD uint16_t
#define _BYTE unsigned char

int __cdecl rc4_plus(char *a1)
{
  unsigned __int8 v2; // [esp+Eh] [ebp-2h]
  char v3; // [esp+Fh] [ebp-1h]

  v3 = a1[(unsigned __int8)++*a1 + 2];
  a1[1] += v3;
  v2 = a1[(unsigned __int8)a1[1] + 2];
  a1[(unsigned __int8)a1[1] + 2] = v3;
  a1[(unsigned __int8)*a1 + 2] = v2;
  return (unsigned __int8)a1[(v2 ^ (unsigned __int8)(a1[(unsigned __int8)(v3 + v2) + 2] + a1[1])) + 2];
}

void __cdecl rc4_plus_setup(unsigned __int8 *ctx, char *key, unsigned int key_len)
{
  unsigned __int8 *v3; // edx
  unsigned int v4; // ebx
  unsigned __int8 *v5; // edi
  unsigned __int8 *v6; // edx
  unsigned __int8 v8; // [esp+9h] [ebp-13h]
  int j; // [esp+Ch] [ebp-10h]
  int i; // [esp+10h] [ebp-Ch]
  int i_; // [esp+10h] [ebp-Ch]
  int k; // [esp+10h] [ebp-Ch]

  v3 = ctx;
  v4 = 258;
  if ( ((unsigned __int8)ctx & 1) != 0 )
  {
    *ctx = 0;
    v3 = ctx + 1;
    v4 = 257;
  }
  if ( ((unsigned __int8)v3 & 2) != 0 )
  {
    *(_WORD *)v3 = 0;
    v3 += 2;
    v4 -= 2;
  }
  memset(v3, 0, 4 * (v4 >> 2));
  v5 = &v3[4 * (v4 >> 2)];
  v6 = v5;
  if ( (v4 & 2) != 0 )
  {
    *(_WORD *)v5 = 0;
    v6 = v5 + 2;
  }
  if ( (v4 & 1) != 0 )
    *v6 = 0;
  ctx[1] = 0;
  *ctx = ctx[1];
  j = 0;
  // init
  for ( i = 0; i <= 0xFF; ++i )
  {
    ctx[i + 2] = i;
  }
  for ( i_ = 0; i_ <= 0x2FF; ++i_ )
  {
    j = ((unsigned __int8)key[(unsigned __int8)i_ % key_len] + j + ctx[j + 2]) % 256;
    v8 = ctx[(unsigned __int8)i_ + 2];
    ctx[(unsigned __int8)i_ + 2] = ctx[j + 2];
    ctx[j + 2] = v8;
  }
  for ( k = 0; k <= 0x1FF; ++k )
    rc4_plus(ctx);
}

int __cdecl decrypt_pak(char *data, int data_size, char **out_buf, _DWORD *out_size)
{
  char *p; // ebx
  char c; // si
  char rc4_ctx[258]; // [esp+1Ah] [ebp-10Eh] BYREF
  unsigned int i; // [esp+11Ch] [ebp-Ch]

  *out_size = data_size - 0x20;
  *out_buf = (char *)calloc(*out_size, 1);
  rc4_plus_setup((unsigned __int8 *)rc4_ctx, data, 0x20u);
  for ( i = 0; data_size - 0x20 > i; ++i )
  {
    p = &(*out_buf)[i];
    c = data[i + 0x20];
    *p = c ^ rc4_plus((unsigned __int8 *)rc4_ctx);
  }
  return 0;
}

int __cdecl encrypt_pak(char *a1, unsigned int a2, char **a3, _DWORD *a4)
{
  int v4; // eax
  int v5; // ebx
  int v6; // edx
  char *v7; // ebx
  char *v8; // ebx
  char v9; // si
  char v11[16]; // [esp+1Ah] [ebp-11Eh] BYREF
  unsigned __int8 v12[258]; // [esp+2Ah] [ebp-10Eh] BYREF
  unsigned int i; // [esp+12Ch] [ebp-Ch]

  *a4 = a2 + 32;
  *a3 = (char *)calloc(*a4, 1);
  v4 = time(0);
  srandom(v4);
  for ( i = 0; i <= 0xF; ++i )
  {
    v5 = random() >> 8;
    v6 = v5 ^ (random() % 255);
    v11[i] = v6;
  }
  rc4_plus_setup(v12, v11, 0x10u);
  for ( i = 0; i <= 0x1F; ++i )
  {
    v7 = &(*a3)[i];
    *v7 = rc4_plus((char *)v12);
  }
  rc4_plus_setup(v12, *a3, 0x20u);
  for ( i = 0; i < a2; ++i )
  {
    v8 = &(*a3)[i + 32];
    v9 = a1[i];
    *v8 = v9 ^ rc4_plus((char *)v12);
  }
  return 0;
}

char encrypted[1024 * 1024];

int main() {
    char *buf = NULL;
    _DWORD size = 0;
    int n = 0;
    if((n = fread(encrypted, 1, sizeof(encrypted), stdin)) > 0) {
        encrypt_pak(encrypted, n, &buf, &size);
        fwrite(buf, size, 1, stdout);
    }
    return 0;
}

