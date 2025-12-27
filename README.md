# `aes128`: A fresh, dependency-free and cross-platform implementation of AES-128 and AES-CMAC (OMAC1)

## Installation

Copy both [aes128.c](aes128.c) and [aes128.h](aes128.h) into your project and
include the header where needed.

## Usage

The opaque `aes128_t` type is used to maintain contexts for both AES encryption
/ decryption and CMAC generation.

Contexts are initialized using

```c
void aes128_init(aes128_t *ctx, const uint8_t *iv, const uint8_t *key);
```

and

```c
void aes128_init_cmac(aes128_t *ctx, const uint8_t *key);
```

Initializing a context for encryption / decryption requires an Initialization
Vector (IV) to be provided. This *usually does not* have to be kept secret, but
it **absolutely does** need to be random.

Once initialized, data can be encrypted and decrypted in-place using

```c
void aes128_encrypt(aes128_t *ctx, uint8_t *chunk, size_t length);
```

and

```c
void aes128_decrypt(aes128_t *ctx, uint8_t *chunk, size_t length);
```

where `chunk` points to `length` (at least 16) bytes to be encrypted or
decrypted using the provided `aes128_t` context.

Initialization of a CMAC context only requires a key to be provided. Once
initialized, a tag can be computed using

```c
void aes128_cmac(const aes128_t *ctx, const uint8_t *msg, size_t length, uint8_t *mac);
```

where `msg` points to `length` bytes to be used, computing a tag at `mac`.
Unlike with aes128_encrypt() and aes128_decrypt(), `length` does not have to be
a minimum of 16-bytes.

See [aes128.h](aes128.h) for additional API reference

## Sample Usage

See [validation.c](validation.c) for a usage example.
