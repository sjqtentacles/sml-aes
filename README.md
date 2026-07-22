# sml-aes

[![CI](https://github.com/sjqtentacles/sml-aes/actions/workflows/ci.yml/badge.svg)](https://github.com/sjqtentacles/sml-aes/actions/workflows/ci.yml)

AES block cipher with ECB, CBC, CTR, and GCM modes in pure Standard ML (FIPS 197)

## Installation

```
smlpkg add github.com/sjqtentacles/sml-aes
smlpkg sync
```

## Usage

```sml
(* AES-GCM authenticated encryption *)
val key   = (* 16, 24, or 32-byte key *)
val iv    = (* 12-byte IV *)
val aad   = "additional data"
val pt    = "plaintext"

(* seal returns ciphertext concatenated with the 16-byte tag
   (so String.size sealed = String.size pt + 16). *)
val sealed    = AesGcm.seal key iv aad pt

(* open' returns SOME plaintext, or NONE on authentication failure
   (wrong key/IV/AAD or a tampered ciphertext/tag). *)
val recovered = AesGcm.open' key iv aad sealed   (* : string option *)

(* AES-CBC *)
val ivCbc = (* 16-byte IV *)
val ct = AesCbc.encrypt key ivCbc pt
val dt = AesCbc.decrypt key ivCbc ct

(* AES-CTR *)
val ctCtr = AesCtr.encrypt key ivCbc pt

(* Raw AES block — expand key once, reuse for many blocks *)
val k128 = AesBlock.expand128 key   (* 16-byte key *)
val k256 = AesBlock.expand256 key   (* 32-byte key *)
val block = AesBlock.encrypt k128 pt  (* encrypts exactly 16 bytes *)
```

## Example

`make example` builds and runs [`examples/demo.sml`](examples/demo.sml), which
encrypts fixed FIPS 197 / NIST SP 800-38A / GCM test vectors and prints the
ciphertext in hex:

```
$ make example
AES-128 block encrypt (FIPS 197 App. B):
  key        = 2b7e151628aed2a6abf7158809cf4f3c
  plaintext  = 3243f6a8885a308d313198a2e0370734
  ciphertext = 3925841d02dc09fbdc118597196a0b32
  decrypt    = 3243f6a8885a308d313198a2e0370734

AES-128 CBC encrypt (NIST SP 800-38A):
  iv         = 000102030405060708090a0b0c0d0e0f
  ciphertext = 7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2

AES-128 CTR encrypt (NIST SP 800-38A):
  ciphertext = 874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff

AES-128 GCM seal (McGrew/NIST case 4, ciphertext||tag):
  sealed = 42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e0915bc94fbc3221a5db94fae95ae7121a47
  open   = verified, 60 bytes
```

## Testing

```
make test       # MLton
make test-poly  # Poly/ML
make example    # build + run the demo
```

## License

MIT
