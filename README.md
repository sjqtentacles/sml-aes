# sml-aes

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

val {ciphertext, tag} = AesGcm.encrypt key iv aad pt
val recovered         = AesGcm.decrypt key iv aad ciphertext tag
(* decrypt raises Fail on authentication failure *)

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

## Testing

```
make test       # MLton
make test-poly  # Poly/ML
```

## License

MIT
