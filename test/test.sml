(* test.sml - AES test suite. NIST FIPS 197 test vectors. *)

structure AesTests =
struct
  open Harness

  fun fromHex s =
    let fun n c = if c >= #"0" andalso c <= #"9" then Char.ord c - 48
                  else Char.ord c - 87
        val len = String.size s
    in String.implode (List.tabulate (len div 2, fn i =>
         Char.chr (n (String.sub (s, i*2)) * 16 + n (String.sub (s, i*2+1)))))
    end

  fun toHex s =
    let val h = "0123456789abcdef"
    in String.concat (List.tabulate (String.size s, fn i =>
         let val b = Char.ord (String.sub (s, i))
         in String.implode [String.sub (h, b div 16), String.sub (h, b mod 16)]
         end))
    end

  fun runEcb128 () =
    let
      val () = section "AES-128 ECB (FIPS 197 Appendix B)"
      val key = fromHex "2b7e151628aed2a6abf7158809cf4f3c"
      val pt  = fromHex "3243f6a8885a308d313198a2e0370734"
      val ct  = fromHex "3925841d02dc09fbdc118597196a0b32"
      val k   = AesBlock.expand128 key
      val ()  = checkString "encrypt" (toHex ct, toHex (AesBlock.encrypt k pt))
      val ()  = checkString "decrypt" (toHex pt, toHex (AesBlock.decrypt k ct))
    in () end

  fun runEcb256 () =
    let
      val () = section "AES-256 ECB (FIPS 197 Appendix B)"
      val key = fromHex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
      val pt  = fromHex "00112233445566778899aabbccddeeff"
      val ct  = fromHex "8ea2b7ca516745bfeafc49904b496089"
      val k   = AesBlock.expand256 key
      val ()  = checkString "encrypt" (toHex ct, toHex (AesBlock.encrypt k pt))
      val ()  = checkString "decrypt" (toHex pt, toHex (AesBlock.decrypt k ct))
    in () end

  fun runCbc () =
    let
      val () = section "AES-128 CBC (NIST SP 800-38A)"
      val key = fromHex "2b7e151628aed2a6abf7158809cf4f3c"
      val iv  = fromHex "000102030405060708090a0b0c0d0e0f"
      val pt  = fromHex "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
      val ct  = fromHex "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
      val () = checkString "CBC encrypt" (toHex ct, toHex (AesCbc.encrypt key iv pt))
      val () = checkString "CBC decrypt" (toHex pt, toHex (AesCbc.decrypt key iv ct))
    in () end

  fun runCtr () =
    let
      val () = section "AES-128 CTR (NIST SP 800-38A)"
      val key = fromHex "2b7e151628aed2a6abf7158809cf4f3c"
      val ctr = fromHex "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
      val pt  = fromHex "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
      val ct  = AesCtr.encrypt key ctr pt
      val () = check "CTR encrypt length" (String.size ct = String.size pt)
      val () = checkString "CTR decrypt" (toHex pt, toHex (AesCtr.decrypt key ctr ct))
      val () = check "CTR different from plaintext" (ct <> pt)
    in () end

  fun runGcm () =
    let
      val () = section "AES-128 GCM"
      val key = fromHex "00000000000000000000000000000000"
      val iv  = fromHex "000000000000000000000000"
      val pt  = "Hello, AES-GCM!"
      val aad = "header"
      val sealed = AesGcm.seal key iv aad pt
      val opened = AesGcm.open' key iv aad sealed
      val () = check "sealed length = pt + 16" (String.size sealed = String.size pt + 16)
      val () = check "open succeeds" (opened = SOME pt)
      val tampered = String.substring (sealed, 0, String.size sealed - 1) ^
                     String.str (Char.chr ((Char.ord (String.sub (sealed, String.size sealed - 1)) + 1) mod 256))
      val () = check "tampered fails" (AesGcm.open' key iv aad tampered = NONE)
      val () = check "wrong aad fails" (AesGcm.open' key iv "wrong" sealed = NONE)
    in () end

  (* Byte-exact GCM known-answer tests (McGrew & Viega, "The Galois/Counter
     Mode of Operation (GCM)" Appendix B; also the de-facto NIST GCM vectors).
     These pin the GHASH/tag computation so it cannot silently regress to a
     non-interoperable tag while still round-tripping. *)
  fun runGcmKat () =
    let
      val () = section "AES-GCM known-answer (McGrew/NIST)"
      val iv  = fromHex "cafebabefacedbaddecaf888"
      val pt  = fromHex ("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a3"
                       ^ "18a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
      val aad = fromHex "feedfacedeadbeeffeedfacedeadbeefabaddad2"
      (* Test Case 4: AES-128-GCM *)
      val k128 = fromHex "feffe9928665731c6d6a8f9467308308"
      val exp128 = "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
                 ^ "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
                 ^ "5bc94fbc3221a5db94fae95ae7121a47"
      val () = checkString "AES-128-GCM seal (case 4)"
                 (exp128, toHex (AesGcm.seal k128 iv aad pt))
      val () = check "AES-128-GCM open (case 4)"
                 (AesGcm.open' k128 iv aad (fromHex exp128) = SOME pt)
      (* Test Case 16: AES-256-GCM *)
      val k256 = fromHex ("feffe9928665731c6d6a8f9467308308"
                        ^ "feffe9928665731c6d6a8f9467308308")
      val exp256 = "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                 ^ "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
                 ^ "76fc6ece0f4e1768cddf8853bb2d551b"
      val () = checkString "AES-256-GCM seal (case 16)"
                 (exp256, toHex (AesGcm.seal k256 iv aad pt))
      val () = check "AES-256-GCM open (case 16)"
                 (AesGcm.open' k256 iv aad (fromHex exp256) = SOME pt)
    in () end

  fun runRoundtrip () =
    let
      val () = section "AES roundtrip properties"
      val key128 = String.implode (List.tabulate (16, fn i => Char.chr i))
      val key256 = String.implode (List.tabulate (32, fn i => Char.chr i))
      val blk    = String.implode (List.tabulate (16, fn i => Char.chr (i * 7 mod 256)))
      val k128   = AesBlock.expand128 key128
      val k256   = AesBlock.expand256 key256
      val () = check "AES-128 encrypt/decrypt roundtrip"
        (AesBlock.decrypt k128 (AesBlock.encrypt k128 blk) = blk)
      val () = check "AES-256 encrypt/decrypt roundtrip"
        (AesBlock.decrypt k256 (AesBlock.encrypt k256 blk) = blk)
      val () = check "AES-128 different keys give different ciphertexts"
        (AesBlock.encrypt k128 blk <> AesBlock.encrypt k256 blk)
    in () end

  fun run () =
    ( runEcb128 ()
    ; runEcb256 ()
    ; runCbc ()
    ; runCtr ()
    ; runGcm ()
    ; runGcmKat ()
    ; runRoundtrip () )
end
