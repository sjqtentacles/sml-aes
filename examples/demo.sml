(* demo.sml - exercise AES on fixed FIPS 197 / NIST SP 800-38A / GCM test
   vectors, printing ciphertext in hex. Deterministic: same bytes out on every
   run and compiler (no RNG, no clock, hex output only). *)

fun hex s =
  let val d = "0123456789abcdef"
  in String.concat (List.map
       (fn c => let val b = Char.ord c
                in String.implode [String.sub (d, b div 16), String.sub (d, b mod 16)] end)
       (String.explode s))
  end

fun fromHex s =
  let fun n c = if c >= #"0" andalso c <= #"9" then Char.ord c - 48
                else Char.ord c - 87
  in String.implode (List.tabulate (String.size s div 2, fn i =>
       Char.chr (n (String.sub (s, i*2)) * 16 + n (String.sub (s, i*2+1))))) end

(* AES-128 block, FIPS 197 Appendix B *)
val key128 = fromHex "2b7e151628aed2a6abf7158809cf4f3c"
val pt     = fromHex "3243f6a8885a308d313198a2e0370734"
val k      = AesBlock.expand128 key128
val ct     = AesBlock.encrypt k pt
val () = print "AES-128 block encrypt (FIPS 197 App. B):\n"
val () = print ("  key        = " ^ hex key128 ^ "\n")
val () = print ("  plaintext  = " ^ hex pt ^ "\n")
val () = print ("  ciphertext = " ^ hex ct ^ "\n")
val () = print ("  decrypt    = " ^ hex (AesBlock.decrypt k ct) ^ "\n")

(* AES-128 CBC, NIST SP 800-38A *)
val iv  = fromHex "000102030405060708090a0b0c0d0e0f"
val cpt = fromHex "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
val cct = AesCbc.encrypt key128 iv cpt
val () = print "\nAES-128 CBC encrypt (NIST SP 800-38A):\n"
val () = print ("  iv         = " ^ hex iv ^ "\n")
val () = print ("  ciphertext = " ^ hex cct ^ "\n")

(* AES-128 CTR, NIST SP 800-38A counter block *)
val ctr  = fromHex "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
val ctct = AesCtr.encrypt key128 ctr cpt
val () = print "\nAES-128 CTR encrypt (NIST SP 800-38A):\n"
val () = print ("  ciphertext = " ^ hex ctct ^ "\n")

(* AES-128 GCM, McGrew/NIST test case 4 *)
val gk   = fromHex "feffe9928665731c6d6a8f9467308308"
val giv  = fromHex "cafebabefacedbaddecaf888"
val gaad = fromHex "feedfacedeadbeeffeedfacedeadbeefabaddad2"
val gpt  = fromHex ("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a3"
                  ^ "18a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39")
val sealed = AesGcm.seal gk giv gaad gpt
val () = print "\nAES-128 GCM seal (McGrew/NIST case 4, ciphertext||tag):\n"
val () = print ("  sealed = " ^ hex sealed ^ "\n")
val () = print ("  open   = "
                ^ (case AesGcm.open' gk giv gaad sealed
                     of SOME m => "verified, " ^ Int.toString (String.size m) ^ " bytes"
                      | NONE   => "FAILED") ^ "\n")
