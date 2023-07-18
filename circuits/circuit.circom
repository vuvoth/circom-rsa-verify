pragma circom 2.0.0;

include "./rsa_verify_sha1.circom";

//w, nb, e_bits, hashLen
component main{public [exp, modulus]} = RsaSha1VerifyPkcs1v15(64, 32, 17, 3);
