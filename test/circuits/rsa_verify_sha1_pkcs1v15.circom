pragma circom 2.0.0;

include "../../circuits/rsa_verify_sha1.circom";

//w, nb, e_bits, hashLen
component main{public [exp, modulus]} = RsaSha1VerifyPkcs1v15(32, 64, 17, 5);
