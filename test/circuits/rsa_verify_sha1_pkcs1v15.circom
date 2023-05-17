pragma circom 2.0.0;

include "../../circuits/rsa_verify_sha1.circom";

//w, nb, e_bits, hashLen
component main{public [exp, sign, modulus, hashed]} = RsaSha1VerifyPkcs1v15(32, 32, 17, 5);
