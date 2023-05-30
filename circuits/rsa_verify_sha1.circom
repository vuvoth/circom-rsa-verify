pragma circom 2.0.0;

include "./pow_mod.circom";

// Pkcs1v15 + Sha1, exp 65537
// w, nb, e_bits, hashLen
template RsaSha1VerifyPkcs1v15(w, nb, e_bits, hashLen) {
    // w: 64, nb: 32, e_bits: 17, hashLen: 2.5 ???
    // Question: Should we modify hashLen to bit. ???
    
    signal input sign[nb];
    signal input hashed[hashLen];
    
    signal input exp[nb];
    signal input modulus[nb];

    // sign ** exp mod modulus
    component pm = PowerMod(w, nb, e_bits);
    for (var i = 0; i < nb; i++) {
        pm.base[i] <== sign[i];
        pm.exp[i] <== exp[i];
        pm.modulus[i] <== modulus[i];
    }

    // 1. Check hashed data
    // SHA1: 160 bits => 2 first number and 32 first bit of third number 
    for (var i = 0; i < hashLen - 1 ; i++) {
        hashed[i] === pm.out[i];
    }

    // 2. Check hash prefix for sha1 and 1 byte 0x00: 
    // Prefix:   (0x)30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 || <32 bit> remain of hash 
   
    // check  05 00 04 14 || <32 bit> remain of hash 
    component num2bits_hash = Num2Bits(w);
    num2bits_hash.in <== hashed[hashLen - 1];


    component num2bits_2 = Num2Bits(w);
    num2bits_2.in <== pm.out[hashLen - 1];

    for (var i = 0; i < 32; i++) {
        num2bits_2.out[i] === num2bits_hash.out[i];
    }

    var num2RemainsBits[32] = [0,0,0,0,0,1,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0,0,0,0, 0, 1, 0, 1, 0, 0];
    for (var i = 32; i < w; i++) {
        num2bits_hash.out[i] === 0;
        num2bits_2.out[i] === num2RemainsBits[63 - i];
    }
    // 09 06 05 2b 0e 03 02 1a
    pm.out[3] === 650212878678426138;

    // 3. Check (0x00 required by RFC) || (00 bits padding from 32 bit word)
    component num2bits = Num2Bits(w);
    num2bits.in <== pm.out[4];
    var remainsBits[32] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0];

    for (var i = 0; i < 32; i++) {
        num2bits.out[i] === remainsBits[31 - i];
    }

    for (var i = 32; i < w; i++) {
        num2bits.out[i] === 1;
    }


    // 4. Check PS
    for (var i = 7; i < 31; i++) {
        // 0b1111111111111111111111111111111111111111111111111111111111111111
        pm.out[i] === 18446744073709551615;
    }

    // 5. Remains 16 bits (0xffff) from PS and 0x00 0x01
    // Hence: 0x0001FFFF == 131071
    pm.out[31] === 562949953421311;
    // pm.out[63] === 131071;
}