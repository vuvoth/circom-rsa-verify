pragma circom 2.0.0;
 
include "../circom-ecdsa/circuits/bigint.circom";
// w = 32
// base ** exp mod modulus
// nb is the length of the input number
// exp = 65537
template PowerMod(w, nb, e_bits) {
    signal input base[nb];
    signal input exp[nb];
    signal input modulus[nb];

    signal output out[nb];
    
   
    component muls[e_bits + 2];
    for (var i = 0; i < e_bits + 2; i++) {
        muls[i] = BigMultModP(w, nb);
        // modulus params
        for (var j = 0; j < nb; j++) {
            muls[i].p[j] <== modulus[j];
        }
    }

    // result/base muls component index
    var result_index=0;
    var base_index=0;
    var muls_index=0;
 
    for (var i = 0; i< e_bits; i++) {
        if (i == 0 || i == e_bits - 1) {
            if (i == 0) {
                for(var j = 0; j < nb; j ++) {
                    if (j == 0) {
                        muls[muls_index].a[j] <== 1;
                    } else {
                        muls[muls_index].a[j] <== 0;
                    }
                   
                }
                muls[muls_index].b <== base;
            } else {
                muls[muls_index].a <== muls[result_index].out;
                muls[muls_index].b <== muls[base_index].out;
            }
            result_index = muls_index;
            muls_index++;
        }

        if (base_index == 0) {
                muls[muls_index].a <== base;
                muls[muls_index].b <== base;
        } else {
            muls[muls_index].a <== muls[base_index].out;
            muls[muls_index].b <== muls[base_index].out; 
        }

        base_index = muls_index;
        muls_index++;
    }

    out <== muls[result_index].out;

}
