import path = require("path");
import { expect, assert } from "chai";
import { genData } from "./utils";
const circom_tester = require("circom_tester");
const wasm_tester = circom_tester.wasm;

// TODO: Factor this out into some common code among all the tests
const F1Field = require("ffjavascript").F1Field;
const Scalar = require("ffjavascript").Scalar;
exports.p = Scalar.fromString(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617"
);
const Fr = new F1Field(exports.p);

function bigint_to_array(n: number, k: number, x: bigint) {
  let mod: bigint = 1n;
  for (var idx = 0; idx < n; idx++) {
    mod = mod * 2n;
  }

  let ret: bigint[] = [];
  var x_temp: bigint = x;
  for (var idx = 0; idx < k; idx++) {
    ret.push(x_temp % mod);
    x_temp = x_temp / mod;
  }
  return ret;
}

describe("Test rsa pkcs1v15 sha1 n = 64, k = 32", function () {
  this.timeout(1000 * 1000);

  // runs circom compilation
  let circuit: any;
  before(async function () {
    circuit = await wasm_tester(
      path.join(__dirname, "circuits", "rsa_verify_sha1_pkcs1v15.circom")
    );
  });

  let test_rsa_verify = function (message: string) {
    it(`Testing ${message}`, async function () {
      const [exp, sign, m, hashed] = await genData(message, 'SHA-1');

      let exp_array: bigint[] = bigint_to_array(63, 32, exp);
      let sign_array: bigint[] = bigint_to_array(64, 32, sign);
      let m_array: bigint[] = bigint_to_array(64, 32, m);
      let hashed_array: bigint[] = bigint_to_array(64, 3, hashed);
      // console.log(hashed_array);
      let witness = await circuit.calculateWitness({
        exp: exp_array,
        sign: sign_array,
        modulus: m_array,
        hashed: hashed_array,
      });

      await circuit.checkConstraints(witness);
    });
  };

  test_rsa_verify("Hello world");
});
