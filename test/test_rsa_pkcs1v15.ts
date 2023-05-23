import path = require("path");
import { expect, assert } from "chai";
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

async function genData(): Promise<[bigint, bigint, bigint, bigint]> {
  const { subtle } = require("crypto");
  const publicExponent = new Uint8Array([1, 0, 1]);

  async function generateRsaKey(modulusLength = 2048, hash = "SHA-256") {
    const { publicKey, privateKey } = await subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength,
        publicExponent,
        hash,
      },
      true,
      ["sign", "verify"]
    );

    return { publicKey, privateKey };
  }

  let keys = await generateRsaKey();

  let public_key = await subtle.exportKey("jwk", keys.publicKey);

  let enc = new TextEncoder();
  let text = enc.encode("Hello world");
  let hash = BigInt(
    "0x" + Buffer.from(await subtle.digest("SHA-256", text)).toString("hex")
  );
  let sign_buff = await subtle.sign(
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1" },
    keys.privateKey,
    text
  );

  let e = BigInt("0x" + Buffer.from(public_key.e, "base64url").toString("hex"));
  let n = BigInt("0x" + Buffer.from(public_key.n, "base64url").toString("hex"));
  let sign = BigInt("0x" + Buffer.from(sign_buff).toString("hex"));

  return [e, sign, n, hash];
}

describe("Test rsa pkcs1v15 n = 64, k = 32", function () {
  this.timeout(1000 * 1000);

  // runs circom compilation
  let circuit: any;
  before(async function () {
    circuit = await wasm_tester(
      path.join(__dirname, "circuits", "rsa_verify_pkcs1v15.circom")
    );
  });

  //   console.log(await genData());
  // a, e, m, (a ** e) % m
  let test_cases: Array<[bigint, bigint, bigint, bigint]> = [];

  test_cases.push([0n, 0n, 0n, 0n]);

  let test_rsa_verify = function (x: [bigint, bigint, bigint, bigint]) {
    it(`Testing `, async function () {
      const [exp, sign, m, hashed] = await genData();


      let exp_array: bigint[] = bigint_to_array(64, 32, exp);
      let sign_array: bigint[] = bigint_to_array(64, 32, sign);
      let m_array: bigint[] = bigint_to_array(64, 32, m);
      let hashed_array: bigint[] = bigint_to_array(64, 4, hashed);
      let witness = await circuit.calculateWitness({
        exp: exp_array,
        sign: sign_array,
        modulus: m_array,
        hashed: hashed_array,
      });

      await circuit.checkConstraints(witness);
    });
  };

  test_cases.forEach(test_rsa_verify);
});
