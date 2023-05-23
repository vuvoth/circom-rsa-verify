const { subtle } = require("crypto");

function buffToBigInt(buff: string): bigint{
    return BigInt("0x" + Buffer.from(buff, "base64url").toString("hex"));
}

async function generateRsaKey(hash = "SHA-256") {
  const publicExponent = new Uint8Array([1, 0, 1]);
  const modulusLength = 2048;
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

export async function genData(
  data: string,
  HASH_ALGO: string
): Promise<[bigint, bigint, bigint, bigint]> {
  let keys = await generateRsaKey(HASH_ALGO);

  let public_key = await subtle.exportKey("jwk", keys.publicKey);

  let enc = new TextEncoder();
  let text = enc.encode(data);
  console.log(await subtle.digest(HASH_ALGO, text));
  let hash = BigInt('0x' + Buffer.from(await subtle.digest(HASH_ALGO, text)).toString('hex'));
  
  let sign_buff = await subtle.sign(
    { name: "RSASSA-PKCS1-v1_5", hash: HASH_ALGO },
    keys.privateKey,
    text
  );

  let e = buffToBigInt(public_key.e);
  let n = buffToBigInt(public_key.n);
  let sign = buffToBigInt(sign_buff);

  return [e, sign, n, hash];
}
