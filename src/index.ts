import { PointG1 } from "@noble/bls12-381";
import * as ibe from "./crypto/ibe";
import { encryptAge } from "./age/age-encrypt-decrypt";
import { Buffer } from "buffer";

type Stanza = {
  type: string;
  args: Array<string>;
  body: Uint8Array;
};

interface Ciphertext {
  U: PointG1;
  V: Uint8Array;
  W: Uint8Array;
}

function createTimelockEncrypter(id: number, pubKey: string) {
  return async (fileKey: Uint8Array): Promise<Array<Stanza>> => {
    const idByte = new TextEncoder().encode(id.toString());
    const point = PointG1.fromHex(pubKey);
    const ciphertext = await ibe.encryptOnG1(point, idByte, fileKey);
    return [
      {
        type: "distIBE",
        args: [`${id}`],
        body: serialisedCiphertext(ciphertext),
      },
    ];
  };
}

function serialisedCiphertext(ciphertext: Ciphertext): Uint8Array {
  return Buffer.concat([
    ciphertext.U.toRawBytes(true),
    ciphertext.V,
    ciphertext.W,
  ]);
}

export async function timelockEncrypt(
  id: number,
  pubKey: string,
  payload: Buffer
): Promise<string> {
  const timelockEncrypter = createTimelockEncrypter(id, pubKey);
  const agePayload = await encryptAge(payload, timelockEncrypter);
  return Buffer.from(agePayload, "binary").toString();
}
