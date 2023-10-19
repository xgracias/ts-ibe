import { PointG1 } from "@noble/bls12-381";
import * as ibe from "./crypto/ibe";
import { encryptAge } from "./age/age-encrypt-decrypt";
import { Buffer } from "buffer";
import { Stanza } from "./types";

interface Ciphertext {
  U: PointG1;
  V: Uint8Array;
  W: Uint8Array;
}

function createTimelockEncrypter(id: string, pubKey: string) {
  return async (fileKey: Uint8Array): Promise<Array<Stanza>> => {
    const idByte = new TextEncoder().encode(id);
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
  identity: string,
  pubKey: string,
  payload: Uint8Array
): Promise<string> {
  const timelockEncrypter = createTimelockEncrypter(identity, pubKey);
  const agePayload = await encryptAge(payload, timelockEncrypter);

  return Buffer.from(agePayload, "binary").toString();
}
