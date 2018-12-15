import * as crypto from 'crypto';
import * as sshpk from 'sshpk';
import { Helper } from './helper';

type KeyType = 'rsa-ssh';

export class Key {
  public Type: KeyType;
  public Value: string;

  constructor(o: any) {
    this.Type = o.type;
    this.Value = o.value;
  }

  public toO(): any {
    return {
      type: this.Type,
      value: this.Value
    };
  }

  public static async fromPublicKeyFile(filename: string, passphrase: string) {
    let contents = await Helper.loadFile(filename);

    let key = sshpk.parseKey(contents, 'auto', {
      filename: filename,
      passphrase: passphrase
    });

    return new Key({
      type: 'rsa-ssh',
      value: key.toString('pem')
    });
  }

  public static async fromPrivateKeyFile(filename: string, passphrase: string) {
    let contents = await Helper.loadFile(filename);

    let key = sshpk.parsePrivateKey(contents, 'auto', {
      filename: filename,
      passphrase: passphrase
    });

    return new Key({
      type: 'rsa-ssh',
      value: key.toString('pem')
    });
  }

  public encryptGroupKey(groupKey: string): string {
    let buffer: Buffer = crypto.publicEncrypt(
      this.Value,
      Buffer.from(groupKey, 'base64')
    );
    return buffer.toString('base64');
  }

  public decryptGroupKey(groupKey: string): string {
    let buffer: Buffer = crypto.privateDecrypt(
      this.Value,
      Buffer.from(groupKey, 'base64')
    );
    return buffer.toString('base64');
  }
}
