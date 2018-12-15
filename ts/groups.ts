import * as crypto from 'crypto';
import * as secureRandom from 'secure-random';

import * as keys from './keys';

let encoding: crypto.HexBase64BinaryEncoding = 'base64';

export interface IGroupUsers {
  [user: string]: string;
}

export interface IGroupValues {
  [key: string]: string;
}

export interface IGroups {
  [name: string]: Group;
}

export class Groups {
  public static fromO(o: any): IGroups {
    let result: IGroups = {};

    for (let name in o) {
      result[name] = new Group(o[name]);
    }

    return result;
  }

  public static toO(value: IGroups): any {
    let result: any = {};
    for (let name in value) {
      result[name] = value[name].toO();
    }
    return result;
  }
}

export class Group {
  public Users: IGroupUsers;
  public Values: IGroupValues;

  public constructor(o: any) {
    this.Users = o.users;
    this.Values = o.values;
  }

  public toO(): any {
    return {
      users: this.Users,
      values: this.Values
    };
  }

  public static newIV(bits: number = 128): string {
    let buffer: Buffer = secureRandom(bits / 8, { type: 'Buffer' });
    return buffer.toString(encoding);
  }

  public static newGroupKey(bits: number = 256): string {
    let buffer: Buffer = secureRandom(bits / 8, { type: 'Buffer' });
    return buffer.toString(encoding);
  }

  public async keys(
    groupKey: string,
    algorithm = 'aes-256-cbc'
  ): Promise<IGroupValues> {
    let result = {};
    for (let encryptedKey in this.Values) {
      let key = await this.decrypt(encryptedKey, groupKey, algorithm);
      result[key] = encryptedKey;
    }
    return result;
  }

  public async keyValues(
    groupKey: string,
    algorithm = 'aes-256-cbc'
  ): Promise<IGroupValues> {
    let result = {};
    for (let encryptedKey in this.Values) {
      let key = await this.decrypt(encryptedKey, groupKey, algorithm);
      let encryptedValue = this.Values[encryptedKey];
      let value = await this.decrypt(encryptedValue, groupKey, algorithm);
      result[key] = value;
    }
    return result;
  }

  public async encrypt(
    value: string,
    groupKey: string,
    algorithm = 'aes-256-cbc'
  ): Promise<string> {
    let groupKeyBuffer = Buffer.from(groupKey, encoding);
    let iv = Group.newIV();
    let ivBuffer = Buffer.from(iv, encoding);
    let cipher = crypto.createCipheriv(algorithm, groupKeyBuffer, ivBuffer);

    let encrypted = iv + '.';
    encrypted += cipher.update(value, 'utf8', encoding);
    encrypted += cipher.final(encoding);

    return encrypted;
  }

  public async decrypt(
    salted: string,
    groupKey: string,
    algorithm = 'aes-256-cbc'
  ): Promise<string> {
    let groupKeyBuffer = Buffer.from(groupKey, encoding);
    let dotPos = salted.indexOf('.');
    if (dotPos < 0) return Promise.reject('Value is not salted');
    let iv = salted.substr(0, dotPos - 1);
    let value = salted.substr(dotPos + 1);
    let ivBuffer = Buffer.from(iv, encoding);
    let cipher = crypto.createDecipheriv(algorithm, groupKeyBuffer, ivBuffer);

    let decrypted = cipher.update(value, encoding, 'utf8');
    decrypted += cipher.final('utf8');

    return decrypted;
  }
}
