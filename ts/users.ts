import * as keys from './keys';

export interface IUsers {
  [name: string]: User;
}

export class Users {
  public static fromO(o: any): IUsers {
    let result: IUsers = {};

    for (let name in o) {
      result[name] = new User(o[name]);
    }

    return result;
  }

  public static toO(value: IUsers): any {
    let result: any = {};
    for (let name in value) {
      result[name] = value[name].toO();
    }
    return result;
  }
}

export class User {
  public Key: keys.Key;

  constructor(o: any) {
    if (o instanceof keys.Key) {
      this.Key = o;
    } else {
      this.Key = new keys.Key(o.key);
    }
  }

  public toO(): any {
    return {
      key: this.Key.toO()
    };
  }
}
