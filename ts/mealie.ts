import { Helper } from './helper';
import * as keys from './keys';
import * as users from './users';
import * as groups from './groups';
import { rejects } from 'assert';

export class Mealie {
  public Users: users.IUsers;
  public Groups: groups.IGroups;

  constructor(o: any) {
    this.Users = users.Users.fromO(o.users);
    this.Groups = groups.Groups.fromO(o.groups);
  }

  public toO(): any {
    return {
      users: users.Users.toO(this.Users),
      groups: groups.Groups.toO(this.Groups)
    };
  }

  public async addUser(
    name: string,
    filename: string,
    passphrase: string = undefined
  ) {
    if (this.Users[name]) {
      return Promise.reject('User already exists');
    } else {
      let key = await keys.Key.fromPublicKeyFile(filename, passphrase);
      this.Users[name] = new users.User(key);
    }
  }

  public async removeUser(name: string) {
    if (!this.Users[name]) return Promise.reject('User not found: ' + name);

    //Check that it is safe to remove that user
    for (let groupName in this.Groups) {
      let group = this.Groups[groupName];

      let hasOtherUser = false;
      for (let userName in group.Users) {
        if (userName != name) {
          hasOtherUser = true;
          break;
        }
      }
      if (!hasOtherUser)
        return Promise.reject(
          'That user is the only user in group: ' + groupName
        );
    }

    //Remove that user from the groups
    for (let groupName in this.Groups) {
      let group = this.Groups[groupName];
      delete group.Users[name];
    }

    //Remove that user
    delete this.Users[name];
  }

  public async addGroup(groupName: string, userNames: string[]) {
    if (this.Groups[groupName]) {
      return Promise.reject('Group already exists');
    }

    for (let index in userNames) {
      let userName = userNames[index];
      if (!this.Users[userName]) return Promise.reject('User does not exist');
    }

    let iv = groups.Group.newIV();
    let groupKey = groups.Group.newGroupKey();

    let groupUsers = {};
    for (let index in userNames) {
      let userName = userNames[index];
      let user = this.Users[userName];
      groupUsers[userName] = user.Key.encryptGroupKey(groupKey);
    }

    this.Groups[groupName] = new groups.Group({
      iv: iv,
      users: groupUsers,
      values: {}
    });
  }

  public async addUsersToGroup(
    groupName: string,
    userNameInGroup: string,
    privateKey: keys.Key,
    newUserNames: string[]
  ) {
    if (!this.Groups[groupName]) {
      return Promise.reject('Group does not exist: ' + groupName);
    }

    if (!this.Users[userNameInGroup]) {
      return Promise.reject('User does not exist: ' + userNameInGroup);
    }

    for (let index in newUserNames) {
      let userName = newUserNames[index];
      if (!this.Users[userName])
        return Promise.reject('User does not exist: ' + userName);
    }

    let group = this.Groups[groupName];
    let groupKey = privateKey.decryptGroupKey(group.Users[userNameInGroup]);

    for (let index in newUserNames) {
      let userName = newUserNames[index];
      let user = this.Users[userName];
      group.Users[userName] = user.Key.encryptGroupKey(groupKey);
    }
  }

  public async addValuesToGroup(
    groupName: string,
    userNameInGroup: string,
    privateKey: keys.Key,
    values: groups.IGroupValues
  ) {
    if (!this.Groups[groupName]) {
      return Promise.reject('Group does not exist: ' + groupName);
    }

    if (!this.Users[userNameInGroup]) {
      return Promise.reject('User does not exist: ' + userNameInGroup);
    }

    let group = this.Groups[groupName];
    let groupKey = privateKey.decryptGroupKey(group.Users[userNameInGroup]);

    let existingKeys = await group.keys(groupKey);

    for (let key in values) {
      let value = values[key];

      let encryptedKey = existingKeys[key];
      if (!encryptedKey) {
        encryptedKey = await group.encrypt(key, groupKey);
      }

      let encryptedValue = group.Values[encryptedKey];
      let decryptedValue = undefined;
      if (encryptedValue) {
        decryptedValue = group.decrypt(encryptedValue, groupKey);
        if (decryptedValue != value) decryptedValue = undefined;
      }

      if (!decryptedValue) {
        let encryptedValue = await group.encrypt(value, groupKey);
        group.Values[encryptedKey] = encryptedValue;
      }
    }
  }

  public async removeValuesFromGroup(
    groupName: string,
    userNameInGroup: string,
    privateKey: keys.Key,
    valueKeys: string[]
  ) {
    if (!this.Groups[groupName]) {
      return Promise.reject('Group does not exist: ' + groupName);
    }

    if (!this.Users[userNameInGroup]) {
      return Promise.reject('User does not exist: ' + userNameInGroup);
    }

    let group = this.Groups[groupName];
    let groupKey = privateKey.decryptGroupKey(group.Users[userNameInGroup]);

    let existingKeys = await group.keys(groupKey);
    for (let index in valueKeys) {
      let valueKey = valueKeys[index];
      let encryptedKey = existingKeys[valueKey];

      if (encryptedKey) {
        delete group.Values[encryptedKey];
      }
    }
  }

  public async rekeyGroup(
    groupName: string,
    userNameInGroup: string,
    privateKey: keys.Key
  ) {
    if (!this.Groups[groupName]) {
      return Promise.reject('Group does not exist: ' + groupName);
    }

    if (!this.Users[userNameInGroup]) {
      return Promise.reject('User does not exist: ' + userNameInGroup);
    }

    let group = this.Groups[groupName];
    let groupKey = privateKey.decryptGroupKey(group.Users[userNameInGroup]);

    let newGroupKey = groups.Group.newGroupKey();

    //Encrypt the new key for each user
    for (let username in group.Users) {
      let user = this.Users[username];
      group.Users[username] = user.Key.encryptGroupKey(newGroupKey);
    }

    //Re-ncrypt the key / value pairs
    for (let encryptedKey in group.Values) {
      let decryptedKey = await group.decrypt(encryptedKey, groupKey);
      let encryptedValue = group.Values[encryptedKey];
      let decryptedValue = await group.decrypt(encryptedValue, groupKey);

      let recryptedKey = await group.encrypt(decryptedKey, newGroupKey);
      let recryptedValue = await group.encrypt(decryptedValue, newGroupKey);
      delete group.Values[encryptedKey];
      group.Values[recryptedKey] = recryptedValue;
    }
  }

  public async decryptGroup(
    groupName: string,
    userNameInGroup: string,
    privateKey: keys.Key
  ): Promise<groups.IGroupValues> {
    if (!this.Groups[groupName]) {
      return Promise.reject('Group does not exist: ' + groupName);
    }

    if (!this.Users[userNameInGroup]) {
      return Promise.reject('User does not exist: ' + userNameInGroup);
    }

    let group = this.Groups[groupName];
    let groupKey = privateKey.decryptGroupKey(group.Users[userNameInGroup]);

    return await group.keyValues(groupKey);
  }
}
