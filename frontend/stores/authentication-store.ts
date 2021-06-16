import {authentication} from "Frontend/auth";
import {
  action,
  makeObservable,
  observable
} from "mobx";

export interface UserInfo {
  name?: string;
  picture?: string;
}

function getUserInfo() {
  return authentication.claims as UserInfo | undefined;
}

export class AuthenticationStore {
  user?: UserInfo = getUserInfo();

  constructor() {
    makeObservable(this, {
      user: observable,
      updateUser: action.bound
    });

    authentication.onChange = this.updateUser;
    this.updateUser();
  }

  updateUser() {
    this.user = getUserInfo();
  }
}

export const authenticationStore = new AuthenticationStore();