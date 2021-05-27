import {makeAutoObservable} from "mobx";

export class AuthenticationStore {
  constructor() {
    makeAutoObservable(this);
  }
}

export const authenticationStore = new AuthenticationStore();