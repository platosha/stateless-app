import {makeAutoObservable} from "mobx";
import {tokenClient} from "Frontend/auth/token-client";
import {LoginResult} from "@vaadin/flow-frontend/Authentication";

export class AuthenticationStore {
  access_token?: string = undefined;

  constructor() {
    makeAutoObservable(this);
  }

  async login(username: string, password: string): Promise<LoginResult> {
    try {
      const {access_token} = await tokenClient.getTokenUsingPasswordGrant(username, password);
      this.access_token = access_token;
      return {error: false};
    } catch (e) {
      return {
        error: true,
        errorTitle: e.error_type,
        errorMessage: e.error_description
      };
    }
  }
}

export const authenticationStore = new AuthenticationStore();