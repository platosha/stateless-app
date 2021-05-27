import {
  RequestAuthorizationActions,
  RequestAuthorizationStrategy,
  RequestContext
} from "Frontend/connect-client";
import {LoginResult} from "@vaadin/flow-frontend";

export interface Authorization {
  access_token: string;
}

class OAuth2Client implements RequestAuthorizationStrategy {
  private authorization: Authorization | undefined = undefined;

  constructor(private serverUrl: string = 'auth') {
  }

  async token(body: URLSearchParams, requestOptions = {}): Promise<Authorization> {
    const requestInit = {
      method: 'POST',
      headers: {
        'Accept': 'application/json'
      },
      body,
      ...requestOptions
    };

    const response = await (await fetch(this.serverUrl, requestInit)).json();
    if ('error' in response) {
      throw new Error(`Token response error ${response.error_type}: ${response.error_description}`);
    }
    this.authorization = response as Authorization;
    return this.authorization;
  }

  async authorize(context: RequestContext, actions: RequestAuthorizationActions) {
    return this.authorization
      ? actions.withAuthorization(this.authorization)
      : actions.withoutAuthorization();
  }
}

export class LoginFormClient extends OAuth2Client {
  async login(username: string, password: string): Promise<LoginResult> {
    try {
      await this.token(new URLSearchParams({grant_type: 'password', username, password}));
      return {
        error: false
      };
    } catch (e) {
      return {
        error: true,
        errorTitle: 'Error',
        errorMessage: ''
      };
    }
  }

  async logout() {
  }
}

export const loginFormClient = new LoginFormClient();