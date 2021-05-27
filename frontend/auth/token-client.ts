import {
  RequestAuthorizationActions,
  RequestAuthorizationStrategy,
  RequestContext
} from "Frontend/connect-client";
import {LoginResult} from "@vaadin/flow-frontend";

export interface Authorization {
  access_token: string;
}

export class OAuth2Client implements RequestAuthorizationStrategy {
  protected authorization: Authorization | undefined = undefined;
  protected serverRootUrl: URL;

  constructor(serverRootUrl: URL | string = 'auth/') {
    this.serverRootUrl = serverRootUrl instanceof URL ? serverRootUrl : new URL(serverRootUrl, document.baseURI);
  }

  protected get tokenUrl(): URL {
    return new URL('./token', this.serverRootUrl);
  }

  protected async token(body: URLSearchParams, requestOptions = {}): Promise<Authorization> {
    const requestInit = {
      method: 'POST',
      headers: {
        'Accept': 'application/json'
      },
      body,
      ...requestOptions
    };

    const request = new Request(String(this.tokenUrl), requestInit);
    const response = await (await fetch(request)).json();
    if ('error' in response) {
      throw new Error(`Token response error ${response.error_type}: ${response.error_description}`);
    }
    this.authorization = response as Authorization;
    return this.authorization;
  }

  async authorizeRequest(context: RequestContext, actions: RequestAuthorizationActions) {
    return this.authorization
      ? actions.withAuthorization(this.authorization)
      : actions.withoutAuthorization();
  }
}

export class LoginFormClient extends OAuth2Client {
  async login(username: string, password: string): Promise<LoginResult> {
    try {
      await this.token(new URLSearchParams({
        grant_type: 'password',
        username,
        password
      }));
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
    this.authorization = undefined;
  }
}

export const loginFormClient = new LoginFormClient();