export interface TokenResponse {
  access_token: string;
}

export class TokenClient {
  constructor(private tokenUrl: string = '/auth/token') {
  }

  async getTokenUsingPasswordGrant(username: string, password: string): Promise<TokenResponse> {
    const body = new URLSearchParams({
      grant_type: 'password',
      username,
      password
    });

    const requestInit = {
      method: 'POST',
      headers: {
        'Accept': 'application/json'
      },
      body
    };

    const response = await (await fetch(this.tokenUrl, requestInit)).json();
    if ('error' in response) {
      throw new Error(`Token response error ${response.error_type}: ${response.error_description}`);
    }

    return response as TokenResponse;
  }
}

export const tokenClient = new TokenClient();