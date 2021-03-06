import {
  ConnectClient,
  MiddlewareClass,
  MiddlewareContext,
  MiddlewareNext
} from '@vaadin/flow-frontend';
import {
  Authorization,
  statelessLoginClient,
} from "Frontend/auth/token-client";

const client = new ConnectClient({prefix: 'connect'});

export enum AuthorizationErrorType {
  UNAUTHORIZED = '',
  INVALID_TOKEN = 'invalid_token',
  INSUFFICIENT_SCOPE = 'insufficient_scope'
}

class AuthorizationError extends Error {
  constructor(public type: AuthorizationErrorType, public attributes: { readonly [key: string]: string } | undefined) {
    super(`Authorization error: ${type}`);
  }
}

class InvalidTokenError extends AuthorizationError {
  constructor(public attributes: { readonly [key: string]: string } | undefined) {
    super(AuthorizationErrorType.INVALID_TOKEN, attributes);
  }
}

class InsufficientScopeError extends AuthorizationError {
  constructor(public attributes: { readonly [key: string]: string } | undefined) {
    super(AuthorizationErrorType.INSUFFICIENT_SCOPE, attributes);
  }
}

export interface AccessTokenHolder {
  readonly access_token: string;
}

export interface RequestAuthorizationActions {
  withAuthorization: (authorization: Authorization) => Promise<Response>;
  withoutAuthorization: () => Promise<Response>;
}

export interface RequestContext {
  request: Request;
}

export interface RequestAuthorizationStrategy {
  authorizeRequest(context: RequestContext, requestAuthorizationActions: RequestAuthorizationActions): Promise<Response>
}

const authorizationHeaderName = 'Authorization';

class BearerAuthorizationMiddleware implements MiddlewareClass {
  constructor(private strategy: RequestAuthorizationStrategy) {
  }

  async invoke(context: MiddlewareContext, next: MiddlewareNext) {
    const authorizationErrorMiddleware = (context: MiddlewareContext, next: MiddlewareNext) => {
      return next(context);
    };

    const actions: RequestAuthorizationActions = {
      async withAuthorization(authorization: Authorization) {
        context.request.headers.set(
          authorizationHeaderName,
          `Bearer ${authorization.access_token}`
        );
        return authorizationErrorMiddleware(context, next);
      },
      async withoutAuthorization() {
        context.request.headers.delete(authorizationHeaderName);
        return authorizationErrorMiddleware(context, next);
      }
    }

    return this.strategy.authorizeRequest(context, actions);
  }
}

class StatelessLoginClientMiddleware extends BearerAuthorizationMiddleware {
  constructor() {
    super(statelessLoginClient);
  }
}

client.middlewares.push(new StatelessLoginClientMiddleware());
export default client;

// Example: using custom client

class DummyCustomOAuth2Client {
  public readonly authorized = false;

  async getAccessToken(): Promise<{access_token: string}> {
    return {access_token: 'abc'};
  }

  async refresh(): Promise<void> {
  }
}
const oauth2Client = new DummyCustomOAuth2Client();

class CustomAuthorizationStrategy implements RequestAuthorizationStrategy {
  async authorizeRequest(context: RequestContext, actions: RequestAuthorizationActions): Promise<Response> {
    return oauth2Client.authorized
      ? actions.withAuthorization(await oauth2Client.getAccessToken())
      : actions.withoutAuthorization();
  }
}

new BearerAuthorizationMiddleware(new CustomAuthorizationStrategy());

// Example: handle errors

class RefreshAndRetryStrategy extends CustomAuthorizationStrategy {
  async authorizeRequest(context: RequestContext, actions: RequestAuthorizationActions): Promise<Response> {
    try {
      return await super.authorizeRequest(context, actions);
    } catch (error) {
      if (error instanceof InvalidTokenError) {
        await oauth2Client.refresh();
        return this.authorizeRequest(context, actions);
      }
      throw error;
    }
  }
}

new BearerAuthorizationMiddleware(new RefreshAndRetryStrategy());
