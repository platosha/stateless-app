import {
  ConnectClient,
  MiddlewareClass,
  MiddlewareContext,
  MiddlewareNext
} from '@vaadin/flow-frontend';
import {
  Authorization,
  loginFormClient,
} from "Frontend/auth/token-client";

const client = new ConnectClient({prefix: 'connect'});

export enum AuthorizationErrorType {
  UNAUTHORIZED = '',
  INVALID_TOKEN = 'invalid_token',
  INSUFFICIENT_SCOPE = 'insufficient_scope'
}

class AuthorizationError extends Error {
  constructor(public type: AuthorizationError, public attributes: { readonly [key: string]: string } | undefined) {
    super('Authorization e');
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
  authorize(context: RequestContext, requestAuthorizationActions: RequestAuthorizationActions): Promise<Response>
}

const authorizationHeaderName = 'Authorization';

class JwtAuthorizationMiddleware implements MiddlewareClass {
  constructor(private strategy: RequestAuthorizationStrategy = loginFormClient) {
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

    return this.strategy.authorize(context, actions);
  }
}

client.middlewares.push(new JwtAuthorizationMiddleware());
export default client;