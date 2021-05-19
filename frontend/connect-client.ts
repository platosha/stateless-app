import {
  ConnectClient,
  MiddlewareClass,
  MiddlewareContext,
  MiddlewareNext
} from '@vaadin/flow-frontend';
import {authenticationStore} from "Frontend/stores/authentication-store";

const client = new ConnectClient({prefix: 'connect'});

class JwtAuthorizationMiddleware implements MiddlewareClass {
  constructor(private tokenCallback: () => string | void | Promise<string | void>) {
  }

  async invoke(context: MiddlewareContext, next: MiddlewareNext) {
    const token = await this.tokenCallback();
    if (token) {
      context.request.headers.append(
        'Authorization',
        `Bearer ${token}`
      );
    }
    return next(context);
  }
}

client.middlewares.push(new JwtAuthorizationMiddleware(() => authenticationStore.access_token));
export default client;