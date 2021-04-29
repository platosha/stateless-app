import {
  ConnectClient,
  MiddlewareClass,
  MiddlewareContext,
  MiddlewareNext
} from '@vaadin/flow-frontend';

const client = new ConnectClient({prefix: 'connect'});

class JwtAuthorizationMiddleware implements MiddlewareClass {
  async invoke(context: MiddlewareContext, next: MiddlewareNext) {
    const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiaXNzdWVyIjoiU3RhdGVsZXNzYXBwIiwibmFtZSI6IlVzZXIiLCJzY29wZSI6InVzZXIiLCJpYXQiOjE2MTk3MTAzNDczMDJ9.744-rFDiBLI-r-AHZnTWoMZT323lBQ0-N12GUBbN3tU';
    context.request.headers.append(
      'Authorization',
      `Bearer ${token}`
    );
    return next(context);
  }
}

client.middlewares.push(new JwtAuthorizationMiddleware());
export default client;