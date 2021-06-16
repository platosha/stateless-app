interface Authentication {
  readonly claims?: Record<string, any>;
  onChange: () => void;
}

export class JwtCookieAuthentication implements Authentication {
  private __claims?: Record<string, any>;
  private __pollCookiesInterval?: number;
  private __cookie: string = '';
  private __jwtPayload?: string;
  private __pollCookies = () => {
    if (document.cookie !== this.__cookie) {
      this.__cookie = document.cookie;
      this.__parseCookie();
    }
  };

  public onChange = () => {
  };

  constructor() {
    this.subscribe();
  }

  get claims() {
    return this.__claims;
  }

  subscribe() {
    this.__pollCookiesInterval = self.setInterval(this.__pollCookies, 1000 / 60);
  }

  unsubscribe() {
    if (this.__pollCookiesInterval) {
      self.clearInterval(this.__pollCookiesInterval);
      this.__pollCookiesInterval = undefined;
    }
  }

  private __parseCookie() {
    const cookies = this.__cookie.split(/;[ ]?/);
    const cookieName = "jwt.headerAndPayload=";
    const jwtCookie = cookies.find(cookie => cookie.startsWith(cookieName));
    const jwtPayload = jwtCookie && jwtCookie.slice(cookieName.length).split('.')[1] || undefined;
    if (this.__jwtPayload !== jwtPayload) {
      this.__jwtPayload = jwtPayload;
      this.__claims = this.__jwtPayload ? JSON.parse(atob(this.__jwtPayload)) : undefined;
      this.onChange();
    }
  }
}

export const authentication: Authentication = new JwtCookieAuthentication();
