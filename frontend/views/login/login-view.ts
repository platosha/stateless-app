import {
  customElement,
  html,
  LitElement,
  property
} from 'lit-element';

import '@vaadin/vaadin-login/vaadin-login-overlay';
import {LoginI18n} from '@vaadin/vaadin-login';
import {
  AfterEnterObserver,
  RouterLocation
} from '@vaadin/router';
import type {LoginResult} from '@vaadin/flow-frontend';
import {
  statelessLoginClient
} from "Frontend/auth/token-client";

@customElement('login-view')
export class LoginView extends LitElement implements AfterEnterObserver {

  @property({type: Boolean})
  private error = false;

  @property()
  private errorTitle = '';

  @property()
  private errorMessage = '';

  private onSuccess: (result: LoginResult) => void;

  // the url to redirect to after a successful login
  private returnUrl?: string

  constructor() {
    super();
    this.onSuccess = (result: LoginResult) => {
      // window.location.href =
      //   result.redirectUrl || this.returnUrl || result.defaultUrl || '/';
    };
  }

  private static popupResult?: Promise<LoginResult>;

  static async openAsPopup(): Promise<LoginResult> {
    if (this.popupResult) {
      return this.popupResult;
    }

    const popup = new this();
    return this.popupResult = new Promise(resolve => {
      popup.onSuccess = result => {
        this.popupResult = undefined;
        popup.remove();
        resolve(result);
      }
      document.body.append(popup);
    });
  }

  render() {
    return html`
        <vaadin-login-overlay
                opened
                .error=${this.error}
                .i18n="${this.i18n}"
                @login="${this.login}">
        </vaadin-login-overlay>
    `;
  }

  async login(event: CustomEvent): Promise<LoginResult> {
    this.error = false;
    const {
      username,
      password
    } = event.detail;
    const result = await statelessLoginClient.login(username, password);
    this.error = result.error;
    this.errorTitle = result.errorTitle || this.errorTitle;
    this.errorMessage = result.errorMessage || this.errorMessage;

    if (!result.error) {
      this.onSuccess(result);
    }

    return result;
  }

  onAfterEnter(location: RouterLocation) {
    this.returnUrl = location.redirectFrom;
  }

  private get i18n(): LoginI18n {
    return {
      header: {
        title: 'Stateless Application',
        description: 'Example application. Log in with user:user.'
      },
      form: {
        title: 'Log in',
        username: 'Username',
        password: 'Password',
        submit: 'Log in',
        forgotPassword: 'Forgot password'
      },
      errorMessage: {
        title: this.errorTitle,
        message: this.errorMessage
      },
    };
  }
}