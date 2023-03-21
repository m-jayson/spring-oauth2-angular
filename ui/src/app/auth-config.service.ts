import { Injectable } from '@angular/core';
import { AuthConfig,OAuthService } from 'angular-oauth2-oidc';

export const authCodeFlowConfig: AuthConfig = {
  // Url of the Identity Provider
  issuer: 'http://localhost:9000',

  disablePKCE: false,
  sessionChecksEnabled: false,

  // URL of the SPA to redirect the user to after login
  redirectUri: window.location.origin ,

  // The SPA's id. The SPA is registerd with this id at the auth-server
  // clientId: 'server.code',
  clientId: 'public-client',

  // Just needed if your auth server demands a secret. In general, this
  // is a sign that the auth server is not configured with SPAs in mind
  // and it might not enforce further best practices vital for security
  // such applications.
  // dummyClientSecret: 'secret',

  responseType: 'code',

  // set the scope for the permissions the client should request
  // The first four are defined by OIDC.
  // Important: Request offline_access to get a refresh token
  // The api scope is a usecase specific one
  scope: 'openid profile email',

  showDebugInformation: true,
  
};

@Injectable({
  providedIn: 'root'
})
export class AuthConfigServiceService {

  constructor(private readonly oauthService : OAuthService) {
    if (!this.oauthService.hasValidIdToken()) {
      this.oauthService.configure({
          scope: 'openid profile email',
          responseType: 'code',
          oidc: true,
          disablePKCE: false,
          sessionChecksEnabled: false,
          clientId: 'public-client',
          issuer: 'http://localhost:9000', // eg. https://acme-jdo9fs.zitadel.cloud
          redirectUri: 'http://localhost:4200/auth/callback',
          postLogoutRedirectUri: 'http://localhost:4200/',
          requireHttps: false // required for running locally
      });

      this.oauthService.loadDiscoveryDocument().then(() => {
          this.oauthService.initCodeFlow();
      });
  }
  }
}
