export interface PasskeyAssertion {
  credentialId: string;
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
}

export interface BaseIdentity {
  provider: string;
}

export interface GoogleIdentity extends BaseIdentity {
  provider: 'google';
  idToken: string;
}

export interface GitHubIdentity extends BaseIdentity {
  provider: 'github';
  accessToken: string;
}

export interface TwitterIdentity extends BaseIdentity {
  provider: 'twitter';
  accessToken: string;
}

export interface PasskeyIdentity extends BaseIdentity {
  provider: 'passkey';
  assertion: PasskeyAssertion;
}

export type SupportedIdentity = GoogleIdentity | GitHubIdentity | TwitterIdentity | PasskeyIdentity;

export interface IdentityClaim {
  provider: string;
  stableId: string;
}