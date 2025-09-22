declare module "@thxmxx/findmy.js" {
  export interface ICloudLoginResponse {
    dsInfo: {
      lastName: string;
      iCloudEnv: {
        "upload-endpoint": string;
        "search-part-token": string;
        "ck-auth-token": string;
        "instance-id": string;
        "search-url": string;
        "pcs-service-url": string;
        "download-endpoint": string;
        "ck-app-token": string;
        "container-id": string;
        "sharing-url": string;
        "production-url": string;
        "ck-web-auth-token": string;
        "is-custom-environment": boolean;
      };
      hasICloudQualifyingDevice: boolean;
      primaryEmailVerified: boolean;
      appleId: string;
      primaryEmail: string;
      "X-APPLE-WEBAUTH-USER": string;
      "X-APPLE-WEBAUTH-PW": string;
      "X-APPLE-WEBAUTH-TOKEN": string;
      dsid: string;
      fullName: string;
      firstName: string;
      appleIdAliases: string[];
      languageCode: string;
      familyEligible: boolean;
      hasPaymentInfo: boolean;
      appleIdCountry: string;
      isManagedAppleId: boolean;
      aDsID: string;
      notificationId: string;
      isPaidDeveloper: boolean;
      countryCode: string;
      locked: boolean;
    };
    webservices: {
      [key: string]: {
        url: string;
        status: string;
      };
    };
    hsaVersion: number;
    isExtendedLogin: boolean;
    hsaChallengeRequired: boolean;
    "x-apple-id-session-id": string;
    "x-apple-mm-session-id": string;

    requestInfo: {
      country: string;
      "time-zone": string;
      region: string;
    };
    "has-icloud-plus": boolean;
    hsaTrustedBrowser: boolean;
    apps: any[];
    pcsEnabled: boolean;
    "is-icloud-plus-user": boolean;
    "apple-id-features": {
      "is-child-account": boolean;
      "is-legacy-student": boolean;
      "has-parental-controls": boolean;
    };
    "x-apple-mm-data": string;
    authType: string;
    trustedDevice: any;
  }

  export interface AnisetteHeaders {
    "X-Apple-I-Client-Time": string;
    "X-Apple-I-TimeZone": string;
    "X-Apple-I-Request-Key": string;
    "X-Apple-I-MD-M": string;
    "X-Apple-I-MD-RINFO": string;
    "X-Apple-I-MD": string;
  }

  export interface Report {
    name: string;
    id: string;
    modelDisplayName: string;
    location: {
      latitude: number;
      longitude: number;
      timeStamp: number;
    };
  }

  export interface FindMyData {
    advKey: string;
    content: Report[];
    date: string;
    id: string;
    statusCode: string;
  }

  export interface Keys {
    privateKey: string;
    publicKey: string;
    hashedPublicKey: string;
  }

  export function generateKeys(): Keys;

  export function icloudLoginMobileme(
    apple_id: string,
    password: string
  ): Promise<ICloudLoginResponse>;

  export function generateAnisetteHeaders(): Promise<AnisetteHeaders>;

  export function requestReports(
    dsid: string,
    xAppleIdSessionId: string,
    xAppleMmSessionId: string
  ): Promise<FindMyData>;

  export function getFindMyDataFromPrivateKey(privateKey: string): Promise<{
    advertisementKey: string;
    hashedPublicKey: string;
    publicKey: string;
  }>;
}
