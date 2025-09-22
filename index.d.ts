declare module "@thxmxx/findmy.js" {
  export interface KeyData {
    SN: string;
    MAC: string;
    FF: string;
    hashed_adv_public_key: string;
    private_key: string;
    public_key: string;
  }

  export interface FindMyData {
    public_key: string;
    MAC: string;
    FF: string;
    hashed_adv_public_key: string;
  }

  export interface ICloudAuth {
    dsid: string;
    delegates: {
      "com.apple.mobileme": {
        "service-data": {
          tokens: {
            searchPartyToken: string;
          };
        };
      };
    };
    // Other properties may exist
  }

  export interface AnisetteData {
    "X-Apple-I-Client-Time": string;
    "X-Apple-I-TimeZone": string;
    "X-Apple-Locale": string;
    "X-Apple-I-MD": string;
    "X-Apple-I-MD-M": string;
    "X-Apple-I-MD-RINFO": string;
    "X-Apple-I-SRL-NO": string;
    "X-Mme-Device-Id": string;
    // Other properties may exist
  }

  export interface AuthObject {
    dsid: string;
    searchPartyToken: string;
  }

  export interface LocationReport {
    lat: number;
    lon: number;
    conf: number;
    status: number;
    timestamp: number;
    isodatetime: string;
    key: string;
    goog: string;
  }

  export function generateKeys(
    nkeys?: number,
    prefix?: string,
    startFrom?: number
  ): Promise<KeyData[]>;

  export function getFindMyDataFromPrivateKey(
    privateKeyB64: string
  ): Promise<FindMyData | null>;

  export function icloudLoginMobileme(
    username?: string,
    password?: string,
    second_factor?: "sms" | "trusted_device"
  ): Promise<ICloudAuth>;

  export function generateAnisetteHeaders(
    anisetteUrl?: string
  ): Promise<{ anisetteData: AnisetteData }>;

  export function requestReports(
    pKey: string,
    hours?: number,
    username?: string,
    password?: string,
    regen?: boolean,
    trustedDevice?: boolean,
    authObject?: AuthObject | null
  ): Promise<LocationReport[]>;

  export function requestReports(
    pKey: string,
    authObject: AuthObject
  ): Promise<LocationReport[]>;
}
