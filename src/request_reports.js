const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const axios = require("axios");
const {
  icloudLoginMobileme,
  generateAnisetteHeaders,
} = require("./pypush_gsa_icloud");
const { sha256, getFindMyDataFromPrivateKey } = require("./generate_keys"); // Reusing sha256 from generate_keys.js
const { Buffer } = require("buffer"); // Polyfill for Buffer if needed

function decrypt(encData, algorithmDkey, iv, tag) {
  const decipher = crypto.createDecipheriv("aes-128-gcm", algorithmDkey, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(encData);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted;
}

function decodeTag(data) {
  // Assuming data is a Buffer
  const latitude = data.readInt32BE(0) / 10000000.0;
  const longitude = data.readInt32BE(4) / 10000000.0;
  const confidence = data.readUInt8(8);
  const status = data.readUInt8(9);
  return { lat: latitude, lon: longitude, conf: confidence, status: status };
}

/**
 * Gets authentication data from various sources
 * @param {boolean} regenerate - Whether to regenerate auth from iCloud
 * @param {string} second_factor - 2FA method ("sms" or "trusted_device")
 * @param {string} username - iCloud username
 * @param {string} password - iCloud password
 * @param {Object} authObject - Pre-existing auth object with dsid and searchPartyToken
 * @returns {Object} Authentication object with dsid and searchPartyToken
 */
async function getAuth(
  regenerate = false,
  second_factor = "sms",
  username,
  password,
  authObject = null
) {
  // If auth object is provided, use it directly
  if (authObject && typeof authObject === 'object' && authObject.dsid && authObject.searchPartyToken) {
    return authObject;
  }

  const configPath = path.join(process.cwd(), "auth.json");
  if (fs.existsSync(configPath) && !regenerate) {
    return JSON.parse(fs.readFileSync(configPath, "utf8"));
  } else {
    if (!username || !password) {
      throw new Error("Username and password are required");
    }
    const mobileme = await icloudLoginMobileme(
      username,
      password,
      second_factor
    );
    const j = {
      dsid: mobileme.dsid,
      searchPartyToken:
        mobileme.delegates["com.apple.mobileme"]["service-data"].tokens
          .searchPartyToken,
    };
    fs.writeFileSync(configPath, JSON.stringify(j));
    return j;
  }
}

/**
 * Requests FindMy location reports for a device
 * @param {string} pKey - Base64 encoded private key
 * @param {number} hours - Number of hours to look back (default: 24)
 * @param {string} username - iCloud username (optional if using authObject or saved auth)
 * @param {string} password - iCloud password (optional if using authObject or saved auth)
 * @param {boolean} regen - Whether to regenerate authentication (default: false)
 * @param {boolean} trustedDevice - Whether to use trusted device for 2FA (default: false)
 * @param {Object} authObject - Pre-existing auth object with dsid and searchPartyToken (optional)
 * @returns {Array} Array of location reports with timestamps and coordinates
 */
async function requestReports(
  pKey,
  hours = 24,
  username = undefined,
  password = undefined,
  regen = false,
  trustedDevice = false,
  authObject = null
) {
  const keys = await getFindMyDataFromPrivateKey(pKey);
  const unixEpoch = Math.floor(Date.now() / 1000);
  const startDate = unixEpoch - hours * 60 * 60;
  const data = {
    search: [
      {
        startDate: startDate * 1000,
        endDate: unixEpoch * 1000,
        ids: [keys.hashed_adv_public_key],
      },
    ],
  };

  const auth = await getAuth(
    regen,
    trustedDevice ? "trusted_device" : "sms",
    username,
    password,
    authObject
  );
  const dsid = auth.dsid;
  const searchPartyToken = auth.searchPartyToken;

  const { anisetteData } = await generateAnisetteHeaders();

  const r = await axios.post(
    "https://gateway.icloud.com/acsnservice/fetch",
    data,
    {
      auth: {
        username: dsid,
        password: searchPartyToken,
      },
      headers: anisetteData,
      validateStatus: () => true,
    }
  );

  const res = r.data.results;
  console.log(`${r.status}: ${res.length} reports received.`);

  const ordered = [];
  const found = new Set();

  const priv = BigInt("0x" + Buffer.from(pKey, "base64").toString("hex"));

  for (const report of res) {
    let dataPayload = Buffer.from(report.payload, "base64");
    if (dataPayload.length > 88)
      dataPayload = Buffer.concat([
        dataPayload.slice(0, 4),
        dataPayload.slice(5),
      ]);

    const timestamp = dataPayload.readUInt32BE(0) + 978307200;

    const ephKeyHex = dataPayload.slice(5, 62).toString("hex");
    const ecdh = crypto.createECDH("secp224r1");
    ecdh.setPrivateKey(Buffer.from(priv.toString(16), "hex"));
    const ephemeralPublicKeyBuffer = Buffer.from(ephKeyHex, "hex");
    const sharedKey = ecdh.computeSecret(ephemeralPublicKeyBuffer);

    const symmetricKey = sha256(
      Buffer.concat([
        sharedKey,
        Buffer.from([0, 0, 0, 1]),
        dataPayload.slice(5, 62),
      ])
    );

    const decryptionKey = symmetricKey.slice(0, 16);
    const iv = symmetricKey.slice(16);
    const encData = dataPayload.slice(62, 72);
    const tag = dataPayload.slice(72);

    const decrypted = decrypt(encData, decryptionKey, iv, tag);
    const decodedTag = decodeTag(decrypted);
    decodedTag.timestamp = timestamp;
    decodedTag.isodatetime = new Date(timestamp * 1000).toISOString();
    decodedTag.key = keys.hashed_adv_public_key;
    decodedTag.goog = `https://maps.google.com/maps?q=${decodedTag.lat},${decodedTag.lon}`;
    found.add(decodedTag.key);
    ordered.push(decodedTag);
  }
  ordered.sort((a, b) => a.timestamp - b.timestamp);
  return ordered;
}

// Command-line argument parsing equivalent to Python's argparse

if (require.main === module) {
  // Example usage:
  
  // Method 1: Using saved auth.json file (existing behavior)
  // requestReports('YOUR_PRIVATE_KEY_BASE64', 24);
  
  // Method 2: Using username/password (existing behavior)
  // requestReports('YOUR_PRIVATE_KEY_BASE64', 24, 'username', 'password');
  
  // Method 3: Using auth object (NEW FEATURE)
  // const authObject = {
  //   dsid: 'your_dsid_here',
  //   searchPartyToken: 'your_search_party_token_here'
  // };
  // requestReports('YOUR_PRIVATE_KEY_BASE64', 24, undefined, undefined, false, false, authObject);
  
  // Method 4: Shorter syntax for auth object
  // requestReports('YOUR_PRIVATE_KEY_BASE64', 24, null, null, false, false, authObject);
}

module.exports = { requestReports };
