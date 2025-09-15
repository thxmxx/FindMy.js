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

async function getAuth(
  regenerate = false,
  second_factor = "sms",
  username,
  password
) {
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

async function requestReports(
  pKey,
  hours = 24,
  username = undefined,
  password = undefined,
  regen = false,
  trustedDevice = false
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
    password
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
  // requestReports(24, '', false, false); // Request reports for the last 24 hours, no prefix, no regen, no trusted device
}

module.exports = { requestReports };
