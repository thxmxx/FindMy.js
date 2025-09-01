const {
  randomBytes,
  createHash,
  createHmac,
  createDecipheriv,
  pbkdf2Sync,
} = require("crypto");
const crypto = require("crypto");
const { readFileSync, writeFileSync } = require("fs");
const { homedir } = require("os");
const { join } = require("path");
const { v4: uuidv4 } = require("uuid");
const plist = require("plist");
const { Srp, Mode, Hash } = require("@foxt/js-srp");
const axios = require("axios");
const { Buffer } = require("buffer"); // Polyfill for Buffer in browser environments if needed
const https = require("https");

const axiosInstance = axios.create({
  responseType: "arraybuffer", // Set default responseType to arraybuffer
  httpsAgent: new https.Agent({
    secureProtocol: "TLSv1_2_method", // This forces Node.js to use TLS 1.2 or a newer version
    rejectUnauthorized: false,
  }),
});

// Configure SRP library for compatibility with Apple's implementation

const ANISETTE_URL = "http://localhost:6969"; // https://github.com/Dadoum/anisette-v3-server

const USER_ID = uuidv4();
const DEVICE_ID = uuidv4();

async function icloudLoginMobileme(
  username = "",
  password = "",
  second_factor = "sms"
) {
  if (!username) {
    username = await prompt("Apple ID: ");
  }
  if (!password) {
    password = await prompt("Password: ", { echo: false });
  }

  const g = await gsaAuthenticate(username, password, second_factor);
  const pet = g.t["com.apple.gs.idms.pet"].token;
  const adsid = g.adsid;

  const { anisetteData } = await generateAnisetteHeaders();

  const data = {
    "apple-id": username,
    delegates: { "com.apple.mobileme": {} },
    password: pet,
    "client-id": USER_ID,
  };
  const dataPlist = plist.build(data);

  const headers = {
    "X-Apple-ADSID": adsid,
    "User-Agent": "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0",
    ...anisetteData,
  };

  const r = await axios.post(
    "https://setup.icloud.com/setup/iosbuddy/loginDelegates",
    dataPlist,
    {
      headers,
      auth: { username, password: pet },
      validateStatus: () => true, // Don't throw on non-2xx status codes
    }
  );

  return plist.parse(r.data);
}

async function gsaAuthenticate(username, password, second_factor = "sms") {
  const srp = new Srp(Mode.GSA, Hash.SHA256, 2048);
  const usr = await srp.newClient(Buffer.from(username), Buffer.from(""));
  const A = usr.A;

  // --- Step 1: SRP Initialization ---
  let r = await gsaAuthenticatedRequest({
    A2k: Buffer.from(A.toString(16), "hex"),
    ps: ["s2k", "s2k_fo"],
    u: username,
    o: "init",
  });

  if (!r || !r.sp) {
    throw new Error("GSA Init failed. Response was empty or invalid.");
  }

  if (!["s2k", "s2k_fo"].includes(r.sp)) {
    throw new Error(
      `This implementation only supports s2k and sk2_fo. Server returned ${r.sp}`
    );
  }

  // --- Step 2: SRP Challenge Response ---
  usr.p = encryptPassword(password, Buffer.from(r.s, "hex"), r.i, r.sp);
  const M = await usr.generate(
    Buffer.from(r.s, "hex"),
    Buffer.from(r.B, "hex")
  );

  if (!M) {
    throw new Error("Failed to generate SRP challenge");
  }

  r = await gsaAuthenticatedRequest({
    c: r.c,
    M1: Buffer.from(M.toString("hex"), "hex"),
    u: username,
    o: "complete",
  });

  if (!r || !r.M2) {
    throw new Error("GSA Complete failed. Response was empty or invalid.");
  }

  // --- Step 3: Verify Server and Decrypt Session ---
  const M2 = await usr.generateM2();
  if (
    Buffer.from(r.M2, "hex").toString("hex") !== Buffer.from(M2).toString("hex")
  ) {
    throw new Error("Failed to verify session (M2 mismatch)");
  }

  const spd = await decryptCbc(usr, Buffer.from(r.spd, "base64"));
  const parsedSpd = plist.parse("<plist>" + spd.toString() + "</plist>");

  // --- FIX: This is the corrected logic block ---
  if (
    r.Status &&
    ["trustedDeviceSecondaryAuth", "secondaryAuth"].includes(r.Status.au)
  ) {
    // CASE 1: 2FA is explicitly required.
    console.log("2FA required, requesting code");
    for (const key in parsedSpd) {
      if (Buffer.isBuffer(parsedSpd[key])) {
        parsedSpd[key] = parsedSpd[key].toString("base64");
      }
    }
    if (second_factor === "sms") {
      await smsSecondFactor(parsedSpd.adsid, parsedSpd.GsIdmsToken);
    } else if (second_factor === "trusted_device") {
      await trustedSecondFactor(parsedSpd.adsid, parsedSpd.GsIdmsToken);
    }
    // After 2FA is complete, re-run the entire authentication flow.
    return gsaAuthenticate(username, password);
  } else {
    // CASE 2: No 'au' key is present. This is a SUCCESS.
    // Return the parsed session data.
    return parsedSpd;
  }
}

async function gsaAuthenticatedRequest(parameters) {
  const { anisetteData } = await generateAnisetteHeaders();

  const body = {
    Header: { Version: "1.0.1" },
    Request: { cpd: await generateCpd(anisetteData) },
  };
  Object.assign(body.Request, parameters);

  const headers = {
    "Content-Type": "text/x-xml-plist",
    Accept: "*/*",
    "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
    ...anisetteData,
  };

  const requestBody = plist.build(body);

  const resp = await axiosInstance.post(
    "https://gsa.apple.com/grandslam/GsService2",
    requestBody,
    {
      headers,
      validateStatus: () => true,
      timeout: 5000,
      responseType: "arraybuffer", // Ensure response is treated as buffer
    }
  );

  if (resp.status !== 200) {
    throw new Error(`Request failed with status ${resp.status}`);
  }

  const responseString = Buffer.from(resp.data).toString();
  return plist.parse(responseString).Response;
}

async function generateCpd(anisetteData) {
  const cpd = {
    bootstrap: true,
    icscrec: true,
    pbe: false,
    prkgen: true,
    svct: "iCloud",
    loc: anisetteData["X-Apple-Locale"], // FIX: Add the missing 'loc' key.
  };

  // FIX: The Python version does not include X-Mme-Client-Info inside the cpd block,
  // so we must remove it before merging.
  delete anisetteData["X-Mme-Client-Info"];

  // Use the provided Anisette data.
  Object.assign(cpd, anisetteData);
  return cpd;
}

async function generateAnisetteHeaders() {
  try {
    const response = await axios.get(ANISETTE_URL, {
      timeout: 5000,
      responseType: "json",
    });

    const anisetteData = response.data;

    return { anisetteData };
  } catch (e) {
    console.error(
      `Failed to query anisette server at ${ANISETTE_URL}. Please ensure it's running.`
    );
    // It's better to throw an error here than to continue with an invalid request
    throw new Error("Anisette server is unavailable.");
  }
}

function encryptPassword(password, salt, iterations, protocol) {
  if (!["s2k", "s2k_fo"].includes(protocol)) {
    throw new Error("Unsupported protocol");
  }
  let p = createHash("sha256").update(password).digest();
  if (protocol === "s2k_fo") {
    p = Buffer.from(p.toString("hex"));
  }
  // @foxt/js-srp's Client.setPassword expects a Buffer, so we need to ensure the output is a Buffer.
  // The original Python uses pbkdf2 from the `pbkdf2` library, which returns bytes.
  // Node.js crypto.pbkdf2 returns a Buffer.
  return pbkdf2Sync(p, salt, iterations, 32, "sha256");
}

function createSessionKey(usr, name) {
  const k = usr.K; // @foxt/js-srp stores the session key in `K` property
  if (!k) {
    throw new Error("No session key");
  }
  return createHmac("sha256", k).update(name).digest();
}

function decryptCbc(usr, data) {
  const extraDataKey = createSessionKey(usr, "extra data key:");
  const extraDataIv = createSessionKey(usr, "extra data iv:").slice(0, 16);

  const decipher = createDecipheriv("aes-256-cbc", extraDataKey, extraDataIv);
  let decrypted = decipher.update(data);
  decrypted = Buffer.concat([decrypted, decipher.final()]);

  // PKCS#7 unpadding (Node.js crypto handles this automatically if padding is enabled by default)
  return decrypted;
}

async function trustedSecondFactor(dsid, idmsToken) {
  const identityToken = Buffer.from(`${dsid}:${idmsToken}`).toString("base64");

  const { anisetteData } = await generateAnisetteHeaders();

  const headers = {
    Accept: "application/json, text/javascript, */*", // FIX: Correct Accept header
    "X-Apple-Identity-Token": identityToken,
    "X-Xcode-Version": "11.2 (11B41)",
    "X-Apple-App-Info": "com.apple.gs.xcode.auth",
    "User-Agent": "Xcode",
    ...anisetteData,
  };

  await axiosInstance.get("https://gsa.apple.com/auth/verify/trusteddevice", {
    headers,
    validateStatus: () => true,
    timeout: 10000,
  });

  const code = await prompt("Enter 2FA code: ");
  headers["security-code"] = code;
  headers["Accept"] = "text/x-xml-plist";

  const resp = await axiosInstance.get(
    "https://gsa.apple.com/grandslam/GsService2/validate",
    {
      headers,
      validateStatus: () => true,
      timeout: 10000,
    }
  );

  if (resp.status === 200) {
    console.log("2FA successful");
  } else {
    console.error("2FA failed:", resp.status, resp.data);
  }
}

async function smsSecondFactor(dsid, idmsToken) {
  const identityToken = Buffer.from(`${dsid}:${idmsToken}`).toString("base64");

  const { anisetteData } = await generateAnisetteHeaders();

  const headers = {
    "Content-Type": "application/json", // FIX: Set correct Content-Type
    Accept: "application/json, text/javascript, */*", // FIX: Correct Accept header
    "X-Apple-Identity-Token": identityToken,
    "X-Apple-App-Info": "com.apple.gs.xcode.auth",
    "X-Xcode-Version": "11.2 (11B41)",
    "User-Agent": "Xcode",
    ...anisetteData,
  };

  const body = { phoneNumber: { id: 1 }, mode: "sms" };

  try {
    const response = await axiosInstance.put(
      "https://gsa.apple.com/auth/verify/phone/",
      body,
      {
        headers,
        validateStatus: () => true,
        timeout: 5000,
        responseType: "json", // Expect a JSON response
      }
    );
    console.log("SMS 2FA request response status:", response.status);
    console.log("SMS 2FA request response data:", response.data);
    if (response.status !== 200) {
      console.error(
        "Failed to request SMS 2FA code:",
        response.status,
        response.data
      );
      throw new Error("Failed to request SMS 2FA code.");
    }
  } catch (error) {
    console.error("Error requesting SMS 2FA code:", error.message);
    throw error;
  }

  const code = await prompt("Enter 2FA code: ");
  body.securityCode = { code };

  const resp = await axiosInstance.post(
    "https://gsa.apple.com/auth/verify/phone/securitycode",
    body,
    {
      headers,
      validateStatus: () => true,
      timeout: 5000,
      responseType: "json", // FIX: Expect a JSON response
    }
  );

  if (resp.status === 200) {
    console.log("2FA successful");
  } else {
    console.error("2FA failed:", resp.status, resp.data);
  }
}

// Simple prompt function for input (Node.js specific)
function prompt(question, options = {}) {
  return new Promise((resolve) => {
    const readline = require("readline").createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    readline.question(question, (answer) => {
      readline.close();
      resolve(answer);
    });
  });
}

module.exports = {
  icloudLoginMobileme,
  gsaAuthenticate,
  generateAnisetteHeaders,
};
