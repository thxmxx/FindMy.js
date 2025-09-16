const crypto = require('crypto');
const fs = require('fs');
const asn1 = require('asn1.js');


function sha256(data) {
    return crypto.createHash('sha256').update(data).digest();
}

function intToBytes(num, byteLength) {
    const hex = num.toString(16);
    const paddedHex = hex.padStart(byteLength * 2, '0');
    return Buffer.from(paddedHex, 'hex');
}

// Define the ASN.1 schema for SubjectPublicKeyInfo (SPKI)
const SubjectPublicKeyInfo = asn1.define('SubjectPublicKeyInfo', function() {
    this.seq().obj(
        this.key('algorithm').seq().obj(
            this.objid('algorithm'), // Corrected: Use objid for OID field
            this.optional().any('parameters')
        ),
        this.key('subjectPublicKey').bitstr()
    );
});

function generateFindMyData(
    b64AdvPublicKey,
    stateByte = 0x20
) {
    try {
        let advPublicKey;
        try {
            advPublicKey = Buffer.from(b64AdvPublicKey, "base64");
        } catch (e) {
            console.error(`Error: Invalid Base64 public key provided. ${e}`);
            return { macAddress: null, ffPayload: null };
        }

        if (advPublicKey.length < 28) {
            console.error(
                `Decoded public key must be at least 28 bytes long, but got ${advPublicKey.length}.`
            );
            return { macAddress: null, ffPayload: null };
        } else if (advPublicKey.length > 28) {
            console.warn(
                `Warning: Decoded public key is ${advPublicKey.length} bytes long. Using only the first 28 bytes.`
            );
            advPublicKey = advPublicKey.subarray(0, 28);
        }

        // --- 1. Generate the MAC Address ---
        const macBytes = Buffer.alloc(6);
        macBytes[0] = advPublicKey[0] | 0xc0;
        advPublicKey.subarray(1, 6).copy(macBytes, 1);
        const macAddress = Array.from(macBytes)
            .map((b) => b.toString(16).padStart(2, "0"))
            .join(":")
            .toUpperCase();

        // --- 2. Generate the FF Advertising Payload ---
        const ffPayloadParts = ["4C001219"];
        ffPayloadParts.push(stateByte.toString(16).padStart(2, "0").toUpperCase());
        ffPayloadParts.push(advPublicKey.subarray(6).toString("hex").toUpperCase());
        ffPayloadParts.push(
            ((advPublicKey[0] >> 6) & 0x03)
                .toString(16)
                .padStart(2, "0")
                .toUpperCase()
        ); // Ensure only 2 bits
        ffPayloadParts.push(
            advPublicKey[5].toString(16).padStart(2, "0").toUpperCase()
        );

        const ffPayload = ffPayloadParts.join("");

        return { macAddress, ffPayload };
    } catch (e) {
        console.error(`Error generating Find My data: ${e.message}`);
        return { macAddress: null, ffPayload: null };
    }
}

/**
 * Generates FindMy keys with customizable starting serial number
 * @param {number} nkeys - Number of keys to generate (default: 1)
 * @param {string} prefix - Prefix filter for hashed public key (default: '')
 * @param {number} startFrom - Starting serial number for generated keys (default: 1)
 * @returns {Array} Array of generated key objects with SN, MAC, FF, hashed_adv_public_key, private_key, public_key
 */
async function generateKeys(nkeys = 1, prefix = '', startFrom = 1) {
    const generatedKeys = [];
    let attempts = 0;
    while (generatedKeys.length < nkeys && attempts < nkeys * 1000) { // Add a limit to attempts
        attempts++;
        // Generate a random private key (224 bits for secp224r1)
        const keyPair = crypto.generateKeyPairSync('ec', { namedCurve: 'secp224r1' });
        const priv = BigInt('0x' + keyPair.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('hex').substring(16, 16 + 28 * 2)); // Extract 28 bytes private key

        // Export public key as DER SPKI
        const publicKeyDer = keyPair.publicKey.export({ format: 'der', type: 'spki' });
        // Decode DER and extract the raw public key bytes (BIT STRING content)
        const decodedSpki = SubjectPublicKeyInfo.decode(publicKeyDer, 'der');
        // The subjectPublicKey field is a BitString. The first byte indicates unused bits.
        // The actual public key (04 || X || Y) starts after this first byte.
        const rawPublicKeyBytes = decodedSpki.subjectPublicKey.data;
        const advBytes = rawPublicKeyBytes.subarray(1, 1 + 28); // Extract the X-coordinate (28 bytes) after the 0x04 prefix

        const privBytes = intToBytes(priv, 28);

        const privB64 = privBytes.toString('base64');
        const advB64 = advBytes.toString('base64');
        const s256B64 = sha256(advBytes).toString('base64');

        if (prefix && !s256B64.startsWith(prefix)) {
            continue;
        } else if (s256B64.substring(0, 7).includes('/')) {
            // This is a filter, not an error.
            // console.log('no key file written, there was a / in the b64 of the hashed pubkey :(');
            continue; // Skip this key
        } else {
            // No file writing here
            const { macAddress, ffPayload } = generateFindMyData(advB64);
            const keyData = {
                SN: (startFrom + generatedKeys.length).toString(),
                MAC: macAddress.replace(/:/g, ""),
                FF: ffPayload,
                hashed_adv_public_key: s256B64,
                private_key: privB64,
                public_key: advB64,
            };
            generatedKeys.push(keyData);
        }
    }

    return generatedKeys;
}

// Command-line argument parsing equivalent to Python's argparse

// Execute the main function if run directly

async function getFindMyDataFromPrivateKey(privateKeyB64) {
    try {
        const privateKeyBuffer = Buffer.from(privateKeyB64, 'base64');

        // Create an ECDH object for secp224r1
        const ecdh = crypto.createECDH('secp224r1');
        // Set the private key
        ecdh.setPrivateKey(privateKeyBuffer);

        // Get the public key in uncompressed format (04 || X || Y)
        const publicKeyUncompressedHex = ecdh.getPublicKey('hex', 'uncompressed');
        // Extract the X-coordinate (28 bytes)
        const advBytes = Buffer.from(publicKeyUncompressedHex.substring(2), 'hex').subarray(0, 28); // Skip '04' prefix, then take first 28 bytes

        const advB64 = advBytes.toString('base64');
        const s256B64 = sha256(advBytes).toString('base64');

        const { macAddress, ffPayload } = generateFindMyData(advB64);

        return {
            public_key: advB64,
            MAC: macAddress.replace(/:/g, ""),
            FF: ffPayload,
            hashed_adv_public_key: s256B64,
        };
    } catch (e) {
        console.error(`Error in getFindMyDataFromPrivateKey: ${e.message}`);
        return null;
    }
}

module.exports = { generateKeys, sha256, intToBytes, generateFindMyData, getFindMyDataFromPrivateKey };