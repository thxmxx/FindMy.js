# FindMy.js

A JavaScript package for interacting with Apple's FindMy service, inspired by the Python project [`biemster/FindMy`](https://github.com/biemster/FindMy). This project provides functionalities for iCloud authentication, key generation, and fetching/decrypting device location reports. It enables programmatic access and management of FindMy features, offering insights into device tracking and security.

## Features

- **iCloud Authentication**: Securely authenticate with Apple's iCloud using the SRP protocol and handle Two-Factor Authentication (2FA) via SMS or trusted devices.
- **Key Generation**: Generate private and public keys compatible with the FindMy network.
- **Location Reporting**: Fetch and decrypt device location data from the FindMy network.
- **Anisette Support**: Integrates with an Anisette server for device attestation, crucial for successful iCloud interactions.

## Installation

To get started with FindMy.js, ensure you have Node.js and npm installed on your system.

1. **Clone the repository**:

   ```bash
   git clone https://github.com/thxmxx/FindMy.js.git
   cd FindMy.js
   ```

2. **Install dependencies**:

   ```bash
   npm install
   ```

3. **Anisette Server**: This project requires an Anisette server to function correctly. You can set up your own using a project like [`Dadoum/anisette-v3-server`](https://github.com/Dadoum/anisette-v3-server) or similar. Ensure the server is running and accessible at the configured `ANISETTE_URL` (default: `http://localhost:6969`).

## Usage

Before running, ensure your Apple ID has SMS 2FA properly set up.

### Authenticating with iCloud

The `pypush_gsa_icloud.js` script handles the authentication process:

```javascript
const { icloudLoginMobileme } = require('./src/pypush_gsa_icloud');

async function authenticate() {
    try {
        const authData = await icloudLoginMobileme(); // Will prompt for Apple ID and password
        console.log('Authentication successful:', authData);
    } catch (error) {
        console.error('Authentication failed:', error.message);
    }
}

authenticate();
```

### Requesting FindMy Reports

The `request_reports.js` script allows you to fetch location reports using a private key:

```javascript
const { requestReports } = require('./src/request_reports');

async function getReports() {
    // Replace 'YOUR_PRIVATE_KEY_BASE64' with your actual base64 encoded private key
    const privateKey = 'YOUR_PRIVATE_KEY_BASE64'; 
    try {
        const reports = await requestReports(privateKey, 24); // Last 24 hours
        console.log('Received reports:', reports);
    } catch (error) {
        console.error('Failed to fetch reports:', error.message);
    }
}

getReports();
```

### Generating Keys

The `generate_keys.js` script can be used to generate new FindMy compatible keys:

```javascript
const { generateKeys } = require('./src/generate_keys');

async function generateNewKeys() {
    try {
        const newKeys = await generateKeys(1); // Generate 1 key pair
        console.log('Generated Keys:', newKeys);
    } catch (error) {
        console.error('Failed to generate keys:', error.message);
    }
}

generateNewKeys();
```

## Contributing

Contributions are welcome! Please feel free to open issues or submit pull requests.

## License

This project is licensed under the ISC License. See the `LICENSE` file for details.