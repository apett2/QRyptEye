# QRyptEye 🔐

End-to-end encryption is great, but what if your endpoint is compromised? 

QRyptEye is an encrypted messaging app intended for installation on a secondary offline device with networking utilities (wi-fi, bluetooth, cellular) disabled. Cipher text is embedded in a QR code and sent using an online primary device. Plain text stays air-gapped as long as networking is disabled on the secondary device.   


## ⚠️ CAUTION

This application is 100% vibe-coded and designed for educational and research purposes only. While it implements industry-standard cryptographic practices, it has not undergone formal security auditing. Use in production environments is not recommended without proper security review.

## 🚀 Getting Started

### Usage

Install this app on a secondary device with all networking components disabled. 

Add a user name and generate your public key in the QRyptEye app. Public keys are dispayed as QR codes.

Exchange public keys with your contacts by scanning each other's QR codes, either in person, or by sending a photo of your public key QR code to your contact via any messaging application or channel.

After exchanging public keys, choose a contact and compose a plain text message offline in the QRyptEye app.

QRyptEye encrypts the message and creates a QR code of the cipher text. 

Take a photo of the QR code with your primary device, then send the photo to your contact via any messaging application or channel.

When receiving a message, scan the received QR code with QRyptEye on your secondary offline device. If you have exchanged public keys with the sender, QRyptEye will verify authenticity, decrypt the messsage, and display the plain text.

Note that initial exchange of public keys follows a trust-on-first-use model. Initial public key exchanges are not validated for authenticity. Exchanging public keys in-person mitigates the risk of intercepted or modified public keys during initial exchange.

After initial public key exchange, all messages are cryptographically validated for authenticity.  

## 🔒 Security Features

- **End-to-End Encryption**: RSA-2048 hybrid encryption with AES-256-GCM
- **Digital Signatures**: Cryptographic message authentication
- **Replay Protection**: Comprehensive timestamp and nonce-based replay attack prevention
- **Air-Gap Security**: Designed for secure, offline communication
- **Hardware-Backed Security**: Android Keystore integration for private key protection
- **Input Validation**: Multi-layer security validation against injection attacks
- **Metadata Signing**: Tamper-evident encrypted data structures

## 📱 Features

- **QR Code Communication**: Messages and public keys transmitted via QR codes
- **Contact Management**: Secure storage of public keys and contact information
- **Message History**: Encrypted conversation history with integrity protection
- **Key Management**: Secure key generation, storage, and rotation
- **Security Auditing**: Comprehensive logging of security events

## 🛡️ Cryptographic Implementation

- **Encryption**: RSA-2048 with OAEP padding + AES-256-GCM hybrid encryption
- **Digital Signatures**: RSA-PSS with SHA-256
- **Key Derivation**: PBKDF2 with SHA-256
- **Secure Random**: Hardware-backed random number generation
- **Key Storage**: Android Keystore with hardware security module (HSM) support

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   UI Layer      │    │  Security Layer │    │  Storage Layer  │
├─────────────────┤    ├─────────────────┤    ├─────────────────┤
│ • ScanQRActivity│    │ • CryptoManager │    │• SecureDataMgr  │
│ • ComposeActivity│    │ • ContactValidator│  │• EncryptedPrefs │
│ • ConversationsUI│    │ • ReplayProtection│  │• Android Keystore│
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🔧 Technical Details

### Security Validations
- **Input Sanitization**: XSS, SQL injection, script injection prevention
- **Content Validation**: Character encoding, length limits, format checks
- **Cryptographic Verification**: Signature validation, replay detection
- **Timestamp Validation**: Clock drift protection, freshness verification 

### Prerequisites
- Android Studio Arctic Fox or later
- Android SDK 21+ (Android 5.0+)
- Kotlin 1.8+

### Installation
Download the APK from the releases page, then transfer and install on your offline device.
Allow Installation: Go to Settings > Apps > Three dots in the top right corner > Special access > Install unknown apps. Find your file manager and toggle on Allow from this source.
Install the App: Open your file manager or downloads app, tap QRyptEye.apk, and select Install. If prompted about unknown apps, tap OK or Install anyway. Scan app for safety if prompted.
Secure Your Device After installation, go back to Settings > Apps > Three dots in the top right corner > Special access > Install unknown apps and toggle off the permission you enabled.

or

1. Clone the repository
```bash
git clone https://github.com/apett2/QRyptEye.git
cd QRyptEye
```

2. Open in Android Studio
3. Build and run on device or emulator


## 🧪 Testing

The project includes comprehensive security testing:
- **Cryptographic Tests**: Encryption/decryption validation
- **Replay Attack Tests**: Timestamp and nonce validation
- **Input Validation Tests**: Malicious content detection
- **Performance Tests**: Large message handling

## 📚 Documentation

- **Security Design**: See `/docs/security-design.md`
- **API Reference**: Generated KDoc in `/docs/api/`
- **Architecture**: See `/docs/architecture.md`

## 🤝 Contributing

This project follows secure development practices:
1. All crypto operations must be reviewed
2. Input validation is mandatory for all external data
3. Security tests required for new features
4. Code review required for all changes

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔍 Security Auditing

Security events are logged for:
- Key generation and rotation
- Message encryption/decryption
- Signature verification
- Replay attack detection
- Input validation failures

---
