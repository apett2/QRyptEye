# QRyptEye 🔐

End-to-end encryption is great, but what if your endpoint is compromised? QRyptEye is an encrypted messaging app intended for installation on a fully offline device. Encryption and decryption occur offline, with cipher text transmitted to an online device via QR codes.

## ⚠️ CAUTION

This application is 100% vibe-coded and designed for educational and research purposes only. While it implements industry-standard cryptographic practices, it has not undergone formal security auditing. Use in production environments is not recommended without proper security review.

To any cryptography, optical data transfer, or Android security experts: please play, test, refine, and improve. Maybe there is a foundation here for something cool.   

## 🚀 Getting Started

### Usage

Plain text messages are composed in the QRyptEye app, installed on an offline device. The QRyptEye app encrypts the message and displays a QR code of the cipher text. The user then takes a photo of the QR code with their primary online device and sends that photo to their contact via the channel of their choice (email, text, social media, etc.). The recipient receives the photo of the QR code on their online device, then scans the QR code using QRyptEye installed on their offline device. The message is decrypted and plain text is displayed in the QRytEye app on the recipient's offline device. 

In order to exchange messages, contacts must first exchange public keys. This can be done in the same fashion as messages, with photos of QR codes being sent via traditional channels, or it can be done in person for increased security. Initial public key exchange follows a trust-on-first-use model, meaning initial public key exchanges are not validated for authenticity. Exchanging public keys in-person mitigates the risk of intercepted or modified public keys during initial exchange.

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
