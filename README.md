# QRyptEye 🔐

A secure, end-to-end encrypted messaging application for Android that uses QR codes for message transmission. Built with enterprise-grade security features and cryptographic best practices.

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

### Message Flow
1. **Compose**: User types message → Content validation → Encryption
2. **QR Generation**: Signed encrypted message → QR code display
3. **Scanning**: QR code scan → Content validation → Signature verification
4. **Decryption**: Signature validation → Message decryption → Display

### Security Validations
- **Input Sanitization**: XSS, SQL injection, script injection prevention
- **Content Validation**: Character encoding, length limits, format checks
- **Cryptographic Verification**: Signature validation, replay detection
- **Timestamp Validation**: Clock drift protection, freshness verification

## 🚀 Getting Started

### Prerequisites
- Android Studio Arctic Fox or later
- Android SDK 21+ (Android 5.0+)
- Kotlin 1.8+

### Installation
1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/QRyptEye.git
cd QRyptEye
```

2. Open in Android Studio
3. Build and run on device or emulator

### Usage
1. **Generate Keys**: First launch generates RSA key pair
2. **Share Public Key**: Generate QR code containing your public key
3. **Import Contacts**: Scan others' public key QR codes
4. **Send Messages**: Compose → Encrypt → Generate QR → Share
5. **Receive Messages**: Scan QR → Verify → Decrypt → Display

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

## ⚠️ Security Notice

This application is designed for educational and research purposes. While it implements industry-standard cryptographic practices, it has not undergone formal security auditing. Use in production environments is not recommended without proper security review.

## 🔍 Security Auditing

Security events are logged for:
- Key generation and rotation
- Message encryption/decryption
- Signature verification
- Replay attack detection
- Input validation failures

## 📞 Contact

For security-related issues, please contact [security@example.com](mailto:security@example.com)

---

**Built with ❤️ and 🔒 by [Your Name]**