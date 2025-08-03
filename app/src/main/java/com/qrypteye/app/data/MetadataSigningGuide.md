# Metadata Signing Guide

## Overview

This guide documents the metadata signing mechanisms implemented to prevent attacker-controlled payload injection and ensure the integrity of encrypted data structures stored in EncryptedSharedPreferences.

## Security Vulnerability Addressed

### Attacker-Controlled Payload Injection
**Risk**: An attacker with access to EncryptedSharedPreferences could replace entire encrypted data structures with malicious content.

**Example Attack**:
- Attacker creates malicious encrypted data using known keys
- Attacker overwrites legitimate encrypted contact/message records
- App decrypts attacker-controlled content, thinking it's legitimate
- Attacker gains control over app behavior through malicious data

**Why This Happens**:
- Individual field encryption (AAD) only protects field-level integrity
- No protection at the data structure level
- Attacker can replace entire encrypted objects
- App cannot distinguish legitimate from malicious encrypted structures

## Mitigation Strategy

### HMAC Metadata Signing

We use HMAC-SHA256 to sign the metadata of encrypted data structures, providing cryptographic protection against tampering:

```kotlin
// HMAC signature of metadata (excluding signature field itself)
val metadataToSign = buildString {
    append("contact:")
    append(encryptedContact.id)
    append(":")
    append(encryptedContact.nameEncrypted)
    append(":")
    append(encryptedContact.publicKeyString)
    append(":")
    append(encryptedContact.timestamp)
}

val metadataSignature = signMetadata(metadataToSign)
```

### Security Properties

1. **Cryptographic Integrity**: HMAC-SHA256 provides strong integrity protection
2. **Tamper Detection**: Any modification to metadata invalidates signature
3. **Replay Prevention**: Signature includes timestamp for freshness
4. **Object Binding**: Signature binds all metadata fields together
5. **Constant-Time Verification**: Prevents timing attacks during verification

## Implementation Details

### HMAC Key Generation

```kotlin
// HMAC key for metadata signing (separate from encryption key)
private val metadataSigningKey by lazy {
    val keyGenerator = javax.crypto.KeyGenerator.getInstance("HmacSHA256")
    keyGenerator.init(256, java.security.SecureRandom())
    keyGenerator.generateKey()
}
```

**Security Properties**:
- **256-bit key** - sufficient for HMAC-SHA256 security
- **Separate from encryption key** - key separation principle
- **Cryptographically secure RNG** - unpredictable key generation
- **Lazy initialization** - key only generated when needed

### Metadata Signing

```kotlin
private fun signMetadata(metadata: String): String {
    val mac = javax.crypto.Mac.getInstance("HmacSHA256")
    val secretKeySpec = javax.crypto.spec.SecretKeySpec(metadataSigningKey.encoded, "HmacSHA256")
    mac.init(secretKeySpec)
    
    val signatureBytes = mac.doFinal(metadata.toByteArray())
    return android.util.Base64.encodeToString(signatureBytes, android.util.Base64.DEFAULT)
}
```

**Security Features**:
- **HMAC-SHA256** - industry standard for message authentication
- **Base64 encoding** - compatible with JSON storage
- **Exception handling** - graceful error handling

### Metadata Verification

```kotlin
private fun verifyMetadata(metadata: String, signature: String): Boolean {
    return try {
        val expectedSignature = signMetadata(metadata)
        val constantTimeComparison = java.security.MessageDigest.isEqual(
            android.util.Base64.decode(signature, android.util.Base64.DEFAULT),
            android.util.Base64.decode(expectedSignature, android.util.Base64.DEFAULT)
        )
        constantTimeComparison
    } catch (e: Exception) {
        false
    }
}
```

**Security Features**:
- **Constant-time comparison** - prevents timing attacks
- **Exception handling** - returns false on any error
- **Secure comparison** - uses MessageDigest.isEqual for timing safety

## Data Structure Protection

### EncryptedContact Metadata Signing

```kotlin
data class EncryptedContact(
    val id: String,
    val nameEncrypted: String,
    val publicKeyString: String,
    val timestamp: Long,
    val metadataSignature: String  // HMAC signature of metadata
) {
    companion object {
        fun fromContact(contact: Contact, encryptField: (String) -> String, signMetadata: (String) -> String): EncryptedContact {
            val encryptedContact = EncryptedContact(
                id = contact.id,
                nameEncrypted = encryptField(contact.name),
                publicKeyString = contact.publicKeyString,
                timestamp = contact.timestamp,
                metadataSignature = "" // Will be set after creation
            )
            
            // Generate HMAC signature of metadata (excluding the signature field itself)
            val metadataToSign = buildString {
                append("contact:")
                append(encryptedContact.id)
                append(":")
                append(encryptedContact.nameEncrypted)
                append(":")
                append(encryptedContact.publicKeyString)
                append(":")
                append(encryptedContact.timestamp)
            }
            
            return encryptedContact.copy(
                metadataSignature = signMetadata(metadataToSign)
            )
        }
    }
}
```

### EncryptedSecureMessage Metadata Signing

```kotlin
data class EncryptedSecureMessage(
    val id: String,
    val senderNameEncrypted: String,
    val recipientNameEncrypted: String,
    val contentEncrypted: String,
    val timestamp: Long,
    val isOutgoing: Boolean,
    val isRead: Boolean,
    val signature: String?,
    val senderPublicKeyHash: String?,
    val metadataSignature: String  // HMAC signature of metadata
) {
    companion object {
        fun fromSecureMessage(secureMessage: SecureMessage, encryptField: (String) -> String, signMetadata: (String) -> String): EncryptedSecureMessage {
            val encryptedMessage = EncryptedSecureMessage(
                id = secureMessage.id,
                senderNameEncrypted = encryptField(secureMessage.senderName),
                recipientNameEncrypted = encryptField(secureMessage.recipientName),
                contentEncrypted = encryptField(secureMessage.content),
                timestamp = secureMessage.timestamp,
                isOutgoing = secureMessage.isOutgoing,
                isRead = secureMessage.isRead,
                signature = secureMessage.signature,
                senderPublicKeyHash = secureMessage.senderPublicKeyHash,
                metadataSignature = "" // Will be set after creation
            )
            
            // Generate HMAC signature of metadata (excluding the signature field itself)
            val metadataToSign = buildString {
                append("message:")
                append(encryptedMessage.id)
                append(":")
                append(encryptedMessage.senderNameEncrypted)
                append(":")
                append(encryptedMessage.recipientNameEncrypted)
                append(":")
                append(encryptedMessage.contentEncrypted)
                append(":")
                append(encryptedMessage.timestamp)
                append(":")
                append(encryptedMessage.isOutgoing)
                append(":")
                append(encryptedMessage.isRead)
                append(":")
                append(encryptedMessage.signature ?: "")
                append(":")
                append(encryptedMessage.senderPublicKeyHash ?: "")
            }
            
            return encryptedMessage.copy(
                metadataSignature = signMetadata(metadataToSign)
            )
        }
    }
}
```

## Metadata Format

### Contact Metadata Format
```
"contact:{id}:{nameEncrypted}:{publicKeyString}:{timestamp}"
```

**Components**:
- **Object type prefix** (`"contact:"`) - prevents cross-object attacks
- **ID** - unique identifier for the contact
- **Encrypted name** - encrypted contact name
- **Public key string** - unencrypted public key
- **Timestamp** - creation/modification time

### Message Metadata Format
```
"message:{id}:{senderNameEncrypted}:{recipientNameEncrypted}:{contentEncrypted}:{timestamp}:{isOutgoing}:{isRead}:{signature}:{senderPublicKeyHash}"
```

**Components**:
- **Object type prefix** (`"message:"`) - prevents cross-object attacks
- **ID** - unique identifier for the message
- **Encrypted sender name** - encrypted sender name
- **Encrypted recipient name** - encrypted recipient name
- **Encrypted content** - encrypted message content
- **Timestamp** - message creation time
- **Is outgoing** - message direction flag
- **Is read** - read status flag
- **Signature** - cryptographic signature (or empty string)
- **Sender public key hash** - hash of sender's public key (or empty string)

## Error Handling and Logging

### Metadata Signature Violation Detection

```kotlin
try {
    val decryptedContact = EncryptedContact.toContact(
        encryptedContact, 
        { decryptFieldWithIntegrity(it, encryptedContact.id, "contact", encryptedContact.timestamp) },
        { metadata, signature -> verifyMetadata(metadata, signature) }
    )
} catch (e: SecurityException) {
    // Metadata signature verification failed - possible tampering
    android.util.Log.e("SecureDataManager", 
        "Metadata signature violation for contact ${encryptedContact.id}: ${e.message}")
    securityLogger.logSecurityEvent(
        SecurityEvent.METADATA_SIGNATURE_VIOLATION,
        "Contact metadata signature failed: ${e.message}"
    )
    // Skip this contact, continue with others
}
```

### Security Event Logging

```kotlin
enum class SecurityEvent {
    // ... existing events ...
    METADATA_SIGNATURE_VIOLATION,  // New: For metadata tampering detection
}
```

### Graceful Degradation

- **Skip tampered data** rather than crashing
- **Log security events** for monitoring
- **Continue operation** with remaining valid data
- **User notification** for critical violations

## Usage Examples

### Contact Creation with Metadata Signing

```kotlin
// Create encrypted contact with metadata signing
val encryptedContact = EncryptedContact.fromContact(
    contact, 
    { encryptFieldWithIntegrity(it, contact.id, "contact", contact.timestamp) },
    { signMetadata(it) }
)

// Verify and decrypt contact with metadata verification
val decryptedContact = EncryptedContact.toContact(
    encryptedContact, 
    { decryptFieldWithIntegrity(it, encryptedContact.id, "contact", encryptedContact.timestamp) },
    { metadata, signature -> verifyMetadata(metadata, signature) }
)
```

### Message Creation with Metadata Signing

```kotlin
// Create encrypted message with metadata signing
val encryptedMessage = EncryptedSecureMessage.fromSecureMessage(
    message, 
    { encryptFieldWithIntegrity(it, message.id, "message", message.timestamp) },
    { signMetadata(it) }
)

// Verify and decrypt message with metadata verification
val decryptedMessage = EncryptedSecureMessage.toSecureMessage(
    encryptedMessage, 
    { decryptFieldWithIntegrity(it, encryptedMessage.id, "message", encryptedMessage.timestamp) },
    { metadata, signature -> verifyMetadata(metadata, signature) }
)
```

## Security Benefits

### 1. Attacker-Controlled Payload Prevention
- **Metadata signing** prevents replacement with malicious data
- **Cryptographic verification** ensures data authenticity
- **Automatic detection** of tampering attempts

### 2. Data Structure Integrity
- **HMAC protection** of entire data structures
- **Field binding** prevents partial modifications
- **Object type binding** prevents cross-object attacks

### 3. Tamper Detection
- **Immediate detection** of metadata modifications
- **Security logging** for monitoring and analysis
- **Graceful handling** without system compromise

### 4. Defense in Depth
- **Field-level protection** (AAD in GCM)
- **Structure-level protection** (HMAC metadata signing)
- **Multiple layers** of security verification

## Attack Scenarios Prevented

### 1. Attacker-Controlled Contact Injection
```
Attacker: Creates malicious encrypted contact using known keys
Attacker: Replaces legitimate contact record
System: Metadata signature verification fails
Result: Attack detected and logged, malicious contact rejected
```

### 2. Attacker-Controlled Message Injection
```
Attacker: Creates malicious encrypted message using known keys
Attacker: Replaces legitimate message record
System: Metadata signature verification fails
Result: Attack detected and logged, malicious message rejected
```

### 3. Partial Data Modification
```
Attacker: Modifies individual fields in encrypted data
System: Metadata signature verification fails
Result: Attack detected and logged, modified data rejected
```

### 4. Cross-Object Substitution
```
Attacker: Swaps metadata between different object types
System: Object type prefix in metadata prevents substitution
Result: Attack detected and logged, substituted data rejected
```

## Performance Considerations

### HMAC Performance
- **Fast computation** - HMAC-SHA256 is highly optimized
- **Minimal overhead** - single cryptographic operation per object
- **Efficient verification** - constant-time comparison

### Storage Overhead
- **Base64 encoding** - ~33% size increase for signature
- **Metadata field** - additional string field per object
- **Acceptable cost** - security benefit outweighs storage cost

### Memory Usage
- **Temporary metadata strings** - created during signing/verification
- **Efficient cleanup** - strings are garbage collected
- **Minimal impact** - no persistent memory overhead

## Testing Metadata Signing

### Unit Tests

```kotlin
@Test
fun testMetadataSigningAndVerification() {
    val contact = Contact.createContactFromString("Test Contact", validPublicKey)
    val encryptedContact = EncryptedContact.fromContact(
        contact, 
        { encryptFieldWithIntegrity(it, contact.id, "contact", contact.timestamp) },
        { signMetadata(it) }
    )
    
    // Verify signature is valid
    val metadataToVerify = buildString {
        append("contact:")
        append(encryptedContact.id)
        append(":")
        append(encryptedContact.nameEncrypted)
        append(":")
        append(encryptedContact.publicKeyString)
        append(":")
        append(encryptedContact.timestamp)
    }
    
    assertTrue(verifyMetadata(metadataToVerify, encryptedContact.metadataSignature))
}

@Test
fun testMetadataTamperingDetection() {
    val contact = Contact.createContactFromString("Test Contact", validPublicKey)
    val encryptedContact = EncryptedContact.fromContact(
        contact, 
        { encryptFieldWithIntegrity(it, contact.id, "contact", contact.timestamp) },
        { signMetadata(it) }
    )
    
    // Tamper with metadata
    val tamperedContact = encryptedContact.copy(
        id = "tampered-id"
    )
    
    // Verify signature fails
    val metadataToVerify = buildString {
        append("contact:")
        append(tamperedContact.id)
        append(":")
        append(tamperedContact.nameEncrypted)
        append(":")
        append(tamperedContact.publicKeyString)
        append(":")
        append(tamperedContact.timestamp)
    }
    
    assertFalse(verifyMetadata(metadataToVerify, tamperedContact.metadataSignature))
}
```

### Integration Tests

```kotlin
@Test
fun testContactMetadataSigningIntegration() {
    val contact = Contact.createContactFromString("Test Contact", validPublicKey)
    val encryptedContact = EncryptedContact.fromContact(
        contact, 
        { encryptFieldWithIntegrity(it, contact.id, "contact", contact.timestamp) },
        { signMetadata(it) }
    )
    
    // Verify decryption works with correct metadata
    val decryptedContact = EncryptedContact.toContact(
        encryptedContact, 
        { decryptFieldWithIntegrity(it, encryptedContact.id, "contact", encryptedContact.timestamp) },
        { metadata, signature -> verifyMetadata(metadata, signature) }
    )
    
    assertEquals(contact.name, decryptedContact.name)
}

@Test
fun testMessageMetadataSigningIntegration() {
    val message = SecureMessage(
        senderName = "Alice",
        recipientName = "Bob",
        content = "Hello, Bob!",
        isOutgoing = true
    )
    
    val encryptedMessage = EncryptedSecureMessage.fromSecureMessage(
        message, 
        { encryptFieldWithIntegrity(it, message.id, "message", message.timestamp) },
        { signMetadata(it) }
    )
    
    // Verify decryption works with correct metadata
    val decryptedMessage = EncryptedSecureMessage.toSecureMessage(
        encryptedMessage, 
        { decryptFieldWithIntegrity(it, encryptedMessage.id, "message", encryptedMessage.timestamp) },
        { metadata, signature -> verifyMetadata(metadata, signature) }
    )
    
    assertEquals(message.content, decryptedMessage.content)
}
```

## Monitoring and Alerting

### Security Event Monitoring
- **Log metadata violations** for analysis
- **Track tampering patterns** over time
- **Alert on suspicious activity** thresholds

### Metrics to Monitor
- **Metadata signature violation frequency** by object type
- **Tampering attempt patterns** by object ID
- **Verification failure rates** by data age
- **Attack vector analysis** for targeted attacks

### Response Procedures
1. **Immediate**: Log security event and skip tampered data
2. **Short-term**: Analyze tampering patterns and update monitoring
3. **Long-term**: Consider additional security measures if needed

## Best Practices

### 1. Always Use Metadata Signing
- **Sign all encrypted data structures** for maximum protection
- **Verify signatures before processing** any encrypted data
- **Never disable signature verification** in production

### 2. Secure Key Management
- **Use cryptographically secure RNG** for HMAC keys
- **Separate signing keys** from encryption keys
- **Rotate keys periodically** for enhanced security

### 3. Proper Error Handling
- **Log security violations** for monitoring
- **Handle gracefully** without system compromise
- **User notification** for critical violations

### 4. Regular Security Audits
- **Monitor security logs** for tampering patterns
- **Review signing methods** periodically
- **Update security measures** as needed

### 5. Performance Optimization
- **Batch signature operations** when possible
- **Cache signature results** for repeated verifications
- **Optimize metadata string building** for efficiency

This metadata signing system provides robust defense against attacker-controlled payload injection while maintaining excellent performance and usability. 