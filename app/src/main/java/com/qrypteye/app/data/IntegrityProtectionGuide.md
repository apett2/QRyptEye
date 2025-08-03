# Integrity Protection Guide

## Overview

This guide documents the integrity protection mechanisms implemented to prevent replay and substitution attacks on encrypted data stored in EncryptedSharedPreferences.

## Security Vulnerabilities Addressed

### 1. Replay Attacks
**Risk**: An attacker with access to EncryptedSharedPreferences could replay old encrypted data blobs.

**Example Attack**:
- Attacker copies an old encrypted message blob
- Replaces current message with old encrypted data
- App decrypts old message, thinking it's current

### 2. Substitution Attacks
**Risk**: An attacker could swap encrypted data between different objects.

**Example Attack**:
- Attacker swaps encrypted content between two messages
- App decrypts message A's content for message B
- Data integrity is compromised

## Mitigation Strategy

### Additional Authenticated Data (AAD) in GCM

We use GCM (Galois/Counter Mode) with Additional Authenticated Data to bind encrypted content to object metadata:

```kotlin
// AAD format: "objectType:objectId:timestamp"
val aad = "$objectType:$objectId:$timestamp".toByteArray()
cipher.updateAAD(aad)
```

### AAD Components

1. **Object Type** (`"contact"`, `"message"`, `"user"`)
   - Prevents cross-object substitution attacks
   - Ensures encrypted data belongs to correct object type

2. **Object ID** (cryptographically secure UUID)
   - Prevents substitution between objects of same type
   - Ensures encrypted data belongs to specific object

3. **Timestamp** (creation/modification time)
   - Prevents replay attacks with old data
   - Ensures data freshness

## Implementation Details

### Encryption with Integrity Protection

```kotlin
private fun encryptFieldWithIntegrity(
    data: String, 
    objectId: String, 
    objectType: String, 
    timestamp: Long
): String {
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, fieldEncryptionKey)
    
    // Create AAD to bind encrypted content to object metadata
    val aad = "$objectType:$objectId:$timestamp".toByteArray()
    cipher.updateAAD(aad)
    
    val encryptedBytes = cipher.doFinal(data.toByteArray())
    val iv = cipher.iv
    
    // Combine IV and encrypted data
    val combined = iv + encryptedBytes
    return Base64.encodeToString(combined, Base64.DEFAULT)
}
```

### Decryption with Integrity Verification

```kotlin
private fun decryptFieldWithIntegrity(
    encryptedData: String, 
    objectId: String, 
    objectType: String, 
    timestamp: Long
): String {
    val combined = Base64.decode(encryptedData, Base64.DEFAULT)
    val iv = combined.copyOfRange(0, 12) // 96-bit IV for GCM
    val encryptedBytes = combined.copyOfRange(12, combined.size)
    
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val ivSpec = GCMParameterSpec(128, iv)
    cipher.init(Cipher.DECRYPT_MODE, fieldEncryptionKey, ivSpec)
    
    // Verify AAD matches expected object metadata
    val expectedAad = "$objectType:$objectId:$timestamp".toByteArray()
    cipher.updateAAD(expectedAad)
    
    try {
        val decryptedBytes = cipher.doFinal(encryptedBytes)
        return String(decryptedBytes)
    } catch (e: AEADBadTagException) {
        // AAD verification failed - possible replay or substitution attack
        throw IllegalArgumentException("Integrity check failed: possible replay or substitution attack", e)
    }
}
```

## Secure ID Generation

### Requirements
- **Cryptographically secure** random generation
- **Unpredictable** to prevent targeted attacks
- **Unique** across all objects
- **Sufficient entropy** (128+ bits)

### Implementation

```kotlin
private fun generateSecureId(): String {
    val bytes = ByteArray(16) // 128 bits
    secureRandom.nextBytes(bytes)
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
}
```

### Security Properties
- **128-bit entropy** - sufficient for cryptographic security
- **URL-safe encoding** - compatible with storage systems
- **No padding** - consistent length
- **SecureRandom** - cryptographically secure RNG

## Error Handling and Logging

### Integrity Violation Detection

```kotlin
try {
    val decryptedData = decryptFieldWithIntegrity(encryptedData, objectId, objectType, timestamp)
    // Use decrypted data
} catch (e: IllegalArgumentException) {
    // Integrity check failed - possible replay or substitution attack
    android.util.Log.e("SecureDataManager", 
        "Data integrity violation for $objectType $objectId: ${e.message}")
    securityLogger.logSecurityEvent(
        SecurityEvent.DATA_INTEGRITY_VIOLATION,
        "$objectType integrity check failed: ${e.message}"
    )
    // Handle gracefully - skip corrupted data
}
```

### Security Event Logging

```kotlin
enum class SecurityEvent {
    // ... existing events ...
    DATA_INTEGRITY_VIOLATION,  // New: For replay/substitution attack detection
}
```

### Graceful Degradation

- **Skip corrupted data** rather than crashing
- **Log security events** for monitoring
- **Continue operation** with remaining valid data
- **User notification** for critical violations

## Usage Examples

### Contact Encryption

```kotlin
// Encrypt contact name with integrity protection
val encryptedName = encryptFieldWithIntegrity(
    contact.name, 
    contact.id, 
    "contact", 
    contact.timestamp
)

// Decrypt with integrity verification
val decryptedName = decryptFieldWithIntegrity(
    encryptedName, 
    contact.id, 
    "contact", 
    contact.timestamp
)
```

### Message Encryption

```kotlin
// Encrypt message content with integrity protection
val encryptedContent = encryptFieldWithIntegrity(
    message.content, 
    message.id, 
    "message", 
    message.timestamp
)

// Decrypt with integrity verification
val decryptedContent = decryptFieldWithIntegrity(
    encryptedContent, 
    message.id, 
    "message", 
    message.timestamp
)
```

## Security Benefits

### 1. Replay Attack Prevention
- **Timestamp binding** prevents old data replay
- **AAD verification** ensures data freshness
- **Automatic detection** of replay attempts

### 2. Substitution Attack Prevention
- **Object ID binding** prevents data swapping
- **Object type binding** prevents cross-type substitution
- **AAD verification** ensures data belongs to correct object

### 3. Data Integrity Assurance
- **GCM authentication** ensures data hasn't been tampered
- **AAD verification** ensures metadata integrity
- **Cryptographic guarantees** of data authenticity

### 4. Attack Detection
- **Immediate detection** of integrity violations
- **Security logging** for monitoring and analysis
- **Graceful handling** without system compromise

## Migration Strategy

### Backward Compatibility
- **Legacy encryption methods** marked as deprecated
- **Automatic migration** to new methods for new data
- **Gradual transition** without breaking existing data

### Legacy Data Handling
```kotlin
@Deprecated("Use encryptFieldWithIntegrity() for better security")
private fun encryptField(data: String): String {
    // Legacy implementation without AAD
}

@Deprecated("Use decryptFieldWithIntegrity() for better security")
private fun decryptField(encryptedData: String): String {
    // Legacy implementation without AAD verification
}
```

## Testing Integrity Protection

### Unit Tests

```kotlin
@Test
fun testReplayAttackPrevention() {
    val originalData = "sensitive data"
    val objectId = "test-id"
    val objectType = "test"
    val timestamp = System.currentTimeMillis()
    
    // Encrypt with current timestamp
    val encrypted = encryptFieldWithIntegrity(originalData, objectId, objectType, timestamp)
    
    // Try to decrypt with old timestamp (should fail)
    assertThrows(IllegalArgumentException::class.java) {
        decryptFieldWithIntegrity(encrypted, objectId, objectType, timestamp - 1000)
    }
}

@Test
fun testSubstitutionAttackPrevention() {
    val data1 = "data1"
    val data2 = "data2"
    val id1 = "id1"
    val id2 = "id2"
    val objectType = "test"
    val timestamp = System.currentTimeMillis()
    
    // Encrypt two different objects
    val encrypted1 = encryptFieldWithIntegrity(data1, id1, objectType, timestamp)
    val encrypted2 = encryptFieldWithIntegrity(data2, id2, objectType, timestamp)
    
    // Try to decrypt data1 with id2 (should fail)
    assertThrows(IllegalArgumentException::class.java) {
        decryptFieldWithIntegrity(encrypted1, id2, objectType, timestamp)
    }
}
```

### Integration Tests

```kotlin
@Test
fun testContactIntegrityProtection() {
    val contact = Contact.createContactFromString("Test Contact", validPublicKey)
    val encryptedContact = EncryptedContact.fromContact(contact) { 
        encryptFieldWithIntegrity(it, contact.id, "contact", contact.timestamp) 
    }
    
    // Verify decryption works with correct metadata
    val decryptedContact = EncryptedContact.toContact(encryptedContact) { 
        decryptFieldWithIntegrity(it, encryptedContact.id, "contact", encryptedContact.timestamp) 
    }
    
    assertEquals(contact.name, decryptedContact.name)
}
```

## Monitoring and Alerting

### Security Event Monitoring
- **Log integrity violations** for analysis
- **Track attack patterns** over time
- **Alert on suspicious activity** thresholds

### Metrics to Monitor
- **Integrity violation frequency** by object type
- **Replay attack attempts** over time
- **Substitution attack attempts** by object ID
- **Decryption failure rates** by data age

### Response Procedures
1. **Immediate**: Log security event and skip corrupted data
2. **Short-term**: Analyze attack patterns and update monitoring
3. **Long-term**: Consider additional security measures if needed

## Best Practices

### 1. Always Use Integrity Protection
- **Use new encryption methods** for all new data
- **Migrate existing data** when possible
- **Never disable integrity checks** in production

### 2. Secure ID Generation
- **Use cryptographically secure RNG** for all IDs
- **Ensure sufficient entropy** (128+ bits)
- **Never reuse IDs** across objects

### 3. Proper Error Handling
- **Log security violations** for monitoring
- **Handle gracefully** without system compromise
- **User notification** for critical violations

### 4. Regular Security Audits
- **Monitor security logs** for attack patterns
- **Review encryption methods** periodically
- **Update security measures** as needed

This integrity protection system provides robust defense against replay and substitution attacks while maintaining excellent performance and usability. 