# Contact Validation Guide

## Overview

This guide explains the validation requirements for Contact objects and public keys in the QRyptEye application. Proper validation is critical for security and preventing crashes.

## Architecture

### Single Source of Truth
- **ContactValidator** contains all core validation logic
- **Contact** class delegates validation to ContactValidator
- **No duplicate validation code** - prevents maintenance drift
- **Centralized validation rules** - easy to update and maintain

### Validation Flow
```
Contact.validatePublicKey() → ContactValidator.validatePublicKey()
Contact.isValid() → ContactValidator.validatePublicKey()
Contact.getValidationResult() → ContactValidator.validatePublicKey()
```

## Validation Requirements

### 1. Public Key Format Validation

All public keys must be:
- **Base64 URL-safe encoded** (no padding)
- **Valid X.509 format** 
- **RSA algorithm** (primary) or EC (elliptic curve)
- **Minimum key sizes**: RSA 2048 bits, EC 256 bits

### 2. Contact Object Validation

Contact objects must have:
- **Non-blank name** (max 100 characters)
- **Valid public key string** (see above)
- **Valid timestamp** (within reasonable bounds)

## Usage Examples

### Creating Contacts with Validation

```kotlin
// ✅ RECOMMENDED: Use factory methods with built-in validation
val contact = Contact.createContactFromString("Alice", publicKeyString)

// ✅ RECOMMENDED: Create from PublicKey object
val contact = Contact.createContact("Bob", publicKeyObject)

// ❌ AVOID: Direct constructor without validation
val contact = Contact(name = "Charlie", publicKeyString = rawString)
```

### Updating Contacts (Immutable Pattern)

```kotlin
// ✅ RECOMMENDED: Use update methods with validation
val updatedContact = contact.updateName("Alice Smith")
val contactWithNewKey = contact.updatePublicKey(newPublicKeyString)

// ✅ RECOMMENDED: Chain updates
val fullyUpdatedContact = contact
    .updateName("Alice Smith")
    .updatePublicKey(newPublicKeyString)
    .refreshTimestamp()

// ✅ RECOMMENDED: Use copy() for simple updates
val contactWithNewTimestamp = contact.copy(timestamp = System.currentTimeMillis())
```

### Validating Existing Contacts

```kotlin
// Basic validation (delegates to ContactValidator)
val validation = Contact.validatePublicKey(publicKeyString)
if (validation is Contact.ValidationResult.Valid) {
    // Contact is valid
} else {
    // Handle validation error
    println("Validation failed: ${validation.message}")
}

// Comprehensive validation
val contactValidation = ContactValidator.validateContact(contact)
val securityValidation = ContactValidator.validatePublicKeySecurity(publicKey)

// Instance validation (delegates to ContactValidator)
if (contact.isValid()) {
    // Contact is valid
} else {
    val validationResult = contact.getValidationResult()
    println("Invalid contact: ${validationResult.message}")
}
```

### Handling Invalid Keys

```kotlin
// Attempt key repair for malformed keys
val repairResult = ContactValidator.attemptKeyRepair(malformedKey)
if (repairResult is ContactValidator.RepairResult.Repaired) {
    val repairedContact = Contact.createContactFromString(name, repairResult.repairedKey)
} else {
    // Handle unrepairable key
    showError("Invalid key format: ${repairResult.message}")
}
```

## Validation Points

### 1. QR Code Scanning (ScanQRActivity)

**Location**: `app/src/main/java/com/qrypteye/app/ui/ScanQRActivity.kt`

**Validation**: 
- Validate public key format before creating Contact
- Attempt key repair if initial validation fails
- Show user-friendly error messages

```kotlin
val contact = try {
    Contact.createContactFromString(name, publicKeyString) // Delegates to ContactValidator
} catch (e: IllegalArgumentException) {
    // Attempt repair or show error
}
```

### 2. Storage Operations (SecureDataManager)

**Location**: `app/src/main/java/com/qrypteye/app/data/SecureDataManager.kt`

**Validation**:
- Validate contacts before storing
- Prevent invalid data from being persisted

```kotlin
fun addContact(contact: Contact) {
    val validation = Contact.validatePublicKey(contact.publicKeyString) // Delegates to ContactValidator
    if (validation !is Contact.ValidationResult.Valid) {
        throw IllegalArgumentException("Invalid public key")
    }
    // Store contact
}
```

### 3. Encrypted Storage (EncryptedDataClasses)

**Location**: `app/src/main/java/com/qrypteye/app/data/EncryptedDataClasses.kt`

**Validation**:
- Validate public keys when decrypting from storage
- Ensure data integrity after decryption

```kotlin
fun toContact(encryptedContact: EncryptedContact, decryptField: (String) -> String): Contact {
    val validation = Contact.validatePublicKey(encryptedContact.publicKeyString) // Delegates to ContactValidator
    if (validation !is Contact.ValidationResult.Valid) {
        throw IllegalArgumentException("Invalid public key in storage")
    }
    // Create contact
}
```

## Security Considerations

### 1. Algorithm Validation

- **Primary**: RSA (2048+ bits)
- **Secondary**: EC (256+ bits)
- **Reject**: Weak algorithms (MD5, SHA1, etc.)

### 2. Key Size Requirements

- **RSA**: Minimum 2048 bits (256 bytes)
- **EC**: Minimum 256 bits (32 bytes)
- **Reject**: Smaller keys as insecure

### 3. Format Validation

- **Encoding**: Base64 URL-safe (no padding)
- **Structure**: X.509 public key format
- **Reject**: Malformed or corrupted keys

## Error Handling

### Validation Result Types

```kotlin
sealed class ValidationResult {
    data class Valid(val publicKey: PublicKey) : ValidationResult()
    data class InvalidFormat(val errorMessage: String) : ValidationResult()
    data class InvalidAlgorithm(val errorMessage: String) : ValidationResult()
    data class InvalidKeySize(val errorMessage: String) : ValidationResult()
}
```

### Common Error Messages

- `"Public key is not valid Base64 URL-safe encoded"`
- `"Failed to parse public key: Invalid key format"`
- `"Expected algorithm: RSA, got: DSA"`
- `"RSA key size appears to be less than 2048 bits"`

## Immutability Best Practices

### Thread Safety

```kotlin
// ✅ SAFE: Multiple threads can read the same Contact object
val contact = Contact.createContactFromString("Alice", publicKeyString)

// Thread 1
thread {
    val name = contact.name // Safe
    val key = contact.getPublicKey() // Safe
}

// Thread 2
thread {
    val updatedContact = contact.updateName("Alice Smith") // Safe - creates new object
}
```

### Update Patterns

```kotlin
// ✅ RECOMMENDED: Use update methods
val updatedContact = contact.updateName("New Name")

// ✅ RECOMMENDED: Chain operations
val updatedContact = contact
    .updateName("Alice Smith")
    .updatePublicKey(newKey)
    .refreshTimestamp()

// ❌ AVOID: Direct field modification (won't compile)
// contact.name = "New Name" // Compilation error - val fields are immutable
```

## Testing Validation

### Unit Tests

```kotlin
@Test
fun testValidPublicKey() {
    val validation = Contact.validatePublicKey(validKeyString) // Delegates to ContactValidator
    assertTrue(validation is Contact.ValidationResult.Valid)
}

@Test
fun testInvalidPublicKey() {
    val validation = Contact.validatePublicKey(invalidKeyString) // Delegates to ContactValidator
    assertTrue(validation is Contact.ValidationResult.InvalidFormat)
}

@Test
fun testContactImmutability() {
    val originalContact = Contact.createContactFromString("Alice", publicKeyString)
    val updatedContact = originalContact.updateName("Alice Smith")
    
    // Original should remain unchanged
    assertEquals("Alice", originalContact.name)
    
    // Updated should have new name
    assertEquals("Alice Smith", updatedContact.name)
    
    // Should be different objects
    assertNotSame(originalContact, updatedContact)
}
```

### Integration Tests

```kotlin
@Test
fun testContactCreationWithValidation() {
    val contact = Contact.createContactFromString("Test", validKeyString)
    assertNotNull(contact)
    assertEquals("Test", contact.name)
    assertTrue(contact.isValid()) // Delegates to ContactValidator
}
```

## Best Practices

1. **Always validate** public keys before using them
2. **Use factory methods** instead of direct constructors
3. **Use update methods** for changes (immutable pattern)
4. **Handle validation errors** gracefully with user feedback
5. **Attempt key repair** when possible for better UX
6. **Log validation failures** for debugging
7. **Test validation** thoroughly with various key formats
8. **Use immutable collections** when possible
9. **Chain operations** for multiple updates
10. **Handle thread safety** through immutability
11. **Use ContactValidator directly** for advanced validation needs
12. **Keep validation logic centralized** in ContactValidator

## Migration Guide

### For Existing Code

If you have existing code that creates Contact objects directly:

```kotlin
// OLD CODE
val contact = Contact(name = "Alice", publicKeyString = keyString)

// NEW CODE
val contact = Contact.createContactFromString("Alice", keyString)
```

### For Contact Updates

If you need to update contact information:

```kotlin
// OLD PATTERN (if it existed)
contact.name = "New Name" // This won't compile anymore

// NEW PATTERN
val updatedContact = contact.updateName("New Name")
// Update your references to use updatedContact
```

### For Data Migration

If you have existing stored contacts that may be invalid:

```kotlin
val contacts = loadContacts()
val validContacts = ContactValidator.filterValidContacts(contacts)
val invalidContacts = contacts.filter { contact ->
    ContactValidator.validateContact(contact) !is Contact.ValidationResult.Valid
}

// Handle invalid contacts (log, remove, or attempt repair)
```

## Troubleshooting

### Common Issues

1. **"Invalid key format"**: Check Base64 URL-safe encoding
2. **"Wrong algorithm"**: Ensure RSA or EC keys only
3. **"Key too small"**: Verify minimum key sizes
4. **"Parse failed"**: Check X.509 format compliance
5. **"Contact name cannot be blank"**: Provide non-empty name
6. **"Contact name is too long"**: Keep names under 100 characters

### Debug Tools

```kotlin
// Check key encoding
val isValidEncoding = Contact.isValidBase64UrlSafe(keyString) // Delegates to ContactValidator

// Check key algorithm
val publicKey = Contact.decodePublicKey(keyString) // Delegates to ContactValidator
println("Algorithm: ${publicKey.algorithm}")
println("Key size: ${publicKey.encoded.size * 8} bits")

// Check contact validity
if (contact.isValid()) { // Delegates to ContactValidator
    println("Contact is valid")
} else {
    println("Contact validation failed: ${contact.getValidationResult().message}")
}
```

## Related Documentation

- [Contact Immutability Guide](ContactImmutabilityGuide.md) - Detailed guide on immutable patterns
- [ContactValidator](ContactValidator.kt) - **Single source of truth for all validation logic**
- [EncryptedDataClasses](EncryptedDataClasses.kt) - Storage and encryption patterns

## Architecture Benefits

### 1. Single Source of Truth
- **All validation logic** is in ContactValidator
- **No duplicate code** to maintain
- **Consistent validation** across the application

### 2. Easy Maintenance
- **Update validation rules** in one place
- **Add new validation checks** without touching Contact class
- **Test validation logic** independently

### 3. Clear Separation of Concerns
- **Contact**: Data storage and immutable operations
- **ContactValidator**: All validation logic
- **UI Components**: Use Contact methods that delegate to ContactValidator 