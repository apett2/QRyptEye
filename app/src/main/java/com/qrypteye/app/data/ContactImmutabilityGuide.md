# Contact Immutability Guide

## Overview

The Contact class is designed as an immutable data class following Kotlin best practices. This guide explains how to properly use the immutable Contact class and the benefits of this approach.

## Immutability Benefits

### 1. Thread Safety
- **No shared mutable state** - Multiple threads can safely read Contact objects
- **No synchronization needed** - Immutable objects are inherently thread-safe
- **Predictable behavior** - No race conditions or data corruption

### 2. Predictable State
- **No unexpected changes** - Contact objects cannot be modified after creation
- **Clear data flow** - All changes create new objects, making data flow explicit
- **Easier debugging** - State changes are explicit and traceable

### 3. Functional Programming
- **Pure functions** - Update methods return new objects without side effects
- **Composability** - Easy to chain operations: `contact.updateName("Alice").updatePublicKey(newKey)`
- **Referential transparency** - Same inputs always produce same outputs

## Usage Patterns

### Creating Contacts

```kotlin
// ✅ RECOMMENDED: Use factory methods
val contact = Contact.createContactFromString("Alice", publicKeyString)
val contact2 = Contact.createContact("Bob", publicKeyObject)

// ✅ RECOMMENDED: Direct constructor (if you have validated data)
val contact3 = Contact(name = "Charlie", publicKeyString = validatedKeyString)
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

### ❌ AVOID: Mutable Patterns

```kotlin
// ❌ DON'T: Try to modify fields directly (won't compile)
contact.name = "New Name" // Compilation error - val fields are immutable

// ❌ DON'T: Create mutable copies
var mutableContact = contact // This is fine, but don't modify the original
mutableContact = mutableContact.copy(name = "New Name") // This is correct

// ❌ DON'T: Use mutable collections to store contacts
val mutableContacts = mutableListOf<Contact>() // Use immutable lists when possible
```

## Update Methods

### 1. Name Updates

```kotlin
// Update name with validation
val updatedContact = contact.updateName("New Name")

// Validation errors
try {
    contact.updateName("") // Throws: "Contact name cannot be blank"
} catch (e: IllegalArgumentException) {
    // Handle validation error
}

try {
    contact.updateName("A".repeat(101)) // Throws: "Contact name is too long"
} catch (e: IllegalArgumentException) {
    // Handle validation error
}
```

### 2. Public Key Updates

```kotlin
// Update with string (validates automatically)
val updatedContact = contact.updatePublicKey(newPublicKeyString)

// Update with PublicKey object
val updatedContact = contact.updatePublicKey(publicKeyObject)

// Validation errors
try {
    contact.updatePublicKey("invalid-key") // Throws validation error
} catch (e: IllegalArgumentException) {
    // Handle validation error
}
```

### 3. Timestamp Updates

```kotlin
// Refresh timestamp to current time
val updatedContact = contact.refreshTimestamp()

// Or use copy for specific timestamp
val updatedContact = contact.copy(timestamp = specificTimestamp)
```

### 4. ID Updates

```kotlin
// Create new contact with new ID (useful for duplicating contacts)
val newContact = contact.withNewId()
```

## Thread Safety Examples

### Multi-threaded Reading

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
    val isValid = contact.isValid() // Safe
    val validation = contact.getValidationResult() // Safe
}
```

### Updating in Multi-threaded Context

```kotlin
// ✅ SAFE: Each thread gets its own updated copy
val originalContact = Contact.createContactFromString("Alice", publicKeyString)

// Thread 1
thread {
    val updatedContact = originalContact.updateName("Alice Smith")
    // Thread 1 has its own copy, doesn't affect other threads
}

// Thread 2
thread {
    val updatedContact = originalContact.updateName("Alice Johnson")
    // Thread 2 has its own copy, doesn't affect other threads
}
```

## Collections and Immutability

### Immutable Lists

```kotlin
// ✅ RECOMMENDED: Use immutable lists
val contacts: List<Contact> = listOf(
    Contact.createContactFromString("Alice", key1),
    Contact.createContactFromString("Bob", key2)
)

// ✅ SAFE: Create new list with updated contact
val updatedContacts = contacts.map { contact ->
    if (contact.name == "Alice") {
        contact.updateName("Alice Smith")
    } else {
        contact
    }
}
```

### Mutable Collections (when needed)

```kotlin
// ✅ SAFE: Use mutable collections carefully
val mutableContacts = mutableListOf<Contact>()

// Add contacts
mutableContacts.add(Contact.createContactFromString("Alice", key1))

// Update specific contact
val index = mutableContacts.indexOfFirst { it.name == "Alice" }
if (index != -1) {
    val updatedContact = mutableContacts[index].updateName("Alice Smith")
    mutableContacts[index] = updatedContact // Replace with new instance
}
```

## Performance Considerations

### Memory Usage

```kotlin
// Immutable objects may use more memory, but provide safety
val contact1 = Contact.createContactFromString("Alice", key1)
val contact2 = contact1.updateName("Alice Smith") // New object created

// For large-scale updates, consider batching
val contacts = largeContactList.map { contact ->
    contact.refreshTimestamp() // Creates new objects
}
```

### Optimization Strategies

```kotlin
// ✅ EFFICIENT: Batch updates
val updatedContacts = contacts.map { contact ->
    contact.copy(timestamp = System.currentTimeMillis()) // Single copy operation
}

// ✅ EFFICIENT: Conditional updates
val updatedContacts = contacts.map { contact ->
    if (contact.name == "Alice") {
        contact.updateName("Alice Smith")
    } else {
        contact // No unnecessary copy
    }
}
```

## Best Practices Summary

### 1. Always Use Factory Methods
```kotlin
// ✅ Good
val contact = Contact.createContactFromString("Alice", publicKeyString)

// ❌ Avoid (unless you have validated data)
val contact = Contact(name = "Alice", publicKeyString = rawString)
```

### 2. Use Update Methods for Changes
```kotlin
// ✅ Good
val updatedContact = contact.updateName("New Name")

// ❌ Avoid direct field access for updates
// contact.name = "New Name" // Won't compile, and that's good!
```

### 3. Chain Operations When Possible
```kotlin
// ✅ Good
val updatedContact = contact
    .updateName("Alice Smith")
    .updatePublicKey(newKey)
    .refreshTimestamp()
```

### 4. Handle Validation Errors
```kotlin
// ✅ Good
try {
    val updatedContact = contact.updatePublicKey(newKeyString)
    // Use updatedContact
} catch (e: IllegalArgumentException) {
    // Handle validation error
    showError("Invalid public key: ${e.message}")
}
```

### 5. Use Immutable Collections
```kotlin
// ✅ Good
val contacts: List<Contact> = listOf(contact1, contact2)

// ❌ Avoid unless you need mutability
val contacts = mutableListOf<Contact>()
```

## Migration from Mutable Patterns

If you have existing code that tries to modify Contact objects:

```kotlin
// OLD PATTERN (if it existed)
contact.name = "New Name" // This won't compile anymore

// NEW PATTERN
val updatedContact = contact.updateName("New Name")
// Update your references to use updatedContact
```

## Testing Immutable Objects

```kotlin
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

This immutable design ensures that Contact objects are thread-safe, predictable, and follow functional programming principles while maintaining excellent performance and usability. 