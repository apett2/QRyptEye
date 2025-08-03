package com.qrypteye.app.data

import java.security.PublicKey
import java.security.SecureRandom
import java.util.*

/**
 * Immutable data class for storing contact information including public keys
 * 
 * SECURITY: This class stores public key information for contacts.
 * - Public keys are safe to share and transmit
 * - Private keys should never be stored in this class
 * - Verify public key authenticity before trusting for encryption
 * - Keys should be generated using cryptographically secure random number generators
 * 
 * ENCODING FORMAT: All publicKeyString values use Base64 URL-safe encoding without padding
 * - Consistent format for cross-platform compatibility
 * - Safe for QR codes, URLs, and storage
 * - Use encodePublicKey() to convert PublicKey objects to string format
 * - Use decodePublicKey() to convert string back to PublicKey (if needed)
 * 
 * VALIDATION REQUIREMENTS: Consumers MUST validate publicKeyString before using Contact objects
 * - Validate Base64 URL-safe encoding format
 * - Verify public key can be parsed into a valid PublicKey object
 * - Confirm the key uses expected algorithm (RSA for this application)
 * - Use validatePublicKey() method for comprehensive validation
 * 
 * IMMUTABILITY: This class is designed to be immutable
 * - All fields are val (immutable)
 * - Use copy() method for updates: contact.copy(name = "New Name")
 * - Thread-safe by design
 * - Predictable behavior in multi-threaded contexts
 */
data class Contact(
    val id: String = generateSecureId(),
    val name: String,
    val publicKeyString: String, // Must be Base64 URL-safe encoded
    val timestamp: Long = System.currentTimeMillis()
) {
    companion object {
        private val secureRandom = SecureRandom()
        
        private fun generateSecureId(): String {
            val bytes = ByteArray(16)
            secureRandom.nextBytes(bytes)
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        }
        
        /**
         * Encodes a PublicKey to Base64 URL-safe string format
         * Use this method to ensure consistent encoding across the application
         */
        fun encodePublicKey(publicKey: PublicKey): String {
            return ContactValidator.encodePublicKey(publicKey)
        }
        
        /**
         * Validates if a string is properly Base64 URL-safe encoded
         * Use this to verify publicKeyString format before creating Contact objects
         */
        fun isValidBase64UrlSafe(encodedString: String): Boolean {
            return ContactValidator.isValidBase64UrlSafe(encodedString)
        }
        
        /**
         * Comprehensive validation of public key string
         * 
         * VALIDATION CHECKS:
         * 1. Base64 URL-safe encoding format
         * 2. Valid public key structure (X.509 format)
         * 3. Expected algorithm (RSA for this application)
         * 4. Key can be successfully parsed
         * 
         * @return ValidationResult with detailed error information
         */
        fun validatePublicKey(publicKeyString: String): ValidationResult {
            return ContactValidator.validatePublicKey(publicKeyString)
        }
        
        /**
         * Decodes a Base64 URL-safe encoded public key string back to PublicKey object
         * @throws IllegalArgumentException if the string is not a valid public key
         */
        fun decodePublicKey(publicKeyString: String): PublicKey {
            return ContactValidator.decodePublicKey(publicKeyString)
        }
        
        /**
         * Creates a Contact with proper public key encoding and validation
         * This is the recommended way to create Contact objects with PublicKey objects
         * 
         * @throws IllegalArgumentException if the public key is invalid
         */
        fun createContact(name: String, publicKey: PublicKey): Contact {
            // Validate the public key before encoding
            val validation = validatePublicKey(encodePublicKey(publicKey))
            if (validation !is ValidationResult.Valid) {
                throw IllegalArgumentException("Invalid public key: ${validation.message}")
            }
            
            return Contact(
                name = name,
                publicKeyString = encodePublicKey(publicKey)
            )
        }
        
        /**
         * Creates a Contact from string with validation
         * This is the recommended way to create Contact objects from encoded strings
         * 
         * @throws IllegalArgumentException if the public key string is invalid
         */
        fun createContactFromString(name: String, publicKeyString: String): Contact {
            // Validate the public key string
            val validation = validatePublicKey(publicKeyString)
            if (validation !is ValidationResult.Valid) {
                throw IllegalArgumentException("Invalid public key: ${validation.message}")
            }
            
            return Contact(
                name = name,
                publicKeyString = publicKeyString
            )
        }
    }
    
    /**
     * IMMUTABLE UPDATE METHODS
     * 
     * These methods provide safe, immutable updates using copy-on-update pattern.
     * They validate inputs and return new Contact instances rather than modifying existing ones.
     */
    
    /**
     * Updates the contact name with validation
     * 
     * @param newName The new name for the contact
     * @return New Contact instance with updated name
     * @throws IllegalArgumentException if the new name is invalid
     */
    fun updateName(newName: String): Contact {
        if (newName.isBlank()) {
            throw IllegalArgumentException("Contact name cannot be blank")
        }
        if (newName.length > 100) {
            throw IllegalArgumentException("Contact name is too long (max 100 characters)")
        }
        return copy(name = newName, timestamp = System.currentTimeMillis())
    }
    
    /**
     * Updates the public key with validation
     * 
     * @param newPublicKeyString The new public key string
     * @return New Contact instance with updated public key
     * @throws IllegalArgumentException if the new public key is invalid
     */
    fun updatePublicKey(newPublicKeyString: String): Contact {
        val validation = validatePublicKey(newPublicKeyString)
        if (validation !is ValidationResult.Valid) {
            throw IllegalArgumentException("Invalid public key: ${validation.message}")
        }
        return copy(publicKeyString = newPublicKeyString, timestamp = System.currentTimeMillis())
    }
    
    /**
     * Updates the public key from a PublicKey object with validation
     * 
     * @param newPublicKey The new PublicKey object
     * @return New Contact instance with updated public key
     * @throws IllegalArgumentException if the new public key is invalid
     */
    fun updatePublicKey(newPublicKey: PublicKey): Contact {
        return updatePublicKey(encodePublicKey(newPublicKey))
    }
    
    /**
     * Refreshes the timestamp to current time
     * 
     * @return New Contact instance with updated timestamp
     */
    fun refreshTimestamp(): Contact {
        return copy(timestamp = System.currentTimeMillis())
    }
    
    /**
     * Creates a copy with a new ID (useful for creating new contacts from existing ones)
     * 
     * @return New Contact instance with a new ID
     */
    fun withNewId(): Contact {
        return copy(id = generateSecureId(), timestamp = System.currentTimeMillis())
    }
    
    /**
     * UTILITY METHODS
     */
    
    /**
     * Gets the decoded PublicKey object
     * 
     * @return PublicKey object
     * @throws IllegalArgumentException if the public key string is invalid
     */
    fun getPublicKey(): PublicKey {
        return decodePublicKey(publicKeyString)
    }
    
    /**
     * Checks if this contact is valid
     * 
     * @return true if the contact is valid, false otherwise
     */
    fun isValid(): Boolean {
        return validatePublicKey(publicKeyString) is ValidationResult.Valid
    }
    
    /**
     * Gets validation result for this contact
     * 
     * @return ValidationResult with detailed validation information
     */
    fun getValidationResult(): ValidationResult {
        return validatePublicKey(publicKeyString)
    }
    
    /**
     * Sealed class for validation results with detailed error information
     */
    sealed class ValidationResult {
        data class Valid(val publicKey: PublicKey) : ValidationResult()
        data class InvalidFormat(val errorMessage: String) : ValidationResult()
        data class InvalidAlgorithm(val errorMessage: String) : ValidationResult()
        data class InvalidKeySize(val errorMessage: String) : ValidationResult()
        
        val isValid: Boolean get() = this is Valid
        val message: String get() = when (this) {
            is Valid -> "Valid public key"
            is InvalidFormat -> errorMessage
            is InvalidAlgorithm -> errorMessage
            is InvalidKeySize -> errorMessage
        }
    }
} 