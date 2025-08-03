package com.qrypteye.app.data

import java.security.PublicKey
import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import java.util.*

/**
 * Utility class for comprehensive Contact and public key validation
 * 
 * This class provides additional validation methods beyond the basic Contact validation
 * to ensure security and compatibility across the application.
 * 
 * SECURITY: All validation methods are designed to prevent:
 * - Invalid key formats that could cause crashes
 * - Weak cryptographic algorithms
 * - Insecure key sizes
 * - Malformed data that could lead to security vulnerabilities
 */
object ContactValidator {
    
    // Minimum key sizes for security
    private const val MIN_RSA_KEY_SIZE_BYTES = 256 // 2048 bits
    private const val MIN_EC_KEY_SIZE_BYTES = 32   // 256 bits
    
    // Supported algorithms for this application
    private val SUPPORTED_ALGORITHMS = setOf("RSA", "EC")
    
    // Expected algorithm for this application
    private const val EXPECTED_ALGORITHM = "RSA"
    
    /**
     * Core validation of public key string
     * 
     * VALIDATION CHECKS:
     * 1. Base64 URL-safe encoding format
     * 2. Valid public key structure (X.509 format)
     * 3. Expected algorithm (RSA for this application)
     * 4. Key can be successfully parsed
     * 
     * @return ValidationResult with detailed error information
     */
    fun validatePublicKey(publicKeyString: String): Contact.ValidationResult {
        // Check 1: Base64 URL-safe encoding
        if (!isValidBase64UrlSafe(publicKeyString)) {
            return Contact.ValidationResult.InvalidFormat("Public key is not valid Base64 URL-safe encoded")
        }
        
        // Check 2: Parse as PublicKey
        val publicKey = try {
            decodePublicKey(publicKeyString)
        } catch (e: Exception) {
            return Contact.ValidationResult.InvalidFormat("Failed to parse public key: ${e.message}")
        }
        
        // Check 3: Verify algorithm
        if (publicKey.algorithm != EXPECTED_ALGORITHM) {
            return Contact.ValidationResult.InvalidAlgorithm(
                "Expected algorithm: $EXPECTED_ALGORITHM, got: ${publicKey.algorithm}"
            )
        }
        
        // Check 4: Verify key size (RSA should be at least 2048 bits)
        if (publicKey.algorithm == "RSA" && publicKey.encoded.size < 256) {
            return Contact.ValidationResult.InvalidKeySize("RSA key size appears to be less than 2048 bits")
        }
        
        return Contact.ValidationResult.Valid(publicKey)
    }
    
    /**
     * Validates if a string is properly Base64 URL-safe encoded
     */
    fun isValidBase64UrlSafe(encodedString: String): Boolean {
        return try {
            android.util.Base64.decode(encodedString, android.util.Base64.URL_SAFE)
            true
        } catch (e: IllegalArgumentException) {
            false
        }
    }
    
    /**
     * Decodes a Base64 URL-safe encoded public key string back to PublicKey object
     * @throws IllegalArgumentException if the string is not a valid public key
     */
    fun decodePublicKey(publicKeyString: String): PublicKey {
        val keyBytes = android.util.Base64.decode(publicKeyString, android.util.Base64.URL_SAFE)
        val keySpec = X509EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance(EXPECTED_ALGORITHM)
        return keyFactory.generatePublic(keySpec)
    }
    
    /**
     * Encodes a PublicKey to Base64 URL-safe string format
     */
    fun encodePublicKey(publicKey: java.security.PublicKey): String {
        return android.util.Base64.encodeToString(publicKey.encoded, android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING)
    }
    
    /**
     * Comprehensive validation of a Contact object
     * 
     * @param contact The Contact object to validate
     * @return ValidationResult with detailed information
     */
    fun validateContact(contact: Contact): Contact.ValidationResult {
        // Validate name
        if (contact.name.isBlank()) {
            return Contact.ValidationResult.InvalidFormat("Contact name cannot be blank")
        }
        
        if (contact.name.length > 100) {
            return Contact.ValidationResult.InvalidFormat("Contact name is too long (max 100 characters)")
        }
        
        // Validate public key using core validation
        return validatePublicKey(contact.publicKeyString)
    }
    
    /**
     * Validates public key algorithm and size for security requirements
     * 
     * @param publicKey The PublicKey to validate
     * @return ValidationResult with security assessment
     */
    fun validatePublicKeySecurity(publicKey: PublicKey): SecurityValidationResult {
        // Check algorithm support
        if (!SUPPORTED_ALGORITHMS.contains(publicKey.algorithm)) {
            return SecurityValidationResult.UnsupportedAlgorithm(
                "Algorithm '${publicKey.algorithm}' is not supported. Supported: ${SUPPORTED_ALGORITHMS.joinToString()}"
            )
        }
        
        // Check key size based on algorithm
        val keySizeBytes = publicKey.encoded.size
        when (publicKey.algorithm) {
            "RSA" -> {
                if (keySizeBytes < MIN_RSA_KEY_SIZE_BYTES) {
                    return SecurityValidationResult.WeakKeySize(
                        "RSA key size (${keySizeBytes * 8} bits) is below minimum security requirement (2048 bits)"
                    )
                }
            }
            "EC" -> {
                if (keySizeBytes < MIN_EC_KEY_SIZE_BYTES) {
                    return SecurityValidationResult.WeakKeySize(
                        "EC key size (${keySizeBytes * 8} bits) is below minimum security requirement (256 bits)"
                    )
                }
            }
        }
        
        return SecurityValidationResult.Secure(publicKey)
    }
    
    /**
     * Validates a list of contacts and returns validation results for each
     * 
     * @param contacts List of contacts to validate
     * @return Map of contact ID to validation result
     */
    fun validateContacts(contacts: List<Contact>): Map<String, Contact.ValidationResult> {
        return contacts.associate { contact ->
            contact.id to validateContact(contact)
        }
    }
    
    /**
     * Filters a list of contacts to only include valid ones
     * 
     * @param contacts List of contacts to filter
     * @return List of only valid contacts
     */
    fun filterValidContacts(contacts: List<Contact>): List<Contact> {
        return contacts.filter { contact ->
            validateContact(contact) is Contact.ValidationResult.Valid
        }
    }
    
    /**
     * Attempts to repair a potentially malformed public key string
     * 
     * @param publicKeyString The potentially malformed public key string
     * @return RepairResult with either the repaired key or error information
     */
    fun attemptKeyRepair(publicKeyString: String): RepairResult {
        // Try different encoding formats
        val encodings = listOf(
            "URL-safe Base64" to { s: String -> s },
            "Standard Base64" to { s: String -> 
                s.replace('-', '+').replace('_', '/') + "=".repeat((4 - s.length % 4) % 4)
            },
            "URL-safe Base64 with padding" to { s: String -> 
                s + "=".repeat((4 - s.length % 4) % 4)
            }
        )
        
        for ((encodingName, transform) in encodings) {
            try {
                val transformed = transform(publicKeyString)
                val validation = validatePublicKey(transformed)
                if (validation is Contact.ValidationResult.Valid) {
                    return RepairResult.Repaired(transformed, encodingName)
                }
            } catch (e: Exception) {
                // Continue to next encoding attempt
            }
        }
        
        return RepairResult.Unrepairable("Could not repair public key string with any known encoding format")
    }
    
    /**
     * Sealed class for security validation results
     */
    sealed class SecurityValidationResult {
        data class Secure(val publicKey: PublicKey) : SecurityValidationResult()
        data class UnsupportedAlgorithm(val errorMessage: String) : SecurityValidationResult()
        data class WeakKeySize(val errorMessage: String) : SecurityValidationResult()
        
        val isSecure: Boolean get() = this is Secure
        val message: String get() = when (this) {
            is Secure -> "Public key meets security requirements"
            is UnsupportedAlgorithm -> errorMessage
            is WeakKeySize -> errorMessage
        }
    }
    
    /**
     * Sealed class for key repair results
     */
    sealed class RepairResult {
        data class Repaired(val repairedKey: String, val encodingUsed: String) : RepairResult()
        data class Unrepairable(val errorMessage: String) : RepairResult()
        
        val wasRepaired: Boolean get() = this is Repaired
        val message: String get() = when (this) {
            is Repaired -> "Key repaired using $encodingUsed encoding"
            is Unrepairable -> errorMessage
        }
    }
} 