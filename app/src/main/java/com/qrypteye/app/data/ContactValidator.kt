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
     * 5. Security strength validation
     * 6. Malicious content detection
     * 
     * @return ValidationResult with detailed error information
     */
    fun validatePublicKey(publicKeyString: String): Contact.ValidationResult {
        // 1. Input sanitization
        val sanitizedKey = publicKeyString.trim()
        
        // 2. Length validation
        if (sanitizedKey.length < 100 || sanitizedKey.length > 10000) {
            return Contact.ValidationResult.InvalidFormat("Public key length is invalid (${sanitizedKey.length} characters)")
        }
        
        // 3. Malicious content detection
        val suspiciousPatterns = listOf(
            Regex("script", RegexOption.IGNORE_CASE),
            Regex("javascript:", RegexOption.IGNORE_CASE),
            Regex("data:", RegexOption.IGNORE_CASE),
            Regex("vbscript:", RegexOption.IGNORE_CASE),
            Regex("on\\w+\\s*=", RegexOption.IGNORE_CASE),
            Regex("<\\w+[^>]*>", RegexOption.IGNORE_CASE), // HTML tags
            Regex("\\b(union|select|insert|update|delete|drop|create|alter)\\b", RegexOption.IGNORE_CASE), // SQL keywords
            Regex("\\b(password|secret|key|token)\\b", RegexOption.IGNORE_CASE) // Suspicious keywords
        )
        
        if (suspiciousPatterns.any { it.containsMatchIn(sanitizedKey) }) {
            return Contact.ValidationResult.InvalidFormat("Public key contains suspicious content")
        }
        
        // 4. Base64 URL-safe encoding
        if (!isValidBase64UrlSafe(sanitizedKey)) {
            return Contact.ValidationResult.InvalidFormat("Public key is not valid Base64 URL-safe encoded")
        }
        
        // 5. Parse as PublicKey
        val publicKey = try {
            decodePublicKey(sanitizedKey)
        } catch (e: Exception) {
            return Contact.ValidationResult.InvalidFormat("Failed to parse public key: ${e.message}")
        }
        
        // 6. Verify algorithm
        if (publicKey.algorithm != EXPECTED_ALGORITHM) {
            return Contact.ValidationResult.InvalidAlgorithm(
                "Expected algorithm: $EXPECTED_ALGORITHM, got: ${publicKey.algorithm}"
            )
        }
        
        // 7. Verify key size (RSA should be at least 2048 bits)
        val keySizeBits = publicKey.encoded.size * 8
        if (publicKey.algorithm == "RSA" && keySizeBits < 2048) {
            return Contact.ValidationResult.InvalidKeySize("RSA key size ($keySizeBits bits) is below minimum security requirement (2048 bits)")
        }
        
        // 8. Key strength validation
        if (keySizeBits < 3072) {
            android.util.Log.w("ContactValidator", "RSA key size ($keySizeBits bits) is below recommended security requirement (3072 bits)")
        }
        
        // 9. Additional security checks
        val securityValidation = validatePublicKeySecurity(publicKey)
        if (securityValidation !is SecurityValidationResult.Secure) {
            return Contact.ValidationResult.InvalidKeySize("Public key security validation failed: ${securityValidation.message}")
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
        // Validate name with enhanced security checks
        val nameValidation = validateContactName(contact.name)
        if (nameValidation !is ContactNameValidationResult.Valid) {
            return Contact.ValidationResult.InvalidFormat("Contact name validation failed: ${nameValidation.message}")
        }
        
        // Validate public key using core validation
        return validatePublicKey(contact.publicKeyString)
    }
    
    /**
     * Enhanced contact name validation with security checks
     * 
     * @param name The contact name to validate
     * @return ContactNameValidationResult with validation details
     */
    fun validateContactName(name: String): ContactNameValidationResult {
        // 1. Basic validation
        if (name.isBlank()) {
            return ContactNameValidationResult.Invalid("Contact name cannot be blank")
        }
        
        if (name.length > 100) {
            return ContactNameValidationResult.Invalid("Contact name is too long (max 100 characters)")
        }
        
        if (name.length < 2) {
            return ContactNameValidationResult.Invalid("Contact name is too short (min 2 characters)")
        }
        
        // 2. Character set validation (prevent injection attacks)
        val allowedChars = Regex("^[a-zA-Z0-9\\s\\-_.'()]+$")
        if (!allowedChars.matches(name)) {
            return ContactNameValidationResult.Invalid("Contact name contains invalid characters")
        }
        
        // 3. Malicious content detection
        val suspiciousPatterns = listOf(
            Regex("script", RegexOption.IGNORE_CASE),
            Regex("javascript:", RegexOption.IGNORE_CASE),
            Regex("data:", RegexOption.IGNORE_CASE),
            Regex("vbscript:", RegexOption.IGNORE_CASE),
            Regex("on\\w+\\s*=", RegexOption.IGNORE_CASE), // onload=, onclick=, etc.
            Regex("<\\w+[^>]*>", RegexOption.IGNORE_CASE), // HTML tags
            Regex("\\b(union|select|insert|update|delete|drop|create|alter)\\b", RegexOption.IGNORE_CASE), // SQL keywords
            Regex("\\b(admin|root|system|test|demo)\\b", RegexOption.IGNORE_CASE) // Suspicious names
        )
        
        if (suspiciousPatterns.any { it.containsMatchIn(name) }) {
            return ContactNameValidationResult.Suspicious("Contact name contains suspicious patterns")
        }
        
        // 4. Normalization
        val normalizedName = name.trim().replace(Regex("\\s+"), " ")
        
        // 5. Final validation
        if (normalizedName.length < 2) {
            return ContactNameValidationResult.Invalid("Contact name is too short after normalization")
        }
        
        return ContactNameValidationResult.Valid(normalizedName)
    }
    
    /**
     * Sealed class for contact name validation results
     */
    sealed class ContactNameValidationResult {
        data class Valid(val normalizedName: String) : ContactNameValidationResult()
        data class Invalid(val reason: String) : ContactNameValidationResult()
        data class Suspicious(val reason: String) : ContactNameValidationResult()
        
        val message: String get() = when (this) {
            is Valid -> "Valid contact name"
            is Invalid -> reason
            is Suspicious -> reason
        }
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

    /**
     * Validate message content for security and safety
     * 
     * @param content The message content to validate
     * @param maxLength Maximum allowed length
     * @return MessageContentValidationResult with validation details
     */
    fun validateMessageContent(content: String, maxLength: Int = 1000): MessageContentValidationResult {
        // 1. Basic validation (allow single character messages)
        if (content.isEmpty()) {
            return MessageContentValidationResult.Invalid("Message content cannot be empty")
        }
        
        if (content.length > maxLength) {
            return MessageContentValidationResult.Invalid("Message is too long (max $maxLength characters)")
        }
        
        // 2. Character encoding validation
        if (!content.all { it.code in 32..126 || it.code in 160..255 || it.code in 0x2000..0x206F }) {
            return MessageContentValidationResult.Invalid("Message contains unsupported characters")
        }
        
        // 3. Malicious content detection
        val suspiciousPatterns = listOf(
            Regex("script", RegexOption.IGNORE_CASE),
            Regex("javascript:", RegexOption.IGNORE_CASE),
            Regex("data:", RegexOption.IGNORE_CASE),
            Regex("vbscript:", RegexOption.IGNORE_CASE),
            Regex("on\\w+\\s*=", RegexOption.IGNORE_CASE), // onload=, onclick=, etc.
            Regex("<\\w+[^>]*>", RegexOption.IGNORE_CASE), // HTML tags
            Regex("\\b(union|select|insert|update|delete|drop|create|alter)\\b", RegexOption.IGNORE_CASE), // SQL keywords
            Regex("\\b(password|secret|key|token|admin|root)\\b", RegexOption.IGNORE_CASE), // Sensitive keywords
            Regex("\\b(exec|eval|system|shell|cmd)\\b", RegexOption.IGNORE_CASE), // Command execution
            Regex("\\b(alert|confirm|prompt)\\b", RegexOption.IGNORE_CASE), // JavaScript functions
            Regex("\\b(document|window|location)\\b", RegexOption.IGNORE_CASE), // Browser objects
            Regex("\\b(\\$\\{|\\$\\(|\\$\\))\\b", RegexOption.IGNORE_CASE), // Template injection
            Regex("\\b(\\{\\{|\\}\\})\\b", RegexOption.IGNORE_CASE), // Template injection
            Regex("\\b(\\$\\w+)\\b", RegexOption.IGNORE_CASE), // Variable injection
            Regex("\\b(\\w+\\s*=\\s*['\"][^'\"]*['\"])", RegexOption.IGNORE_CASE) // Assignment patterns
        )
        
        if (suspiciousPatterns.any { it.containsMatchIn(content) }) {
            return MessageContentValidationResult.Suspicious("Message contains suspicious patterns")
        }
        
        // 4. Content normalization
        val normalizedContent = content.trim().replace(Regex("\\s+"), " ")
        
        // 5. Final validation (allow single character after normalization)
        if (normalizedContent.isEmpty()) {
            return MessageContentValidationResult.Invalid("Message content is empty after normalization")
        }
        
        return MessageContentValidationResult.Valid(normalizedContent)
    }
    
    /**
     * Sealed class for message content validation results
     */
    sealed class MessageContentValidationResult {
        data class Valid(val normalizedContent: String) : MessageContentValidationResult()
        data class Invalid(val reason: String) : MessageContentValidationResult()
        data class Suspicious(val reason: String) : MessageContentValidationResult()
        
        val message: String get() = when (this) {
            is Valid -> "Valid message content"
            is Invalid -> reason
            is Suspicious -> reason
        }
    }

    /**
     * Validate timestamp for security and freshness
     * 
     * @param timestamp The timestamp to validate
     * @param context Description of the timestamp context (e.g., "message", "public key")
     * @return TimestampValidationResult with validation details
     */
    fun validateTimestamp(timestamp: Long, context: String = "data"): TimestampValidationResult {
        val currentTime = System.currentTimeMillis()
        val maxAge = 24 * 60 * 60 * 1000L // 24 hours
        val maxFuture = 5 * 60 * 1000L // 5 minutes for clock skew
        val minAge = 0L // No minimum age requirement
        
        // 1. Basic range validation
        if (timestamp < minAge) {
            return TimestampValidationResult.Invalid("$context timestamp is negative")
        }
        
        if (timestamp > currentTime + maxFuture) {
            return TimestampValidationResult.Invalid("$context timestamp is too far in the future")
        }
        
        if (currentTime - timestamp > maxAge) {
            return TimestampValidationResult.TooOld("$context is too old (${(currentTime - timestamp) / (60 * 1000)} minutes)")
        }
        
        // 2. Clock drift detection
        val clockDrift = Math.abs(timestamp - currentTime)
        if (clockDrift > maxFuture) {
            android.util.Log.w("ContactValidator", "Large clock drift detected: ${clockDrift / 1000} seconds")
        }
        
        return TimestampValidationResult.Valid(timestamp)
    }
    
    /**
     * Sealed class for timestamp validation results
     */
    sealed class TimestampValidationResult {
        data class Valid(val timestamp: Long) : TimestampValidationResult()
        data class Invalid(val reason: String) : TimestampValidationResult()
        data class TooOld(val reason: String) : TimestampValidationResult()
        
        val message: String get() = when (this) {
            is Valid -> "Valid timestamp"
            is Invalid -> reason
            is TooOld -> reason
        }
    }
} 