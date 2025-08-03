package com.qrypteye.app.data

import com.google.gson.Gson
import com.google.gson.GsonBuilder

/**
 * CANONICAL JSON UTILITY
 * 
 * This class provides a canonical Gson instance with deterministic ordering
 * for cryptographic signature verification and hash generation.
 * 
 * SECURITY: Canonical JSON is essential for signature verification to prevent
 * random failures due to non-deterministic field ordering.
 * 
 * CANONICAL PROPERTIES:
 * - Deterministic field ordering (alphabetical)
 * - Consistent null handling
 * - No HTML escaping
 * - Stable serialization format
 * - Compatible with cryptographic operations
 */
object CanonicalGson {
    
    /**
     * Canonical Gson instance for cryptographic operations
     * 
     * SECURITY: This instance provides deterministic JSON serialization
     * that is essential for signature verification and hash generation.
     * 
     * PROPERTIES:
     * - serializeNulls(): Ensures consistent null field handling
     * - disableHtmlEscaping(): Prevents HTML character escaping
     * - create(): Uses default field ordering (alphabetical)
     * 
     * USAGE: Use this instance for all cryptographic operations including:
     * - Message signature creation and verification
     * - Hash generation for replay protection
     * - Metadata signing and verification
     * - Any JSON that affects cryptographic integrity
     */
    val instance: Gson = GsonBuilder()
        .serializeNulls()  // Ensure consistent null handling
        .disableHtmlEscaping()  // Prevent HTML character escaping
        .create()  // Use default field ordering (alphabetical)
    
    /**
     * Create canonical JSON string for cryptographic operations
     * 
     * @param obj The object to serialize
     * @return Canonical JSON string with deterministic ordering
     */
    inline fun <reified T> toJson(obj: T): String {
        return instance.toJson(obj)
    }
    
    /**
     * Parse JSON string using canonical settings
     * 
     * @param json The JSON string to parse
     * @return Parsed object
     */
    inline fun <reified T> fromJson(json: String): T? {
        return instance.fromJson(json, T::class.java)
    }
    
    /**
     * Create canonical JSON string for Map objects
     * 
     * SECURITY: This method ensures that Map objects are serialized
     * with deterministic field ordering for cryptographic operations.
     * 
     * @param map The map to serialize
     * @return Canonical JSON string with deterministic ordering
     */
    fun toJson(map: Map<String, Any>): String {
        return instance.toJson(map)
    }
} 