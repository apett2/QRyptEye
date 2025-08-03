package com.qrypteye.app.data

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPair
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import android.util.Base64

/**
 * SECURE KEY MANAGER
 * 
 * This class provides secure key management using Android Keystore:
 * 1. Generates RSA key pairs within Android Keystore
 * 2. Stores only public keys and key aliases (never private keys)
 * 3. Uses hardware-backed security when available
 * 4. Prevents key extraction and serialization
 * 
 * SECURITY FEATURES:
 * - Private keys never leave Android Keystore
 * - Hardware-backed security on supported devices
 * - No serialization of private keys
 * - Key aliases for secure reference
 * - Protection against key extraction attacks
 */
class SecureKeyManager(private val context: Context) {
    
    companion object {
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val KEY_ALIAS_PREFIX = "qrypteye_key_"
        private const val KEY_ALGORITHM = KeyProperties.KEY_ALGORITHM_RSA // RSA for hybrid encryption
        private const val KEY_SIZE = 2048 // RSA key size
        private const val KEY_PURPOSES = KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        private const val DIGEST_ALGORITHMS = KeyProperties.DIGEST_SHA256
        private const val ENCRYPTION_PADDINGS = KeyProperties.ENCRYPTION_PADDING_RSA_OAEP
        private const val SIGNATURE_PADDINGS = KeyProperties.SIGNATURE_PADDING_RSA_PKCS1
    }
    
    private val masterKey by lazy {
        MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .setUserAuthenticationRequired(false)
            .build()
    }
    
    private val securePrefs by lazy {
        EncryptedSharedPreferences.create(
            context,
            "QRyptEyeKeyPrefs",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }
    
    private val keyStore by lazy {
        KeyStore.getInstance(KEYSTORE_PROVIDER).apply {
            load(null)
        }
    }
    
    /**
     * Generate a new RSA key pair within Android Keystore
     * 
     * SECURITY: This method generates keys within Android Keystore,
     * ensuring private keys never leave the secure hardware environment.
     * 
     * @return KeyPairInfo containing public key and key alias
     */
    fun generateKeyPair(): KeyPairInfo {
        try {
            val keyAlias = generateKeyAlias()
            
            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                keyAlias,
                KEY_PURPOSES
            ).apply {
                setKeySize(KEY_SIZE)
                setDigests(DIGEST_ALGORITHMS)
                setEncryptionPaddings(ENCRYPTION_PADDINGS)
                setSignaturePaddings(SIGNATURE_PADDINGS)
                setUserAuthenticationRequired(false)
                // Note: setUserAuthenticationValidityDurationSeconds is deprecated
                // and not needed when setUserAuthenticationRequired is false
            }.build()
            
            val keyPairGenerator = java.security.KeyPairGenerator.getInstance(
                KEY_ALGORITHM,
                KEYSTORE_PROVIDER
            )
            keyPairGenerator.initialize(keyGenParameterSpec)
            val keyPair = keyPairGenerator.generateKeyPair()
            
            // Store only the public key and alias
            // SECURITY: Uses URL_SAFE and NO_WRAP flags to prevent newline artifacts
            val publicKeyString = Base64.encodeToString(keyPair.public.encoded, Base64.URL_SAFE or Base64.NO_WRAP)
            val keyInfo = KeyPairInfo(
                keyAlias = keyAlias,
                publicKeyString = publicKeyString,
                timestamp = System.currentTimeMillis()
            )
            
            // Save key info to encrypted preferences
            saveKeyPairInfo(keyInfo)
            
            return keyInfo
            
        } catch (e: Exception) {
            throw SecurityException("Failed to generate secure key pair", e)
        }
    }
    
    /**
     * Load a key pair from Android Keystore using the stored alias
     * 
     * SECURITY: This method retrieves keys from Android Keystore
     * without ever exposing the private key in memory.
     * 
     * @return KeyPair if found, null otherwise
     */
    fun loadKeyPair(): KeyPair? {
        return try {
            val keyInfo = loadKeyPairInfo() ?: return null
            
            if (!keyStore.containsAlias(keyInfo.keyAlias)) {
                return null
            }
            
            val privateKey = keyStore.getKey(keyInfo.keyAlias, null) as? PrivateKey
            val publicKey = keyStore.getCertificate(keyInfo.keyAlias)?.publicKey
            
            if (privateKey != null && publicKey != null) {
                KeyPair(publicKey, privateKey)
            } else {
                null
            }
            
        } catch (e: Exception) {
            null
        }
    }
    
    /**
     * Check if a key pair exists
     */
    fun hasKeyPair(): Boolean {
        return try {
            val keyInfo = loadKeyPairInfo()
            keyInfo != null && keyStore.containsAlias(keyInfo.keyAlias)
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Delete the key pair from Android Keystore
     * 
     * SECURITY: This method permanently removes the key from
     * Android Keystore, making it unrecoverable.
     */
    fun deleteKeyPair() {
        try {
            val keyInfo = loadKeyPairInfo()
            if (keyInfo != null && keyStore.containsAlias(keyInfo.keyAlias)) {
                keyStore.deleteEntry(keyInfo.keyAlias)
            }
            
            // Clear key info from encrypted preferences
            securePrefs.edit().remove("key_pair_info").apply()
            
        } catch (e: Exception) {
            throw SecurityException("Failed to delete key pair", e)
        }
    }
    
    /**
     * Get the public key string for export/sharing
     */
    fun getPublicKeyString(): String? {
        return try {
            loadKeyPairInfo()?.publicKeyString
        } catch (e: Exception) {
            null
        }
    }
    
    /**
     * Generate a unique key alias
     */
    private fun generateKeyAlias(): String {
        val timestamp = System.currentTimeMillis()
        val random = java.security.SecureRandom()
        val randomBytes = ByteArray(8)
        random.nextBytes(randomBytes)
        val randomString = Base64.encodeToString(randomBytes, Base64.URL_SAFE or Base64.NO_PADDING)
        return "${KEY_ALIAS_PREFIX}${timestamp}_${randomString}"
    }
    
    /**
     * Save key pair info to encrypted preferences
     */
    private fun saveKeyPairInfo(keyInfo: KeyPairInfo) {
        val json = com.google.gson.Gson().toJson(keyInfo)
        securePrefs.edit().putString("key_pair_info", json).apply()
    }
    
    /**
     * Load key pair info from encrypted preferences
     */
    private fun loadKeyPairInfo(): KeyPairInfo? {
        val json = securePrefs.getString("key_pair_info", null)
        return try {
            if (json != null) {
                com.google.gson.Gson().fromJson(json, KeyPairInfo::class.java)
            } else {
                null
            }
        } catch (e: Exception) {
            null
        }
    }
    
    /**
     * Data class for storing key pair information (no private keys)
     * 
     * SECURITY: This class only stores public keys and key aliases.
     * Private keys are never serialized or stored in this class.
     */
    data class KeyPairInfo(
        val keyAlias: String,
        val publicKeyString: String,
        val timestamp: Long
    )
} 