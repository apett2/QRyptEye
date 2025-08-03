package com.qrypteye.app.data

import java.security.PublicKey

data class Contact(
    val id: String = java.util.UUID.randomUUID().toString(),
    val name: String,
    val publicKeyString: String,
    val publicKey: PublicKey? = null,
    val timestamp: Long = System.currentTimeMillis()
) {
    companion object {
        fun create(name: String, publicKey: PublicKey): Contact {
            return Contact(
                name = name,
                publicKeyString = com.qrypteye.app.crypto.CryptoManager().exportPublicKey(publicKey),
                publicKey = publicKey
            )
        }
    }
} 