package com.qrypteye.app.data

import android.content.Context
import android.content.SharedPreferences
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.security.KeyPair

class DataManager(private val context: Context) {
    
    companion object {
        private const val PREFS_NAME = "QRyptEyePrefs"
        private const val KEY_CONTACTS = "contacts"
        private const val KEY_USER_NAME = "user_name"
        private const val KEY_KEY_PAIR = "key_pair"
        private const val KEY_MESSAGES = "messages"
    }
    
    private val prefs: SharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val gson = Gson()
    
    // Contact management
    fun saveContacts(contacts: List<Contact>) {
        val json = gson.toJson(contacts)
        prefs.edit().putString(KEY_CONTACTS, json).apply()
    }
    
    fun loadContacts(): List<Contact> {
        val json = prefs.getString(KEY_CONTACTS, "[]")
        val type = object : TypeToken<List<Contact>>() {}.type
        return try {
            gson.fromJson(json, type) ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }
    }
    
    fun addContact(contact: Contact) {
        val contacts = loadContacts().toMutableList()
        // Check if contact already exists (by name)
        val existingIndex = contacts.indexOfFirst { it.name == contact.name }
        if (existingIndex >= 0) {
            contacts[existingIndex] = contact
        } else {
            contacts.add(contact)
        }
        saveContacts(contacts)
    }
    
    fun removeContact(contactId: String) {
        val contacts = loadContacts().toMutableList()
        contacts.removeAll { it.id == contactId }
        saveContacts(contacts)
    }
    
    fun getContactByName(name: String): Contact? {
        return loadContacts().find { it.name == name }
    }
    
    // User settings
    fun saveUserName(name: String) {
        prefs.edit().putString(KEY_USER_NAME, name).apply()
    }
    
    fun getUserName(): String {
        return prefs.getString(KEY_USER_NAME, "") ?: ""
    }
    
    // Key pair management
    fun saveKeyPair(keyPairData: KeyPairData) {
        val json = gson.toJson(keyPairData)
        prefs.edit().putString(KEY_KEY_PAIR, json).apply()
    }
    
    fun loadKeyPair(): KeyPairData? {
        val json = prefs.getString(KEY_KEY_PAIR, null)
        return try {
            if (json != null) {
                gson.fromJson(json, KeyPairData::class.java)
            } else {
                null
            }
        } catch (e: Exception) {
            null
        }
    }
    
    fun hasKeyPair(): Boolean {
        return loadKeyPair() != null
    }
    
    // Message history
    fun saveMessages(messages: List<Message>) {
        val json = gson.toJson(messages)
        prefs.edit().putString(KEY_MESSAGES, json).apply()
    }
    
    fun loadMessages(): List<Message> {
        val json = prefs.getString(KEY_MESSAGES, "[]")
        val type = object : TypeToken<List<Message>>() {}.type
        return try {
            gson.fromJson(json, type) ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }
    }
    
    fun addMessage(message: Message) {
        val messages = loadMessages().toMutableList()
        
        // Check for duplicate messages (same content, sender, recipient, and timestamp within 5 seconds)
        val isDuplicate = messages.any { existingMessage ->
            existingMessage.content == message.content &&
            existingMessage.senderName == message.senderName &&
            existingMessage.recipientName == message.recipientName &&
            existingMessage.isOutgoing == message.isOutgoing &&
            Math.abs(existingMessage.timestamp - message.timestamp) < 5000 // 5 seconds
        }
        
        if (!isDuplicate) {
            messages.add(message)
            saveMessages(messages)
        }
    }
    
    fun markMessageAsRead(messageId: String) {
        val messages = loadMessages().toMutableList()
        val messageIndex = messages.indexOfFirst { it.id == messageId }
        if (messageIndex != -1) {
            messages[messageIndex] = messages[messageIndex].copy(isRead = true)
            saveMessages(messages)
        }
    }
} 