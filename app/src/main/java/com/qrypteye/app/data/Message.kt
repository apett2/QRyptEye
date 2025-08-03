package com.qrypteye.app.data

data class Message(
    val id: String = java.util.UUID.randomUUID().toString(),
    val senderName: String,
    val recipientName: String,
    val content: String,
    val timestamp: Long = System.currentTimeMillis(),
    val isOutgoing: Boolean = false,
    val isRead: Boolean = false
) 