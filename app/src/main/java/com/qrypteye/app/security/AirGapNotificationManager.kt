package com.qrypteye.app.security

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import com.qrypteye.app.R
import com.qrypteye.app.ui.ConversationsActivity

class AirGapNotificationManager(private val context: Context) {
    
    companion object {
        private const val CHANNEL_ID = "air_gap_security"
        private const val NOTIFICATION_ID = 1001
    }
    
    private val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
    
    init {
        createNotificationChannel()
    }
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Security Warnings",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows security warnings when device is not air-gapped"
                setShowBadge(false)
            }
            notificationManager.createNotificationChannel(channel)
        }
    }
    
    fun showAirGapWarning(enabledFeatures: List<String>) {
        val intent = Intent(context, ConversationsActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            context,
            0,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_security)
            .setContentTitle("Security Warning")
            .setContentText("Device is not air-gapped. ${enabledFeatures.joinToString(", ")} enabled.")
            .setStyle(NotificationCompat.BigTextStyle()
                .bigText("Your device is not air-gapped. Turn off WiFi, Bluetooth, and Mobile Data for full security protection."))
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .setAutoCancel(false)
            .setContentIntent(pendingIntent)
            .build()
        
        notificationManager.notify(NOTIFICATION_ID, notification)
    }
    
    fun hideAirGapWarning() {
        notificationManager.cancel(NOTIFICATION_ID)
    }
} 