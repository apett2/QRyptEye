package com.qrypteye.app.security

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.bluetooth.BluetoothAdapter
import android.content.Intent
import android.provider.Settings
import android.telephony.TelephonyManager

class AirGapChecker(private val context: Context) {
    
    data class AirGapStatus(
        val isAirGapped: Boolean,
        val message: String,
        val enabledFeatures: List<String>
    )
    
    fun checkAirGapStatus(): AirGapStatus {
        val enabledFeatures = mutableListOf<String>()
        
        // Check WiFi
        val wifiManager = context.getSystemService(Context.WIFI_SERVICE) as WifiManager
        if (wifiManager.isWifiEnabled) {
            enabledFeatures.add("WiFi")
        }
        
        // Check Bluetooth
        val bluetoothAdapter = BluetoothAdapter.getDefaultAdapter()
        if (bluetoothAdapter != null && bluetoothAdapter.isEnabled) {
            enabledFeatures.add("Bluetooth")
        }
        
        // Check Mobile Data
        val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = connectivityManager.activeNetwork
        val capabilities = connectivityManager.getNetworkCapabilities(network)
        
        val hasMobileData = capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true
        if (hasMobileData) {
            enabledFeatures.add("Mobile Data")
        }
        
        // Check if device is air-gapped
        val isAirGapped = enabledFeatures.isEmpty()
        
        val message = if (isAirGapped) {
            "✅ WiFi, Bluetooth, and Mobile Data are OFF\n\nYour device is air-gapped and ready for secure communication."
        } else {
            buildString {
                append("⚠️ Your device is NOT air-gapped\n\n")
                append("The following features are enabled:\n")
                enabledFeatures.forEach { feature ->
                    append("• $feature\n")
                }
                append("\nRecommendation: Turn off these features to make the most of QRyptEye security features. Keep these turned off at all times for full protection.")
            }
        }
        
        return AirGapStatus(
            isAirGapped = isAirGapped,
            message = message,
            enabledFeatures = enabledFeatures
        )
    }
    
    fun openWifiSettings() {
        val intent = Intent(Settings.ACTION_WIFI_SETTINGS)
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(intent)
    }
    
    fun openBluetoothSettings() {
        val intent = Intent(Settings.ACTION_BLUETOOTH_SETTINGS)
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(intent)
    }
    
    fun openMobileDataSettings() {
        val intent = Intent(Settings.ACTION_DATA_ROAMING_SETTINGS)
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(intent)
    }
} 