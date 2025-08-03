package com.qrypteye.app

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.qrypteye.app.databinding.ActivityMainBinding
import com.qrypteye.app.ui.ComposeMessageActivity
import com.qrypteye.app.ui.ConversationsActivity
import com.qrypteye.app.ui.KeyManagementActivity
import com.qrypteye.app.ui.SavedQRCodesActivity
import com.qrypteye.app.ui.ScanQRActivity

class MainActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityMainBinding
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        setSupportActionBar(binding.toolbar)
        
        setupClickListeners()
    }
    
    private fun setupClickListeners() {
        binding.cardComposeMessage.setOnClickListener {
            val intent = Intent(this, ComposeMessageActivity::class.java)
            startActivity(intent)
        }
        
        binding.cardScanQr.setOnClickListener {
            val intent = Intent(this, ScanQRActivity::class.java)
            startActivity(intent)
        }
        
        binding.cardManageKeys.setOnClickListener {
            val intent = Intent(this, KeyManagementActivity::class.java)
            startActivity(intent)
        }
        
        binding.cardConversations.setOnClickListener {
            val intent = Intent(this, ConversationsActivity::class.java)
            startActivity(intent)
        }
        
        binding.cardSavedQrCodes.setOnClickListener {
            val intent = Intent(this, SavedQRCodesActivity::class.java)
            startActivity(intent)
        }
    }
} 