package com.qrypteye.app.ui

import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.snackbar.Snackbar
import com.qrypteye.app.R
import com.qrypteye.app.data.DataManager
import com.qrypteye.app.databinding.ActivitySettingsBinding

class SettingsActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivitySettingsBinding
    private lateinit var dataManager: DataManager
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySettingsBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        dataManager = DataManager(this)
        
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        
        setupUI()
        loadCurrentSettings()
    }
    
    private fun setupUI() {
        binding.toolbar.setNavigationOnClickListener {
            onBackPressed()
        }
        
        binding.saveButton.setOnClickListener {
            saveSettings()
        }
    }
    
    private fun loadCurrentSettings() {
        val currentName = dataManager.getUserName()
        binding.userNameEditText.setText(currentName)
        binding.userNameEditText.setSelection(currentName.length)
    }
    
    private fun saveSettings() {
        val userName = binding.userNameEditText.text.toString().trim()
        
        if (userName.isEmpty()) {
            showError("Please enter a username")
            return
        }
        
        if (userName.length > 50) {
            showError("Username must be 50 characters or less")
            return
        }
        
        dataManager.saveUserName(userName)
        showSuccess("Settings saved successfully")
        
        // Close the activity
        finish()
    }
    
    private fun showSuccess(message: String) {
        Snackbar.make(binding.root, message, Snackbar.LENGTH_LONG)
            .setBackgroundTint(getColor(R.color.success))
            .show()
    }
    
    private fun showError(message: String) {
        Snackbar.make(binding.root, message, Snackbar.LENGTH_LONG)
            .setBackgroundTint(getColor(R.color.error))
            .show()
    }
} 