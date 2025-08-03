package com.qrypteye.app.ui

import android.content.Intent
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import com.qrypteye.app.R
import com.qrypteye.app.data.Contact
import com.qrypteye.app.data.DataManager
import com.qrypteye.app.data.Message
import com.qrypteye.app.databinding.ActivityConversationsBinding
import com.qrypteye.app.databinding.ItemConversationBinding
import com.qrypteye.app.security.AirGapChecker
import com.qrypteye.app.security.AirGapNotificationManager
import java.text.SimpleDateFormat
import java.util.*

class ConversationsActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityConversationsBinding
    private lateinit var dataManager: DataManager
    private lateinit var conversationsAdapter: ConversationsAdapter
    private lateinit var airGapNotificationManager: AirGapNotificationManager
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityConversationsBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        dataManager = DataManager(this)
        airGapNotificationManager = AirGapNotificationManager(this)
        
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(false) // No back button since this is main activity
        
        setupUI()
        loadConversations()
        updateAirGapIndicator()
    }
    
    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.conversations_menu, menu)
        return true
    }
    
    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            R.id.action_key_management -> {
                val intent = Intent(this, KeyManagementActivity::class.java)
                startActivity(intent)
                true
            }
            R.id.action_settings -> {
                val intent = Intent(this, SettingsActivity::class.java)
                startActivity(intent)
                true
            }
            R.id.action_saved_qr_codes -> {
                val intent = Intent(this, SavedQRCodesActivity::class.java)
                startActivity(intent)
                true
            }
            R.id.action_scan_qr -> {
                val intent = Intent(this, ScanQRActivity::class.java)
                startActivity(intent)
                true
            }
            R.id.action_airgap_status -> {
                showAirGapStatus()
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }
    
    private fun showAirGapStatus() {
        val airGapChecker = AirGapChecker(this)
        val status = airGapChecker.checkAirGapStatus()
        
        val dialogBuilder = androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("Air-Gap Status")
            .setMessage(status.message)
            .setPositiveButton("OK", null)
        
        // Add quick action buttons if device is not air-gapped
        if (!status.isAirGapped) {
            dialogBuilder.setNeutralButton("Turn Off All") { _, _ ->
                // Show a dialog with options to turn off specific features
                showTurnOffOptionsDialog(airGapChecker, status.enabledFeatures)
            }
        }
        
        val dialog = dialogBuilder.create()
        dialog.show()
    }
    
    private fun showTurnOffOptionsDialog(airGapChecker: AirGapChecker, enabledFeatures: List<String>) {
        val items = enabledFeatures.toTypedArray()
        val checkedItems = BooleanArray(items.size) { true } // All checked by default
        
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle("Turn Off Features")
            .setMultiChoiceItems(items, checkedItems) { _, which, isChecked ->
                checkedItems[which] = isChecked
            }
            .setPositiveButton("Turn Off Selected") { _, _ ->
                // Open relevant settings based on what's selected
                enabledFeatures.forEachIndexed { index, feature ->
                    if (checkedItems[index]) {
                        when (feature) {
                            "WiFi" -> airGapChecker.openWifiSettings()
                            "Bluetooth" -> airGapChecker.openBluetoothSettings()
                            "Mobile Data" -> airGapChecker.openMobileDataSettings()
                        }
                    }
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
    
    private fun setupUI() {
        binding.composeButton.setOnClickListener {
            val intent = Intent(this, ComposeMessageActivity::class.java)
            startActivity(intent)
        }
        
        // Setup security warning close button
        binding.securityWarningClose.setOnClickListener {
            binding.securityWarningBanner.visibility = View.GONE
        }
        
        // Setup RecyclerView
        conversationsAdapter = ConversationsAdapter { contact ->
            // Open conversation detail
            val intent = Intent(this, ConversationDetailActivity::class.java)
            intent.putExtra("contact_name", contact.name)
            startActivity(intent)
        }
        
        binding.conversationsRecyclerView.apply {
            layoutManager = LinearLayoutManager(this@ConversationsActivity)
            adapter = conversationsAdapter
        }
    }
    
    private fun loadConversations() {
        val contacts = dataManager.loadContacts()
        val messages = dataManager.loadMessages()
        
        if (contacts.isEmpty()) {
            binding.emptyStateCard.visibility = View.VISIBLE
            binding.conversationsRecyclerView.visibility = View.GONE
            return
        }
        
        // Filter out invalid contacts and log them for debugging
        val validContacts = contacts.filter { contact ->
            if (contact.isValid()) {
                true
            } else {
                // Log invalid contact but don't show error to user (might be noisy)
                val validationResult = contact.getValidationResult()
                android.util.Log.w("ConversationsActivity", 
                    "Invalid contact '${contact.name}': ${validationResult.message}")
                false
            }
        }
        
        if (validContacts.isEmpty()) {
            binding.emptyStateCard.visibility = View.VISIBLE
            binding.conversationsRecyclerView.visibility = View.GONE
            return
        }
        
        // Group messages by contact and get the latest message for each
        val conversations = mutableListOf<ConversationItem>()
        
        for (contact in validContacts) {
            val contactMessages = messages.filter { 
                it.senderName == contact.name || it.recipientName == contact.name 
            }
            
            if (contactMessages.isNotEmpty()) {
                val latestMessage = contactMessages.maxByOrNull { it.timestamp }
                val unreadCount = contactMessages.count { !it.isOutgoing && !it.isRead }
                
                conversations.add(
                    ConversationItem(
                        contact = contact,
                        lastMessage = latestMessage,
                        unreadCount = unreadCount
                    )
                )
            }
        }
        
        // Sort by latest message timestamp
        conversations.sortByDescending { it.lastMessage?.timestamp ?: 0 }
        
        if (conversations.isEmpty()) {
            binding.emptyStateCard.visibility = View.VISIBLE
            binding.conversationsRecyclerView.visibility = View.GONE
        } else {
            binding.emptyStateCard.visibility = View.GONE
            binding.conversationsRecyclerView.visibility = View.VISIBLE
            conversationsAdapter.submitList(conversations)
        }
    }
    
    override fun onResume() {
        super.onResume()
        loadConversations() // Refresh when returning from other activities
        updateAirGapIndicator() // Update air-gap status
    }
    
    private fun updateAirGapIndicator() {
        val airGapChecker = AirGapChecker(this)
        val status = airGapChecker.checkAirGapStatus()
        
        // Update toolbar subtitle to show air-gap status
        supportActionBar?.subtitle = if (status.isAirGapped) {
            "🔒 Air-Gapped"
        } else {
            "⚠️ Not Air-Gapped"
        }
        
        // Show/hide security warning banner
        binding.securityWarningBanner.visibility = if (status.isAirGapped) {
            View.GONE
        } else {
            View.VISIBLE
        }
        
        // Show/hide persistent notification
        if (status.isAirGapped) {
            airGapNotificationManager.hideAirGapWarning()
        } else {
            airGapNotificationManager.showAirGapWarning(status.enabledFeatures)
        }
    }
    
    data class ConversationItem(
        val contact: Contact,
        val lastMessage: Message?,
        val unreadCount: Int
    )
    
    inner class ConversationsAdapter(
        private val onConversationClick: (Contact) -> Unit
    ) : androidx.recyclerview.widget.ListAdapter<ConversationItem, ConversationsAdapter.ViewHolder>(ConversationDiffCallback()) {
        
        override fun onCreateViewHolder(parent: android.view.ViewGroup, viewType: Int): ViewHolder {
            val binding = ItemConversationBinding.inflate(
                android.view.LayoutInflater.from(parent.context), parent, false
            )
            return ViewHolder(binding)
        }
        
        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            holder.bind(getItem(position))
        }
        
        inner class ViewHolder(private val binding: ItemConversationBinding) : 
            androidx.recyclerview.widget.RecyclerView.ViewHolder(binding.root) {
            
            fun bind(item: ConversationItem) {
                binding.contactName.text = item.contact.name
                
                item.lastMessage?.let { message ->
                    binding.lastMessage.text = message.content
                    binding.lastMessageTime.text = formatTimestamp(message.timestamp)
                    binding.lastMessageTime.visibility = View.VISIBLE
                } ?: run {
                    binding.lastMessage.text = "No messages yet"
                    binding.lastMessageTime.visibility = View.GONE
                }
                
                // Show unread count
                if (item.unreadCount > 0) {
                    binding.unreadCount.text = item.unreadCount.toString()
                    binding.unreadCount.visibility = View.VISIBLE
                } else {
                    binding.unreadCount.visibility = View.GONE
                }
                
                binding.root.setOnClickListener {
                    onConversationClick(item.contact)
                }
            }
        }
        
        private fun formatTimestamp(timestamp: Long): String {
            val date = Date(timestamp)
            val now = Calendar.getInstance()
            val messageDate = Calendar.getInstance().apply { timeInMillis = timestamp }
            
            return when {
                now.get(Calendar.DATE) == messageDate.get(Calendar.DATE) -> {
                    // Today - show time
                    SimpleDateFormat("HH:mm", Locale.getDefault()).format(date)
                }
                now.get(Calendar.DATE) - messageDate.get(Calendar.DATE) == 1 -> {
                    // Yesterday
                    "Yesterday"
                }
                else -> {
                    // Other days - show date
                    SimpleDateFormat("MMM dd", Locale.getDefault()).format(date)
                }
            }
        }
    }
    
    class ConversationDiffCallback : androidx.recyclerview.widget.DiffUtil.ItemCallback<ConversationItem>() {
        override fun areItemsTheSame(oldItem: ConversationItem, newItem: ConversationItem): Boolean {
            return oldItem.contact.id == newItem.contact.id
        }
        
        override fun areContentsTheSame(oldItem: ConversationItem, newItem: ConversationItem): Boolean {
            return oldItem == newItem
        }
    }
} 