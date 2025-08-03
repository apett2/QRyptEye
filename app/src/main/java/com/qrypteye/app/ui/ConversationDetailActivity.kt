package com.qrypteye.app.ui

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import com.qrypteye.app.data.DataManager
import com.qrypteye.app.data.Message
import com.qrypteye.app.databinding.ActivityConversationDetailBinding
import com.qrypteye.app.databinding.ItemMessageBinding
import java.text.SimpleDateFormat
import java.util.*

class ConversationDetailActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityConversationDetailBinding
    private lateinit var dataManager: DataManager
    private lateinit var messagesAdapter: MessagesAdapter
    private var contactName: String = ""
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityConversationDetailBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        dataManager = DataManager(this)
        
        // Get contact name from intent
        contactName = intent.getStringExtra("contact_name") ?: "Unknown"
        
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        supportActionBar?.title = contactName
        
        setupUI()
        loadMessages()
    }
    
    private fun setupUI() {
        binding.toolbar.setNavigationOnClickListener {
            onBackPressed()
        }
        
        binding.composeButton.setOnClickListener {
            val intent = Intent(this, ComposeMessageActivity::class.java)
            intent.putExtra("selected_contact", contactName)
            startActivity(intent)
        }
        
        // Setup RecyclerView
        messagesAdapter = MessagesAdapter()
        binding.messagesRecyclerView.apply {
            layoutManager = LinearLayoutManager(this@ConversationDetailActivity).apply {
                stackFromEnd = true // Show latest messages at bottom
            }
            adapter = messagesAdapter
        }
    }
    
    private fun loadMessages() {
        val allMessages = dataManager.loadMessages()
        val userName = dataManager.getUserName()
        
        // Filter messages for this conversation
        val conversationMessages = allMessages.filter { message ->
            (message.senderName == contactName && message.recipientName == userName) ||
            (message.senderName == userName && message.recipientName == contactName)
        }.sortedBy { it.timestamp }
        
        if (conversationMessages.isEmpty()) {
            binding.emptyStateCard.visibility = android.view.View.VISIBLE
            binding.messagesRecyclerView.visibility = android.view.View.GONE
        } else {
            binding.emptyStateCard.visibility = android.view.View.GONE
            binding.messagesRecyclerView.visibility = android.view.View.VISIBLE
            messagesAdapter.submitList(conversationMessages)
            
            // Mark messages as read
            conversationMessages.filter { !it.isOutgoing && !it.isRead }.forEach { message ->
                dataManager.markMessageAsRead(message.id)
            }
        }
    }
    
    override fun onResume() {
        super.onResume()
        loadMessages() // Refresh when returning from other activities
    }
    
    inner class MessagesAdapter : androidx.recyclerview.widget.ListAdapter<Message, MessagesAdapter.MessageViewHolder>(MessageDiffCallback()) {
        
        override fun onCreateViewHolder(parent: android.view.ViewGroup, viewType: Int): MessageViewHolder {
            val binding = ItemMessageBinding.inflate(
                android.view.LayoutInflater.from(parent.context), parent, false
            )
            return MessageViewHolder(binding)
        }
        
        override fun onBindViewHolder(holder: MessageViewHolder, position: Int) {
            holder.bind(getItem(position))
        }
        
        inner class MessageViewHolder(private val binding: ItemMessageBinding) : 
            androidx.recyclerview.widget.RecyclerView.ViewHolder(binding.root) {
            
            fun bind(message: Message) {
                val userName = dataManager.getUserName()
                val isOutgoing = message.isOutgoing
                
                binding.messageText.text = message.content
                binding.messageTime.text = formatTimestamp(message.timestamp)
                
                // Align messages based on sender
                if (isOutgoing) {
                    binding.messageCard.setCardBackgroundColor(getColor(com.qrypteye.app.R.color.primary_light))
                    binding.messageText.setTextColor(getColor(com.qrypteye.app.R.color.text_primary))
                    binding.messageCard.layoutParams = (binding.messageCard.layoutParams as androidx.constraintlayout.widget.ConstraintLayout.LayoutParams).apply {
                        startToStart = androidx.constraintlayout.widget.ConstraintLayout.LayoutParams.UNSET
                        endToEnd = androidx.constraintlayout.widget.ConstraintLayout.LayoutParams.PARENT_ID
                        horizontalBias = 1.0f
                    }
                } else {
                    binding.messageCard.setCardBackgroundColor(getColor(com.qrypteye.app.R.color.surface))
                    binding.messageText.setTextColor(getColor(com.qrypteye.app.R.color.text_primary))
                    binding.messageCard.layoutParams = (binding.messageCard.layoutParams as androidx.constraintlayout.widget.ConstraintLayout.LayoutParams).apply {
                        startToStart = androidx.constraintlayout.widget.ConstraintLayout.LayoutParams.PARENT_ID
                        endToEnd = androidx.constraintlayout.widget.ConstraintLayout.LayoutParams.UNSET
                        horizontalBias = 0.0f
                    }
                }
            }
            
            private fun formatTimestamp(timestamp: Long): String {
                val date = Date(timestamp)
                return SimpleDateFormat("HH:mm", Locale.getDefault()).format(date)
            }
        }
    }
    
    class MessageDiffCallback : androidx.recyclerview.widget.DiffUtil.ItemCallback<Message>() {
        override fun areItemsTheSame(oldItem: Message, newItem: Message): Boolean {
            return oldItem.id == newItem.id
        }
        
        override fun areContentsTheSame(oldItem: Message, newItem: Message): Boolean {
            return oldItem == newItem
        }
    }
} 