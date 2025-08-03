package com.qrypteye.app.ui

import android.content.Intent
import android.graphics.BitmapFactory
import android.net.Uri
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.LinearLayoutManager
import com.google.android.material.snackbar.Snackbar
import com.qrypteye.app.R
import com.qrypteye.app.databinding.ActivitySavedQrCodesBinding
import com.qrypteye.app.databinding.ItemSavedQrCodeBinding
import java.io.File

class SavedQRCodesActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivitySavedQrCodesBinding
    private lateinit var qrCodesAdapter: SavedQRCodesAdapter
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySavedQrCodesBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        setSupportActionBar(binding.toolbar)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        
        setupUI()
        loadSavedQRCodes()
    }
    
    private fun setupUI() {
        binding.toolbar.setNavigationOnClickListener {
            onBackPressed()
        }
        
        // Setup RecyclerView
        qrCodesAdapter = SavedQRCodesAdapter(
            onQrCodeClick = { file ->
                // Open QR code in image viewer
                val intent = Intent(Intent.ACTION_VIEW)
                intent.setDataAndType(Uri.fromFile(file), "image/*")
                intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                try {
                    startActivity(intent)
                } catch (e: Exception) {
                    showError("No image viewer app found")
                }
            },
            onQrCodeShare = { file ->
                // Share QR code
                val intent = Intent(Intent.ACTION_SEND)
                intent.type = "image/png"
                intent.putExtra(Intent.EXTRA_STREAM, Uri.fromFile(file))
                intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                startActivity(Intent.createChooser(intent, "Share QR Code"))
            },
            onQrCodeDelete = { file ->
                // Delete QR code
                if (file.delete()) {
                    showSuccess("QR code deleted")
                    loadSavedQRCodes()
                } else {
                    showError("Failed to delete QR code")
                }
            }
        )
        
        binding.qrCodesRecyclerView.apply {
            layoutManager = LinearLayoutManager(this@SavedQRCodesActivity)
            adapter = qrCodesAdapter
        }
    }
    
    private fun loadSavedQRCodes() {
        val qrCodesDir = getExternalFilesDir(null)
        val qrCodeFiles = qrCodesDir?.listFiles { file ->
            file.name.startsWith("qrypteye_") && file.extension == "png"
        }?.sortedByDescending { it.lastModified() } ?: emptyList()
        
        if (qrCodeFiles.isEmpty()) {
            binding.emptyStateCard.visibility = View.VISIBLE
            binding.qrCodesRecyclerView.visibility = View.GONE
        } else {
            binding.emptyStateCard.visibility = View.GONE
            binding.qrCodesRecyclerView.visibility = View.VISIBLE
            qrCodesAdapter.submitList(qrCodeFiles)
        }
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
    
    inner class SavedQRCodesAdapter(
        private val onQrCodeClick: (File) -> Unit,
        private val onQrCodeShare: (File) -> Unit,
        private val onQrCodeDelete: (File) -> Unit
    ) : androidx.recyclerview.widget.ListAdapter<File, SavedQRCodesAdapter.ViewHolder>(QrCodeDiffCallback()) {
        
        override fun onCreateViewHolder(parent: android.view.ViewGroup, viewType: Int): ViewHolder {
            val binding = ItemSavedQrCodeBinding.inflate(
                android.view.LayoutInflater.from(parent.context), parent, false
            )
            return ViewHolder(binding)
        }
        
        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            holder.bind(getItem(position))
        }
        
        inner class ViewHolder(private val binding: ItemSavedQrCodeBinding) : 
            androidx.recyclerview.widget.RecyclerView.ViewHolder(binding.root) {
            
            fun bind(file: File) {
                // Load QR code image
                val bitmap = BitmapFactory.decodeFile(file.absolutePath)
                binding.qrCodeImage.setImageBitmap(bitmap)
                
                // Set file info
                binding.fileName.text = file.name
                binding.fileDate.text = formatDate(file.lastModified())
                binding.fileSize.text = formatFileSize(file.length())
                
                // Set click listeners
                binding.qrCodeCard.setOnClickListener {
                    onQrCodeClick(file)
                }
                
                binding.shareButton.setOnClickListener {
                    onQrCodeShare(file)
                }
                
                binding.deleteButton.setOnClickListener {
                    onQrCodeDelete(file)
                }
            }
            
            private fun formatDate(timestamp: Long): String {
                val date = java.util.Date(timestamp)
                return java.text.SimpleDateFormat("MMM dd, HH:mm", java.util.Locale.getDefault()).format(date)
            }
            
            private fun formatFileSize(size: Long): String {
                return when {
                    size < 1024 -> "$size B"
                    size < 1024 * 1024 -> "${size / 1024} KB"
                    else -> "${size / (1024 * 1024)} MB"
                }
            }
        }
    }
    
    class QrCodeDiffCallback : androidx.recyclerview.widget.DiffUtil.ItemCallback<File>() {
        override fun areItemsTheSame(oldItem: File, newItem: File): Boolean {
            return oldItem.absolutePath == newItem.absolutePath
        }
        
        override fun areContentsTheSame(oldItem: File, newItem: File): Boolean {
            return oldItem.lastModified() == newItem.lastModified() && oldItem.length() == newItem.length()
        }
    }
} 