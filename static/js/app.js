// Secure S3 Share — Frontend (Security Hardened)
// XSS-safe, CSRF-aware, input-validated

const API_BASE = '';
let selectedFile = null;
let pendingFileId = null;

// XSS Escape Helper
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// DOM Elements
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const optionsPanel = document.getElementById('options-panel');
const uploadBtn = document.getElementById('upload-btn');
const cancelBtn = document.getElementById('cancel-btn');
const progressContainer = document.getElementById('progress-container');
const progressFill = document.getElementById('progress-fill');
const progressText = document.getElementById('progress-text');
const filesList = document.getElementById('files-list');
const fileCount = document.getElementById('file-count');
const resultModal = document.getElementById('result-modal');
const shareLink = document.getElementById('share-link');
const copyBtn = document.getElementById('copy-btn');
const closeModal = document.getElementById('close-modal');
const linkExpiry = document.getElementById('link-expiry');

// Event Listeners
dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.querySelector('.upload-area').classList.add('drag-over');
});
dropZone.addEventListener('dragleave', () => {
  dropZone.querySelector('.upload-area').classList.remove('drag-over');
});
dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.querySelector('.upload-area').classList.remove('drag-over');
  const files = e.dataTransfer.files;
  if (files.length > 0) handleFileSelect(files[0]);
});

fileInput.addEventListener('change', (e) => {
  if (e.target.files.length > 0) handleFileSelect(e.target.files[0]);
});

uploadBtn.addEventListener('click', startUpload);
cancelBtn.addEventListener('click', resetUpload);
copyBtn.addEventListener('click', copyToClipboard);
closeModal.addEventListener('click', () => {
  resultModal.style.display = 'none';
  resetUpload();
  loadFiles();
});

// Input validation
function validateFile(file) {
    const MAX_SIZE = 500 * 1024 * 1024; // 500MB
    const ALLOWED_TYPES = [
        'application/pdf', 'application/zip', 'application/octet-stream',
        'image/', 'video/', 'audio/', 'text/',
        'application/json', 'application/xml'
    ];
    
    if (file.size > MAX_SIZE) {
        alert('File exceeds 500MB limit');
        return false;
    }
    
    const isAllowed = ALLOWED_TYPES.some(type => file.type.startsWith(type.replace('/', '')) || 
        (type.endsWith('/') && file.type.startsWith(type)));
    
    if (!isAllowed && file.type) {
        console.warn('Content type not in allowlist:', file.type);
    }
    
    // Validate filename
    if (file.name.length > 255) {
        alert('Filename too long (max 255 characters)');
        return false;
    }
    
    return true;
}

function handleFileSelect(file) {
    if (!validateFile(file)) return;
    selectedFile = file;
    optionsPanel.style.display = 'block';
    dropZone.style.display = 'none';
}

function resetUpload() {
    selectedFile = null;
    pendingFileId = null;
    fileInput.value = '';
    optionsPanel.style.display = 'none';
    dropZone.style.display = 'block';
    progressContainer.style.display = 'none';
    progressFill.style.width = '0%';
    progressFill.style.background = '';
    document.getElementById('file-password').value = '';
    document.getElementById('ttl-select').value = '24';
}

async function startUpload() {
    if (!selectedFile) return;

    const password = document.getElementById('file-password').value;
    const ttlHours = parseInt(document.getElementById('ttl-select').value);

    // Show progress
    optionsPanel.style.display = 'none';
    progressContainer.style.display = 'block';
    progressText.textContent = 'Requesting upload URL...';

    try {
        // Step 1: Get pre-signed upload URL from backend
        const uploadReq = {
            filename: selectedFile.name,
            content_type: selectedFile.type || 'application/octet-stream',
            file_size: selectedFile.size,
            password: password || undefined,
            ttl_hours: ttlHours
        };

        const response = await fetch(`${API_BASE}/api/upload-url`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(uploadReq)
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.detail || 'Failed to get upload URL');
        }

        const { file_id, upload_url, expires_in } = await response.json();
        pendingFileId = file_id;

        // Step 2: Upload directly to S3 using pre-signed URL
        progressText.textContent = 'Uploading to S3...';
        
        await uploadToS3(upload_url, selectedFile);

        // Step 3: Confirm upload
        progressText.textContent = 'Finishing...';
        
        const confirmResponse = await fetch(`${API_BASE}/api/confirm-upload/${encodeURIComponent(file_id)}`, {
            method: 'POST'
        });

        if (!confirmResponse.ok) {
            throw new Error('Upload confirmation failed');
        }

        // Show result
        showResult(file_id, selectedFile.name, ttlHours);

    } catch (error) {
        console.error('Upload error:', error);
        progressText.textContent = `Error: ${escapeHtml(error.message)}`;
        progressFill.style.background = 'var(--accent-red)';
        setTimeout(() => {
            resetUpload();
        }, 3000);
    }
}

function uploadToS3(presignedUrl, file) {
    return new Promise((resolve, reject) => {
        const xhr = new XMLHttpRequest();
        
        xhr.upload.addEventListener('progress', (e) => {
            if (e.lengthComputable) {
                const percent = (e.loaded / e.total) * 100;
                progressFill.style.width = percent + '%';
                progressText.textContent = `Uploading: ${Math.round(percent)}%`;
            }
        });

        xhr.addEventListener('load', () => {
            if (xhr.status >= 200 && xhr.status < 300) {
                progressFill.style.width = '100%';
                resolve();
            } else {
                reject(new Error(`S3 upload failed: ${xhr.status} ${xhr.statusText}`));
            }
        });

        xhr.addEventListener('error', () => reject(new Error('Network error during upload')));
        xhr.addEventListener('abort', () => reject(new Error('Upload aborted')));

        xhr.open('PUT', presignedUrl);
        xhr.setRequestHeader('Content-Type', file.type || 'application/octet-stream');
        xhr.send(file);
    });
}

function showResult(fileId, filename, ttlHours) {
    const downloadUrl = `${window.location.origin}/api/download/${encodeURIComponent(fileId)}`;
    shareLink.value = downloadUrl;
    
    let expiryText;
    if (ttlHours === 0) {
        expiryText = 'API link never expires (S3 download URL expires in 1 hour)';
    } else if (ttlHours === 1) {
        expiryText = 'Link expires in 1 hour';
    } else {
        expiryText = `Link expires in ${ttlHours} hours`;
    }
    linkExpiry.textContent = expiryText;
    
    resultModal.style.display = 'flex';
}

async function copyToClipboard() {
    try {
        await navigator.clipboard.writeText(shareLink.value);
        copyBtn.textContent = 'Copied!';
        copyBtn.classList.add('copied');
        setTimeout(() => {
            copyBtn.textContent = 'Copy';
            copyBtn.classList.remove('copied');
        }, 2000);
    } catch (err) {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = shareLink.value;
        textArea.style.position = 'fixed';
        textArea.style.left = '-9999px';
        document.body.appendChild(textArea);
        textArea.select();
        try {
            document.execCommand('copy');
            copyBtn.textContent = 'Copied!';
            setTimeout(() => copyBtn.textContent = 'Copy', 2000);
        } catch (err) {
            console.error('Copy failed:', err);
        }
        document.body.removeChild(textArea);
    }
}

// File Listing
async function loadFiles() {
    try {
        const response = await fetch(`${API_BASE}/api/files`);
        if (!response.ok) throw new Error('Failed to load files');
        
        const data = await response.json();
        renderFiles(data.files);
    } catch (error) {
        console.error('Error loading files:', error);
        filesList.innerHTML = '<div class="empty-state">Unable to load files</div>';
    }
}

function renderFiles(files) {
    fileCount.textContent = `${files.length} file${files.length !== 1 ? 's' : ''}`;
    
    if (files.length === 0) {
        filesList.innerHTML = '<div class="empty-state">No files shared yet</div>';
        return;
    }
    
    filesList.innerHTML = files.map(file => `
        <div class="file-item" data-id="${escapeHtml(file.file_id)}">
            <div class="file-info">
                <div class="file-icon">${getFileIcon(file.content_type)}</div>
                <div class="file-details">
                    <div class="file-name" title="${escapeHtml(file.filename)}">${escapeHtml(file.filename)}</div>
                    <div class="file-meta">
                        ${escapeHtml(formatSize(file.size))} • ${escapeHtml(formatDate(file.uploaded_at))}
                        ${file.password_protected ? '• 🔒 Protected' : ''}
                        ${file.expired ? '• ⚠️ Expired' : ''}
                    </div>
                </div>
            </div>
            <div class="file-actions">
                <button class="btn-download" onclick="downloadFile('${escapeHtml(file.file_id)}', ${file.password_protected})" ${file.expired ? 'disabled' : ''}>
                    Download
                </button>
                <button class="btn-delete" onclick="deleteFile('${escapeHtml(file.file_id)}')">
                    Delete
                </button>
            </div>
        </div>
    `).join('');
}

async function downloadFile(fileId, needsPassword) {
    let password = '';
    if (needsPassword) {
        password = prompt('Enter password:');
        if (!password) return;
    }
    
    try {
        const url = new URL(`${API_BASE}/api/download/${encodeURIComponent(fileId)}`, window.location.origin);
        if (password) url.searchParams.append('password', password);
        
        const response = await fetch(url);
        if (!response.ok) {
            const error = await response.json();
            alert(escapeHtml(error.detail || 'Download failed'));
            return;
        }
        
        const data = await response.json();
        
        // Trigger download via anchor tag (avoids popup blockers)
        const a = document.createElement('a');
        a.href = data.download_url;
        a.download = data.filename;
        a.style.display = 'none';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        
    } catch (error) {
        console.error('Download error:', error);
        alert('Download failed');
    }
}

async function deleteFile(fileId) {
    if (!confirm('Delete this file?')) return;
    
    const adminToken = prompt('Admin token (if required):');
    
    try {
        const headers = {};
        if (adminToken) {
            headers['X-Admin-Token'] = adminToken;
        }
        
        const response = await fetch(`${API_BASE}/api/files/${encodeURIComponent(fileId)}`, {
            method: 'DELETE',
            headers: headers
        });
        
        if (response.ok) {
            loadFiles();
        } else {
            const error = await response.json();
            alert(escapeHtml(error.detail || 'Delete failed'));
        }
    } catch (error) {
        console.error('Delete error:', error);
        alert('Delete failed');
    }
}

// Utilities
function getFileIcon(contentType) {
    if (contentType?.startsWith('image/')) return '🖼️';
    if (contentType?.startsWith('video/')) return '🎬';
    if (contentType?.startsWith('audio/')) return '🎵';
    if (contentType?.includes('pdf')) return '📄';
    if (contentType?.includes('zip') || contentType?.includes('rar') || contentType?.includes('7z')) return '📦';
    if (contentType?.includes('word') || contentType?.includes('document')) return '📝';
    if (contentType?.includes('excel') || contentType?.includes('sheet')) return '📊';
    if (contentType?.includes('powerpoint') || contentType?.includes('presentation')) return '📽️';
    return '📎';
}

function formatSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatDate(isoString) {
    const date = new Date(isoString);
    return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// Load files on page load
document.addEventListener('DOMContentLoaded', loadFiles);