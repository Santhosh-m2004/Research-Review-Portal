// Drag and drop functionality for file uploads
document.addEventListener('DOMContentLoaded', function() {
    const dropZones = document.querySelectorAll('.file-upload-label');
    
    // Add event listeners to all drop zones
    dropZones.forEach(dropZone => {
        // Prevent default drag behaviors
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, preventDefaults, false);
            document.body.addEventListener(eventName, preventDefaults, false);
        });
        
        // Highlight drop zone when item is dragged over it
        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, highlight, false);
        });
        
        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, unhighlight, false);
        });
        
        // Handle dropped files
        dropZone.addEventListener('drop', handleDrop, false);
        
        // Handle click to select file
        dropZone.addEventListener('click', function(e) {
            if (e.target === this) {
                this.nextElementSibling.click();
            }
        });
    });
    
    // File input change event
    const fileInputs = document.querySelectorAll('.file-upload-input');
    fileInputs.forEach(input => {
        input.addEventListener('change', function() {
            const fileName = this.files[0]?.name || 'No file chosen';
            const fileNameDisplay = this.closest('.file-upload').querySelector('.file-name');
            if (fileNameDisplay) {
                fileNameDisplay.textContent = fileName;
            }
        });
    });
    
    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }
    
    function highlight(e) {
        this.classList.add('highlight');
    }
    
    function unhighlight(e) {
        this.classList.remove('highlight');
    }
    
    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        
        if (files.length) {
            const input = this.nextElementSibling;
            input.files = files;
            
            // Trigger change event
            const event = new Event('change', { bubbles: true });
            input.dispatchEvent(event);
        }
    }
    
    // Add highlight class for styling
    const style = document.createElement('style');
    style.textContent = `
        .file-upload-label.highlight {
            border-color: var(--primary-color);
            background-color: rgba(67, 97, 238, 0.05);
        }
    `;
    document.head.appendChild(style);
});