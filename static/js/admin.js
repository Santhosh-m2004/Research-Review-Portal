// Admin-specific functionality
document.addEventListener('DOMContentLoaded', function() {
    // Initialize charts if Chart.js is available
    if (typeof Chart !== 'undefined') {
        initAdminCharts();
    }
    
    // User management functionality
    const userRoleSelects = document.querySelectorAll('.user-role-select');
    userRoleSelects.forEach(select => {
        select.addEventListener('change', function() {
            const userId = this.getAttribute('data-user-id');
            const newRole = this.value;
            
            if (confirm(`Are you sure you want to change this user's role to ${newRole}?`)) {
                updateUserRole(userId, newRole);
            } else {
                this.value = this.getAttribute('data-previous-value');
            }
        });
    });
    
    // Document search functionality
    const searchForm = document.querySelector('.search-box');
    if (searchForm) {
        const searchInput = searchForm.querySelector('input');
        searchInput.addEventListener('keyup', function(e) {
            if (e.key === 'Enter') {
                searchForm.submit();
            }
        });
    }
    
    // Initialize data tables if DataTables is available
    if (typeof $.fn.DataTable !== 'undefined') {
        $('.table').DataTable({
            responsive: true,
            pageLength: 10,
            order: [[0, 'desc']]
        });
    }
    
    // Feedback form validation
    const feedbackForms = document.querySelectorAll('.feedback-form');
    feedbackForms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const feedbackInput = this.querySelector('input[name="feedback"]');
            if (!feedbackInput.value.trim()) {
                e.preventDefault();
                alert('Please provide feedback before submitting.');
                feedbackInput.focus();
            }
        });
    });
});

function initAdminCharts() {
    // User statistics chart
    const userStatsCtx = document.getElementById('userStatsChart');
    if (userStatsCtx) {
        new Chart(userStatsCtx, {
            type: 'doughnut',
            data: {
                labels: ['Admins', 'Regular Users'],
                datasets: [{
                    data: [
                        userStatsCtx.getAttribute('data-admins'),
                        userStatsCtx.getAttribute('data-users')
                    ],
                    backgroundColor: [
                        'rgba(67, 97, 238, 0.8)',
                        'rgba(76, 201, 240, 0.8)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    }
    
    // Document status chart
    const docStatsCtx = document.getElementById('docStatsChart');
    if (docStatsCtx) {
        new Chart(docStatsCtx, {
            type: 'bar',
            data: {
                labels: ['Total', 'Reviewed', 'Pending'],
                datasets: [{
                    label: 'Documents',
                    data: [
                        docStatsCtx.getAttribute('data-total'),
                        docStatsCtx.getAttribute('data-reviewed'),
                        docStatsCtx.getAttribute('data-pending')
                    ],
                    backgroundColor: [
                        'rgba(67, 97, 238, 0.6)',
                        'rgba(76, 201, 240, 0.6)',
                        'rgba(247, 37, 133, 0.6)'
                    ],
                    borderColor: [
                        'rgba(67, 97, 238, 1)',
                        'rgba(76, 201, 240, 1)',
                        'rgba(247, 37, 133, 1)'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }
}

function updateUserRole(userId, newRole) {
    fetch('/admin/update_user_role', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            user_id: userId,
            role: newRole
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('User role updated successfully', 'success');
            // Update the UI to reflect the change
            const badge = document.querySelector(`.role-badge[data-user-id="${userId}"]`);
            if (badge) {
                badge.className = `role-badge role-${newRole}`;
                badge.textContent = newRole;
            }
        } else {
            showNotification('Error updating user role: ' + data.message, 'error');
            // Revert the select value
            const select = document.querySelector(`.user-role-select[data-user-id="${userId}"]`);
            if (select) {
                select.value = select.getAttribute('data-previous-value');
            }
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showNotification('Error updating user role', 'error');
        // Revert the select value
        const select = document.querySelector(`.user-role-select[data-user-id="${userId}"]`);
        if (select) {
            select.value = select.getAttribute('data-previous-value');
        }
    });
}

function showNotification(message, type) {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} notification-toast`;
    notification.innerHTML = `
        <span class="alert-message">${message}</span>
        <button class="alert-close" onclick="this.parentElement.remove()">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    // Add styles for toast notification
    const style = document.createElement('style');
    style.textContent = `
        .notification-toast {
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 9999;
            min-width: 300px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
            animation: slideIn 0.3s ease;
        }
        
        @keyframes slideIn {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
    `;
    
    if (!document.querySelector('#notification-styles')) {
        style.id = 'notification-styles';
        document.head.appendChild(style);
    }
    
    document.body.appendChild(notification);
    
    // Auto remove after 5 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 5000);
}