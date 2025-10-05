// static/js/home.js
document.addEventListener('DOMContentLoaded', function() {
    // Animate statistics counters
    animateStatistics();
    
    // Add smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
    
    // Add intersection observer for animations
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.classList.add('animate-in');
            }
        });
    }, observerOptions);
    
    // Observe elements for animation
    document.querySelectorAll('.feature-card, .step').forEach(el => {
        observer.observe(el);
    });
});

function animateStatistics() {
    const counters = document.querySelectorAll('.stat-number');
    const speed = 200; // Lower = faster
    
    counters.forEach(counter => {
        const updateCount = () => {
            const target = +counter.getAttribute('data-target');
            const count = +counter.innerText;
            
            const inc = target / speed;
            
            if (count < target) {
                counter.innerText = Math.ceil(count + inc);
                setTimeout(updateCount, 1);
            } else {
                counter.innerText = target;
            }
        };
        
        // Set initial values from backend data if available
        switch(counter.id) {
            case 'totalUsers':
                counter.setAttribute('data-target', 150);
                break;
            case 'totalDocuments':
                counter.setAttribute('data-target', 450);
                break;
            case 'activeTeachers':
                counter.setAttribute('data-target', 25);
                break;
            case 'reviewsCompleted':
                counter.setAttribute('data-target', 380);
                break;
        }
        
        counter.innerText = '0';
        updateCount();
    });
}