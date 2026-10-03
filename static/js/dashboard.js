// Dashboard JS
document.addEventListener("DOMContentLoaded", function() {
    // Add smooth transitions and initialize any extra chart options if needed
    const sidebarLinks = document.querySelectorAll('.sidebar a');
    
    // Highlight active link
    const currentPath = window.location.pathname;
    sidebarLinks.forEach(link => {
        if(link.getAttribute('href') === currentPath) {
            link.style.borderLeft = "3px solid #58a6ff";
            link.style.backgroundColor = "#21262d";
        }
    });

    // Handle toast notifications
    const showToast = (message, type = 'info') => {
        const container = document.createElement('div');
        container.className = 'toast-container';
        
        const toast = document.createElement('div');
        toast.className = `toast align-items-center text-white bg-${type} border-0 show`;
        toast.setAttribute('role', 'alert');
        toast.setAttribute('aria-live', 'assertive');
        toast.setAttribute('aria-atomic', 'true');
        
        const flex = document.createElement('div');
        flex.className = 'd-flex';
        
        const body = document.createElement('div');
        body.className = 'toast-body';
        body.innerText = message;
        
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn-close btn-close-white me-2 m-auto';
        btn.setAttribute('data-bs-dismiss', 'toast');
        btn.onclick = () => container.remove();
        
        flex.appendChild(body);
        flex.appendChild(btn);
        toast.appendChild(flex);
        container.appendChild(toast);
        document.body.appendChild(container);
        
        setTimeout(() => container.remove(), 3000);
    };

    window.showToast = showToast;
});
