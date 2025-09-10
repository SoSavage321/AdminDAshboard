document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const authContainer = document.getElementById('auth-container');
    const dashboardContainer = document.getElementById('dashboard-container');
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    const forgotForm = document.getElementById('forgot-form');
    const showRegisterBtn = document.getElementById('show-register');
    const showLoginBtn = document.getElementById('show-login');
    const forgotPasswordBtn = document.getElementById('forgot-password');
    const backToLoginBtn = document.getElementById('back-to-login');
    const passwordInput = document.getElementById('register-password');
    const passwordStrengthBar = document.querySelector('.strength-bar');
    const passwordStrengthText = document.querySelector('.strength-text');
    const logoutBtn = document.getElementById('logout-btn');
    const adminNameSpan = document.getElementById('admin-name');

    // Dashboard navigation elements
    const navLinks = document.querySelectorAll('.nav-menu a');
    const contentSections = document.querySelectorAll('.content-section');
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    // Show Register Form
    showRegisterBtn.addEventListener('click', function(e) {
        e.preventDefault();
        loginForm.classList.add('hidden');
        registerForm.classList.remove('hidden');
        forgotForm.classList.add('hidden');
    });

    // Show Login Form
    showLoginBtn.addEventListener('click', function(e) {
        e.preventDefault();
        registerForm.classList.add('hidden');
        loginForm.classList.remove('hidden');
        forgotForm.classList.add('hidden');
    });

    // Show Forgot Password Form
    forgotPasswordBtn.addEventListener('click', function(e) {
        e.preventDefault();
        loginForm.classList.add('hidden');
        forgotForm.classList.remove('hidden');
    });

    // Back to Login from Forgot Password
    backToLoginBtn.addEventListener('click', function(e) {
        e.preventDefault();
        forgotForm.classList.add('hidden');
        loginForm.classList.remove('hidden');
    });

    // Password Strength Checker
    passwordInput.addEventListener('input', function() {
        const password = this.value;
        const strength = checkPasswordStrength(password);
        
        // Update strength bar
        passwordStrengthBar.style.width = strength.percentage + '%';
        passwordStrengthBar.style.background = strength.color;
        passwordStrengthText.textContent = strength.text;
    });

    // Login Form Submission
    document.getElementById('login').addEventListener('submit', function(e) {
        e.preventDefault();
        const email = document.getElementById('login-email').value;
        const password = document.getElementById('login-password').value;
        const rememberMe = document.getElementById('remember-me').checked;
        
        // Simple validation
        if (!email || !password) {
            showNotification('Please fill in all fields', 'error');
            return;
        }
        
        // Simulate login process
        simulateLogin(email, password, rememberMe);
    });

    // Registration Form Submission
    document.getElementById('register').addEventListener('submit', function(e) {
        e.preventDefault();
        const name = document.getElementById('register-name').value;
        const email = document.getElementById('register-email').value;
        const password = document.getElementById('register-password').value;
        const confirmPassword = document.getElementById('register-confirm-password').value;
        const adminKey = document.getElementById('admin-key').value;
        const agreeTerms = document.getElementById('terms-agree').checked;
        
        // Validation
        if (!name || !email || !password || !confirmPassword || !adminKey) {
            showNotification('Please fill in all fields', 'error');
            return;
        }
        
        if (password !== confirmPassword) {
            showNotification('Passwords do not match', 'error');
            return;
        }
        
        if (!agreeTerms) {
            showNotification('You must agree to the terms and conditions', 'error');
            return;
        }
        
        // Simulate registration process
        simulateRegistration(name, email, password, adminKey);
    });

    // Forgot Password Form Submission
    document.getElementById('forgot-password-form').addEventListener('submit', function(e) {
        e.preventDefault();
        const email = document.getElementById('reset-email').value;
        
        if (!email) {
            showNotification('Please enter your email address', 'error');
            return;
        }
        
        // Simulate password reset process
        simulatePasswordReset(email);
    });

    // Logout functionality
    logoutBtn.addEventListener('click', function() {
        if (confirm('Are you sure you want to logout?')) {
            // Clear any stored data
            localStorage.removeItem('rememberMe');
            localStorage.removeItem('adminEmail');
            localStorage.removeItem('adminName');
            
            // Show auth container, hide dashboard
            authContainer.style.display = 'flex';
            dashboardContainer.style.display = 'none';
            
            showNotification('Logged out successfully', 'success');
        }
    });

    // Dashboard Navigation
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Remove active class from all links and sections
            navLinks.forEach(l => l.classList.remove('active'));
            contentSections.forEach(s => s.classList.remove('active'));
            
            // Add active class to clicked link
            this.classList.add('active');
            
            // Show corresponding section
            const sectionId = this.getAttribute('data-section');
            document.getElementById(sectionId).classList.add('active');
        });
    });
    
    // Tab functionality for content management
    tabBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            // Remove active class from all buttons and contents
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            
            // Add active class to clicked button
            this.classList.add('active');
            
            // Show corresponding content
            const tabId = this.getAttribute('data-tab');
            document.getElementById(tabId).classList.add('active');
        });
    });

    // Password Strength Check Function
    function checkPasswordStrength(password) {
        let strength = 0;
        let feedback = '';
        let color = '#e74c3c'; // Red (weak)
        
        if (password.length >= 8) strength++;
        if (password.match(/[a-z]+/)) strength++;
        if (password.match(/[A-Z]+/)) strength++;
        if (password.match(/[0-9]+/)) strength++;
        if (password.match(/[!@#$%^&*(),.?":{}|<>]+/)) strength++;
        
        switch(strength) {
            case 0:
            case 1:
            case 2:
                feedback = 'Weak';
                color = '#e74c3c';
                break;
            case 3:
                feedback = 'Medium';
                color = '#f39c12';
                break;
            case 4:
                feedback = 'Strong';
                color = '#27ae60';
                break;
            case 5:
                feedback = 'Very Strong';
                color = '#2ecc71';
                break;
            default:
                feedback = 'Weak';
        }
        
        return {
            percentage: (strength / 5) * 100,
            text: feedback,
            color: color
        };
    }

    // Simulate Login Process
    function simulateLogin(email, password, rememberMe) {
        showNotification('Logging in...', 'info');
        
        // In a real application, this would be an API call
        setTimeout(() => {
            // Check for demo credentials
            if (email === 'admin@funplusmath.com' && password === 'admin123') {
                showNotification('Login successful!', 'success');
                
                // Store login state if remember me is checked
                if (rememberMe) {
                    localStorage.setItem('rememberMe', 'true');
                    localStorage.setItem('adminEmail', email);
                    localStorage.setItem('adminName', 'Admin User');
                }
                
                // Update admin name in dashboard
                adminNameSpan.textContent = 'Admin User';
                
                // Show dashboard, hide auth container
                authContainer.style.display = 'none';
                dashboardContainer.style.display = 'flex';
            } else {
                showNotification('Invalid email or password', 'error');
            }
        }, 1500);
    }

    // Simulate Registration Process
    function simulateRegistration(name, email, password, adminKey) {
        // Check admin key (demo key is 123456)
        if (adminKey !== '123456') {
            showNotification('Invalid administrator key', 'error');
            return;
        }
        
        showNotification('Creating account...', 'info');
        
        // In a real application, this would be an API call
        setTimeout(() => {
            showNotification('Account created successfully! You can now login.', 'success');
            
            // Switch to login form
            registerForm.classList.add('hidden');
            loginForm.classList.remove('hidden');
            
            // Pre-fill email in login form
            document.getElementById('login-email').value = email;
        }, 1500);
    }

    // Simulate Password Reset Process
    function simulatePasswordReset(email) {
        showNotification('Sending reset instructions...', 'info');
        
        // In a real application, this would be an API call
        setTimeout(() => {
            showNotification('Password reset instructions sent to your email', 'success');
            
            // Switch back to login form
            forgotForm.classList.add('hidden');
            loginForm.classList.remove('hidden');
        }, 1500);
    }

    // Notification System
    function showNotification(message, type) {
        // Remove any existing notifications
        const existingNotification = document.querySelector('.notification');
        if (existingNotification) {
            existingNotification.remove();
        }
        
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.textContent = message;
        
        // Add to page
        document.body.appendChild(notification);
        
        // Show notification
        setTimeout(() => {
            notification.classList.add('show');
        }, 10);
        
        // Hide after 3 seconds
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => {
                notification.remove();
            }, 300);
        }, 3000);
    }

    // Check if user previously selected "Remember me"
    window.addEventListener('load', function() {
        if (localStorage.getItem('rememberMe') === 'true') {
            const savedEmail = localStorage.getItem('adminEmail');
            const savedName = localStorage.getItem('adminName');
            
            if (savedEmail) {
                document.getElementById('login-email').value = savedEmail;
                document.getElementById('remember-me').checked = true;
                
                // Auto-login if remember me was checked
                showNotification('Logging you in automatically...', 'info');
                
                setTimeout(() => {
                    adminNameSpan.textContent = savedName || 'Admin User';
                    authContainer.style.display = 'none';
                    dashboardContainer.style.display = 'flex';
                    showNotification('Welcome back!', 'success');
                }, 1000);
            }
        }
    });
});