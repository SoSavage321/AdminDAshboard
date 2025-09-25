document.addEventListener('DOMContentLoaded', function () {
    // DOM Elements
    const authContainer = document.getElementById('auth-container');
    const dashboardContainer = document.getElementById('dashboard-container');

    const loginForm = document.getElementById('login');
    const registerForm = document.getElementById('register');
    const forgotForm = document.getElementById('forgot-password-form');
    const addTeacherForm = document.getElementById('add-teacher-form');

    const registerPassword = document.getElementById('register-password');
    const passwordStrengthBar = document.querySelector('.strength-bar');
    const passwordStrengthText = document.querySelector('.strength-text');

    // Normalization helper (moved to top-level so other handlers can use it)
    function normalizeInput(s) {
        if (typeof s !== 'string') return s;
        let cleaned = s
            .replace(/\u00A0|\u2007|\u202F/g, ' ')
            .replace(/[\u200B-\u200F\uFEFF]/g, '')
            .normalize('NFKC');
        // Collapse any sequence of whitespace (including tabs/newlines/unicode spaces) to a single space
        cleaned = cleaned.replace(/\s+/g, ' ').trim();
        return cleaned;
    }

    const showRegisterBtn = document.getElementById('show-register');
    const showLoginBtn = document.getElementById('show-login');
    const backToLoginBtn = document.getElementById('back-to-login');
    const forgotLink = document.getElementById('forgot-password');
    const forgotModal = document.getElementById('forgot-modal');
    const forgotModalForm = document.getElementById('forgot-modal-form');
    const forgotModalEmail = document.getElementById('forgot-modal-email');
    const forgotModalCancel = document.getElementById('forgot-modal-cancel');

    const usersTableBody = document.getElementById("users-table-body");// Make sure your table has id="users-table"

    /** ---------------- SPA Form Switching ---------------- */
    function showForm(formId) {
        document.querySelectorAll('.auth-form').forEach(f => f.classList.add('hidden'));
        const form = document.getElementById(formId);
        if (form) form.classList.remove('hidden');
    }

    // Helper to send Firebase password reset via REST API
    async function sendResetEmail(email) {
        if (!email) { showNotification('Enter your email', 'error'); return; }
        try {
            console.debug('Sending password reset for', email);
            const apiKey = 'AIzaSyCp-VbOO8Eu9PJwIwdIdx7GZRj3mKJFI0U';
            const endpoint = `https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=${apiKey}`;
            const payload = { requestType: 'PASSWORD_RESET', email };

            const res = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            const data = await res.json();
            if (!res.ok) {
                const msg = (data && data.error && data.error.message) ? data.error.message : 'Failed to send reset email';
                console.error('Firebase reset error', data);
                showNotification(msg, 'error');
            } else {
                showNotification('If that email exists, a password reset link has been sent.', 'success');
                const form = document.getElementById('forgot-password-form');
                try { if (form) form.reset(); } catch(e){}
            }
        } catch (err) {
            console.error('Error sending reset email', err);
            showNotification('Error sending reset email. Try again later.', 'error');
        }
    }

    if (showRegisterBtn) showRegisterBtn.addEventListener('click', e => { e.preventDefault(); showForm('register-form'); });
    if (showLoginBtn) showLoginBtn.addEventListener('click', e => { e.preventDefault(); showForm('login-form'); });
    if (backToLoginBtn) backToLoginBtn.addEventListener('click', e => { e.preventDefault(); showForm('login-form'); });
    if (forgotLink) forgotLink.addEventListener('click', function (e) {
        e.preventDefault();
        // Open in-page modal
        if (forgotModal) {
            forgotModal.classList.remove('hidden');
            setTimeout(() => { if (forgotModalEmail) forgotModalEmail.focus(); }, 50);
        } else {
            // Fallback to prompt
            const email = window.prompt('Please enter your email to receive a password reset link:');
            if (email) sendResetEmail(email.trim());
        }
    });

    // Modal handlers
    if (forgotModal) {
        // close when clicking overlay outside the modal
        forgotModal.addEventListener('click', function (e) {
            if (e.target === forgotModal) {
                forgotModal.classList.add('hidden');
            }
        });
    }
    if (forgotModalCancel) {
        forgotModalCancel.addEventListener('click', function () { if (forgotModal) forgotModal.classList.add('hidden'); });
    }
    if (forgotModalForm) {
        forgotModalForm.addEventListener('submit', function (e) {
            e.preventDefault();
            const email = forgotModalEmail ? forgotModalEmail.value.trim() : '';
            if (email) {
                sendResetEmail(email);
                if (forgotModal) forgotModal.classList.add('hidden');
            }
        });
    }

    /** ---------------- Show Dashboard if Logged In ---------------- */
    const token = localStorage.getItem('idToken');
    if (token) {
        authContainer.style.display = 'none';
        dashboardContainer.style.display = 'flex';
        document.getElementById('admin-name').textContent = localStorage.getItem('adminFullName') || localStorage.getItem('adminEmail');
        loadUsers();
    }

    /** ---------------- Password Strength + Normalization ---------------- */
    if (registerPassword) {
        registerPassword.addEventListener('input', function () {
            // sanitize password input live to remove invisible characters
            const cleaned = normalizeInput(this.value);
            if (this.value !== cleaned) this.value = cleaned;

            // now check strength AFTER cleaning
            const password = this.value;
            const strength = checkPasswordStrength(password);
            passwordStrengthBar.style.width = strength.percentage + '%';
            passwordStrengthBar.style.background = strength.color;
            passwordStrengthText.textContent = strength.text;
        });
    }

    // Also sanitize confirm password field if it exists
    const registerConfirm = document.getElementById('register-confirm-password');
    if (registerConfirm) {
        registerConfirm.addEventListener('input', function () {
            const cleaned = normalizeInput(this.value);
            if (this.value !== cleaned) this.value = cleaned;
        });
    }

    /** ---------------- Registration ---------------- */
    if (registerForm) {
        registerForm.addEventListener('submit', async function (e) {
            e.preventDefault();
            const fullName = document.getElementById('register-name').value.trim();
            const email = document.getElementById('register-email').value.trim();
            const passwordRaw = document.getElementById('register-password').value;
            const confirmRaw = document.getElementById('register-confirm-password').value;
            const adminKey = document.getElementById('admin-key').value;
            const agreeTerms = document.getElementById('terms-agree').checked;

            if (!fullName || !email || !passwordRaw || !confirmRaw || !adminKey) {
                showNotification('Please fill all fields', 'error');
                return;
            }

            // Normalize and sanitize passwords
            const p1 = normalizeInput(passwordRaw);
            const p2 = normalizeInput(confirmRaw);

            let passwordFinal;
            if (p1 === p2) {
                passwordFinal = p1;
            } else if (p1.trim() === p2.trim()) {
                passwordFinal = p1.trim();
                showNotification('Passwords matched after trimming spaces. Please avoid accidental spaces.', 'warning');
            } else {
                // Log useful debug info to console (no DOM debug panel)
                try {
                    const codes1 = Array.from(p1).map(c => c.charCodeAt(0));
                    const codes2 = Array.from(p2).map(c => c.charCodeAt(0));
                    console.debug('Registration password mismatch', {
                        passwordRaw,
                        confirmRaw,
                        normalizedP1: p1,
                        normalizedP2: p2,
                        p1Len: p1.length,
                        p2Len: p2.length,
                        p1Codes: codes1,
                        p2Codes: codes2
                    });
                } catch (e) {
                    console.debug('Registration password mismatch (failed to compute codes)', e);
                }
                showNotification('Passwords do not match', 'error');
                return;
            }

            if (!agreeTerms) {
                showNotification('You must agree to the terms', 'error');
                return;
            }

            try {
                const payload = {
                    fullName,
                    email: email.trim(),
                    password: passwordFinal,
                    adminKey: adminKey.trim()
                };

                const res = await fetch('http://localhost:5000/api/register', {
                    method: 'POST',
                    headers: {'Content-Type':'application/json'},
                    body: JSON.stringify(payload)
                });

                const data = await res.json();
                if (!res.ok) showNotification(data.error || 'Registration failed', 'error');
                else {
                    showNotification(data.message || 'Registration successful', 'success');
                    registerForm.reset();
                    setTimeout(() => { showForm('login-form'); }, 1500);
                }
            } catch(err) {
                console.error(err);
                showNotification('Server error. Try again later.', 'error');
            }
        });
    }

    /** ---------------- Login ---------------- */
    if (loginForm) {
        loginForm.addEventListener('submit', async function (e) {
            e.preventDefault();
            const email = document.getElementById('login-email').value.trim();
            const password = document.getElementById('login-password').value;

            if (!email || !password) { showNotification('Enter both email and password', 'error'); return; }

            try {
                const res = await fetch('http://localhost:5000/api/login', {
                    method: 'POST',
                    headers: {'Content-Type':'application/json'},
                    body: JSON.stringify({email, password})
                });
                const data = await res.json();

                if (!res.ok) showNotification(data.error || 'Login failed', 'error');
                else {
                    showNotification(data.message || 'Login successful', 'success');
                    localStorage.setItem('idToken', data.idToken);
                    localStorage.setItem('adminEmail', data.email || email);
                    localStorage.setItem('adminFullName', data.fullName || '');

                    setTimeout(() => {
                        authContainer.style.display = 'none';
                        dashboardContainer.style.display = 'flex';
                        document.getElementById('admin-name').textContent = data.fullName || data.email || email;
                        loadUsers();
                    }, 500);
                }
            } catch(err) {
                console.error(err);
                showNotification('Server error. Try again later.', 'error');
            }
        });
    }

    /** ---------------- Forgot Password ---------------- */
    if (forgotForm) {
        // helper to call Firebase REST API
        async function sendResetEmail(email) {
            if (!email) { showNotification('Enter your email', 'error'); return; }
            try {
                console.debug('Sending password reset for', email);
                const apiKey = 'AIzaSyCp-VbOO8Eu9PJwIwdIdx7GZRj3mKJFI0U';
                const endpoint = `https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=${apiKey}`;
                const payload = { requestType: 'PASSWORD_RESET', email };

                const res = await fetch(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });

                const data = await res.json();
                if (!res.ok) {
                    const msg = (data && data.error && data.error.message) ? data.error.message : 'Failed to send reset email';
                    console.error('Firebase reset error', data);
                    showNotification(msg, 'error');
                } else {
                    showNotification('If that email exists, a password reset link has been sent.', 'success');
                    try { forgotForm.reset(); } catch(e){}
                }
            } catch (err) {
                console.error('Error sending reset email', err);
                showNotification('Error sending reset email. Try again later.', 'error');
            }
        }

        // Attach submit handler
        forgotForm.addEventListener('submit', function (e) {
            e.preventDefault();
            const email = document.getElementById('reset-email') ? document.getElementById('reset-email').value.trim() : '';
            sendResetEmail(email);
        });

        // Fallback: attach click handler to the button inside the form (in case submit is prevented)
        const forgotBtn = forgotForm.querySelector('button[type="submit"]');
        if (forgotBtn) {
            forgotBtn.addEventListener('click', function (e) {
                // allow submit handler to run; but also call explicitly after a short tick if default prevented
                setTimeout(() => {
                    if (document.activeElement === forgotBtn) {
                        const email = document.getElementById('reset-email') ? document.getElementById('reset-email').value.trim() : '';
                        sendResetEmail(email);
                    }
                }, 20);
            });
        }
    }

    /** ---------------- Add Teacher ---------------- */
    if (addTeacherForm) {
        addTeacherForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const fullName = document.getElementById('teacher-name').value.trim();
            const email = document.getElementById('teacher-email').value.trim();

            if (!fullName || !email) {
                showNotification('Enter both teacher name and email', 'error');
                return;
            }

            try {
                const res = await fetch('http://localhost:5000/api/teachers', {
                    method: 'POST',
                    headers: {'Content-Type':'application/json'},
                    body: JSON.stringify({fullName, email})
                });

                // Robustly parse response: prefer JSON, fall back to text
                const contentType = res.headers.get('content-type') || '';
                let data = null;
                if (contentType.includes('application/json')) {
                    try { data = await res.json(); } catch(e) { data = null; }
                } else {
                    try { const text = await res.text(); data = { text }; } catch(e) { data = null; }
                }

                console.debug('Add teacher response', res, data);
                if (!res.ok) {
                    let msg = `Failed to add teacher (status ${res.status})`;
                    if (data) {
                        if (typeof data === 'object') msg = data.error || data.message || data.text || JSON.stringify(data);
                        else msg = String(data);
                    }
                    showNotification(msg, 'error');
                } else {
                    let msg = `Teacher ${fullName} added successfully!`;
                    if (data) {
                        if (typeof data === 'object') msg = data.message || data.text || JSON.stringify(data);
                        else msg = String(data);
                    }
                    showNotification(msg, 'success');
                    addTeacherForm.reset();
                    loadUsers();
                }
            } catch(err) {
                console.error(err);
                showNotification('Server error. Try again later.', 'error');
            }
        });
    }

    /** ---------------- Logout ---------------- */
    document.body.addEventListener('click', function(e){
        if(e.target && e.target.id === 'logout-btn') {
            localStorage.removeItem('idToken');
            localStorage.removeItem('adminEmail');
            localStorage.removeItem('adminFullName');

            dashboardContainer.style.display = 'none';
            authContainer.style.display = 'flex';
            showForm('login-form');
        }
    });

    /** ---------------- Load Users & Teachers ---------------- */
    async function loadUsers() {
        if (!usersTableBody) {
            console.error("❌ usersTableBody not found in DOM");
            return;
        }

        try {
            const res = await fetch('http://localhost:5000/api/users');
            const data = await res.json();
            console.log("Fetched users:", data);

            usersTableBody.innerHTML = "";

            if (!data.users || data.users.length === 0) {
                usersTableBody.innerHTML = `<tr><td colspan="7">No users found</td></tr>`;
                return;
            }

            data.users.forEach(user => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${user.fullName || "-"}</td>
                    <td>${user.role}</td>
                    <td>${user.grade || "-"}</td>
                    <td>${user.school || "-"}</td>
                    <td>${user.lastActive || "Never"}</td>
                    <td><span class="status ${user.status === 'active' ? 'active' : 'inactive'}">${user.status}</span></td>
                    <td>
                        <button class="btn-sm">Edit</button>
                        <button class="btn-sm btn-danger">Delete</button>
                    </td>
                `;
                usersTableBody.appendChild(tr);
            });
        } catch(err) {
            console.error("Error loading users:", err);
            usersTableBody.innerHTML = `<tr><td colspan="7">Error loading users</td></tr>`;
        }
    }

    /** ---------------- Load Bug Reports ---------------- */
    async function loadBugReports() {
        const container = document.getElementById('report-list');
        if (!container) {
            console.error('❌ #report-list element not found');
            return;
        }

        container.innerHTML = '<p>Loading reports...</p>';

        try {
            const res = await fetch('http://localhost:5000/api/bug-reports');
            const contentType = res.headers.get('content-type') || '';
            let payload = null;
            if (contentType.includes('application/json')) {
                payload = await res.json();
            } else {
                const text = await res.text();
                try { payload = JSON.parse(text); } catch(e) { payload = { error: text }; }
            }

            if (!res.ok) {
                const errMsg = payload && (payload.error || payload.message) ? (payload.error || payload.message) : `Failed to fetch reports (status ${res.status})`;
                container.innerHTML = `<p class="error">${escapeHtml(errMsg)}</p>`;
                return;
            }

            const reports = (payload && Array.isArray(payload.bugReports)) ? payload.bugReports : [];
            if (reports.length === 0) {
                container.innerHTML = '<p>No bug reports found.</p>';
                return;
            }

            // Render list
            container.innerHTML = '';
            reports.forEach(r => {
                const card = document.createElement('div');
                card.className = 'report-card';
                const ts = r.timestamp ? (typeof r.timestamp === 'string' ? new Date(r.timestamp) : new Date(r.timestamp)) : null;
                const header = document.createElement('div');
                header.className = 'report-header';
                header.innerHTML = `<strong>Report${r.id ? ' #' + escapeHtml(String(r.id)) : ''}</strong>` +
                                   (ts ? ` <span class="muted">${escapeHtml(ts.toLocaleString())}</span>` : '');

                const body = document.createElement('div');
                body.className = 'report-body';

                // Show common fields (flexible)
                const keys = Object.keys(r).filter(k => k !== 'id' && k !== 'timestamp');
                if (keys.length === 0) {
                    body.innerHTML = '<div>(no details)</div>';
                } else {
                    keys.forEach(k => {
                        const row = document.createElement('div');
                        row.className = 'report-row';
                        const label = document.createElement('div');
                        label.className = 'report-key';
                        label.textContent = k;
                        const val = document.createElement('div');
                        val.className = 'report-val';
                        // stringify objects
                        let v = r[k];
                        if (v === null || v === undefined) v = '';
                        else if (typeof v === 'object') v = JSON.stringify(v);
                        row.appendChild(label);
                        val.textContent = String(v);
                        row.appendChild(val);
                        body.appendChild(row);
                    });
                }

                card.appendChild(header);
                card.appendChild(body);
                container.appendChild(card);
            });

        } catch (err) {
            console.error('Error loading bug reports', err);
            container.innerHTML = `<p class="error">Error loading reports. See console for details.</p>`;
        }
    }

    // Small html escaper to prevent accidental injection when inserting server text
    function escapeHtml(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    // Hook reports nav click to load reports when opened
    const navLinks = document.querySelectorAll('.nav-menu a[data-section]');
    navLinks.forEach(link => {
        link.addEventListener('click', function (e) {
            const sectionId = this.getAttribute('data-section');
            if (sectionId === 'reports') {
                // slight delay to allow section to become active
                setTimeout(loadBugReports, 50);
            }
        });
    });

    /** ---------------- Helper Functions ---------------- */
    function checkPasswordStrength(password) {
        let strength=0, text='', color='#e74c3c';
        if(password.length>=8) strength++;
        if(password.match(/[a-z]+/)) strength++;
        if(password.match(/[A-Z]+/)) strength++;
        if(password.match(/[0-9]+/)) strength++;
        if(password.match(/[!@#$%^&*(),.?":{}|<>]+/)) strength++;
        switch(strength){
            case 0: case 1: case 2: text='Weak'; color='#e74c3c'; break;
            case 3: text='Medium'; color='#f39c12'; break;
            case 4: text='Strong'; color='#27ae60'; break;
            case 5: text='Very Strong'; color='#2ecc71'; break;
        }
        return {percentage: (strength/5)*100, text, color};
    }

    function showNotification(message,type='info'){
        const existing = document.querySelector('.notification');
        if(existing) existing.remove();
        const notif = document.createElement('div');
        notif.className = `notification ${type}`;
        // If message is object, try to extract useful text
        if (typeof message === 'object' && message !== null) {
            try {
                notif.textContent = message.message || JSON.stringify(message);
            } catch(e){ notif.textContent = String(message); }
        } else {
            notif.textContent = String(message);
        }
        document.body.appendChild(notif);
        setTimeout(()=> notif.classList.add('show'),10);
        setTimeout(()=> { notif.classList.remove('show'); setTimeout(()=>notif.remove(),300); },3000);
    }

    // Sidebar navigation functionality
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const sectionId = this.getAttribute('data-section');
            
            // Remove active class from all links and sections
            navLinks.forEach(l => l.classList.remove('active'));
            document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
            
            // Add active class to clicked link
            this.classList.add('active');
            
            // Show target section
            const targetSection = document.getElementById(sectionId);
            if (targetSection) {
                targetSection.classList.add('active');
                
                // Load specific data based on section
                if (sectionId === 'reports') {
                    setTimeout(loadBugReports, 50);
                } else if (sectionId === 'users') {
                    loadUsers();
                }
            }
        });
    });

});