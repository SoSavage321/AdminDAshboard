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
    // Saved login card reference when removed from DOM
    let _savedLoginCard = null;

    function showForm(formId) {
        // Hide all auth-form panels
        document.querySelectorAll('.auth-form').forEach(f => f.classList.add('hidden'));

        const loginCard = document.getElementById('login-form');

        // If showing login, reattach the saved login card (if it was removed)
        if (formId === 'login-form') {
            if (!loginCard && _savedLoginCard && authContainer) {
                // insert at the top of authContainer
                authContainer.insertBefore(_savedLoginCard, authContainer.firstChild);
            }
            const card = document.getElementById('login-form');
            if (card) card.classList.remove('hidden');
            return;
        }

        // For non-login forms: ensure the login card is physically removed from the DOM
        if (loginCard) {
            _savedLoginCard = loginCard;
            try {
                loginCard.parentNode.removeChild(loginCard);
            } catch (e) {
                // fallback to hide if removal fails
                loginCard.classList.add('hidden');
            }
        }

        // Show the requested auth-form (register, forgot, etc.)
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
        loadDashboardStats();
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
                    localStorage.setItem('refreshToken', data.refreshToken || '');
                    localStorage.setItem('expiresIn', data.expiresIn || '');
                    localStorage.setItem('tokenTimestamp', String(Date.now()));
                    localStorage.setItem('adminEmail', data.email || email);
                    localStorage.setItem('adminFullName', data.fullName || '');

                    setTimeout(() => {
                        authContainer.style.display = 'none';
                        dashboardContainer.style.display = 'flex';
                        document.getElementById('admin-name').textContent = data.fullName || data.email || email;
                            loadUsers();
                            loadDashboardStats();
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
                    loadDashboardStats();
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
                usersTableBody.innerHTML = `<tr><td colspan="6">No users found</td></tr>`;
                return;
            }

            data.users.forEach(user => {
                const tr = document.createElement('tr');

                // determine lastActive timestamp robustly
                let lastActiveMs = 0;
                if (user.lastActive != null) {
                    // Firestore timestamps may come as numbers, ISO strings, or objects
                    if (typeof user.lastActive === 'number') lastActiveMs = Number(user.lastActive);
                    else if (typeof user.lastActive === 'string') {
                        const parsed = Date.parse(user.lastActive);
                        lastActiveMs = Number.isNaN(parsed) ? 0 : parsed;
                    } else if (user.lastActive._seconds) {
                        lastActiveMs = Number(user.lastActive._seconds) * 1000;
                    } else if (typeof user.lastActive.toDate === 'function') {
                        try { lastActiveMs = new Date(user.lastActive.toDate()).getTime(); } catch(e) { lastActiveMs = 0; }
                    }
                }
                const isOnline = lastActiveMs > 0 && (Date.now() - lastActiveMs) <= (5 * 60 * 1000);
                const statusHtml = isOnline ? `<span class="status active">Online</span>` : `<span class="status inactive">Offline</span>`;

                tr.setAttribute('data-id', String(user.id || ''));
                tr.innerHTML = `
                    <td>${user.name || user.fullName || user.displayName || user.email || "-"}</td>
                    <td>${user.role}</td>
                    <td>${user.grade || "-"}</td>
                    <td>${user.school || "-"}</td>
                    <td>${statusHtml}</td>
                    <td>
                        <button class="btn-sm">Edit</button>
                        <button class="btn-sm btn-danger" data-id="${user.id}">Delete</button>
                    </td>
                `;
                usersTableBody.appendChild(tr);
            });
        } catch(err) {
            console.error("Error loading users:", err);
            usersTableBody.innerHTML = `<tr><td colspan="6">Error loading users</td></tr>`;
        }
    }

    // Helper to refresh idToken if expired
    async function getValidIdToken() {
        const token = localStorage.getItem('idToken');
        const refreshToken = localStorage.getItem('refreshToken');
        const expiresIn = parseInt(localStorage.getItem('expiresIn') || '3600', 10);
        const tokenTimestamp = parseInt(localStorage.getItem('tokenTimestamp') || '0', 10);
        const ageSeconds = (Date.now() - tokenTimestamp) / 1000;

        console.log('Token age:', ageSeconds, 'seconds. Expires in:', expiresIn, 'seconds');

        // If token is more than 80% through its lifetime, refresh it
        if (ageSeconds > expiresIn * 0.8 && refreshToken) {
            console.log('Token is stale, refreshing...');
            try {
                // Try the simpler refresh endpoint
                const simpleRefresh = await fetch(
                    'https://securetoken.googleapis.com/v1/accounts:signInWithRefreshToken?key=AIzaSyCp-VbOO8Eu9PJwIwdIdx7GZRj3mKJFI0U',
                    {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            grant_type: 'refresh_token',
                            refresh_token: refreshToken
                        })
                    }
                );

                if (simpleRefresh.ok) {
                    const freshData = await simpleRefresh.json();
                    const newToken = freshData.id_token || freshData.idToken;
                    if (newToken) {
                        console.log('Token refreshed successfully');
                        localStorage.setItem('idToken', newToken);
                        localStorage.setItem('tokenTimestamp', String(Date.now()));
                        return newToken;
                    }
                }
            } catch (err) {
                console.warn('Token refresh failed, will try with current token', err);
            }
        }

        return token;
    }

        // Delegate click handler for Delete buttons in the users table
        if (usersTableBody) {
            usersTableBody.addEventListener('click', async function (e) {
                const btn = e.target.closest && e.target.closest('.btn-danger');
                if (!btn) return;
                const id = btn.dataset.id || (btn.closest && btn.closest('tr') && btn.closest('tr').dataset.id);
                if (!id) {
                    showNotification('Unable to determine user id to delete', 'error');
                    return;
                }
                if (!confirm('Are you sure you want to delete this user? This action cannot be undone.')) return;

                try {
                    const headers = {};
                    let token = localStorage.getItem('idToken');
                    console.log('Delete request for user:', id, 'Token present:', !!token);
                    
                    if (token) {
                        // Try to refresh if stale
                        token = await getValidIdToken();
                        headers['Authorization'] = 'Bearer ' + token;
                        console.log('Sending Authorization header with token');
                    } else {
                        // Fallback: use hardcoded ADMIN_KEY for testing (since token may not have claims)
                        // In production, require user to be logged in with valid idToken
                        const adminKey = '123456';  // TODO: move this to env or config
                        headers['x-admin-key'] = adminKey;
                        console.log('Using x-admin-key fallback (no idToken)');
                    }

                    console.log('DELETE request headers:', Object.keys(headers));
                    const res = await fetch(`http://localhost:5000/api/users/${encodeURIComponent(id)}`, {
                        method: 'DELETE',
                        headers
                    });

                    console.log('DELETE response status:', res.status);
                    const ct = res.headers.get('content-type') || '';
                    let body = null;
                    if (ct.includes('application/json')) {
                        body = await res.json();
                    } else {
                        body = await res.text();
                    }

                    console.log('DELETE response body:', body);
                    if (!res.ok) {
                        const msg = (body && body.error) ? body.error : (typeof body === 'string' ? body : 'Delete failed');
                        showNotification(`Delete failed: ${msg}`, 'error');
                        return;
                    }

                    showNotification('User deleted successfully', 'success');
                    // refresh UI
                    loadUsers();
                    loadDashboardStats();
                } catch (err) {
                    console.error('Error deleting user', err);
                    showNotification('Error deleting user. See console for details.', 'error');
                }
            });
        }

    // ---------------- Dashboard Stats ----------------
    async function loadDashboardStats() {
        const el = document.getElementById('total-users');
        if (!el) return;
        try {
            // By default /api/users returns Firestore users only (no includeAuth)
            const res = await fetch('http://localhost:5000/api/users');
            if (!res.ok) {
                console.error('Failed to fetch users for dashboard stat');
                return;
            }
            const payload = await res.json();
            const users = Array.isArray(payload.users) ? payload.users : (payload.users || []);
            el.textContent = String(users.length);
            // Compute average score across learners who have numeric scores
            try {
                const avgEl = document.getElementById('avg-score');
                if (avgEl) {
                    // filter learners only
                    const learners = users.filter(u => {
                        const r = (u.role || '').toString().toLowerCase();
                        return r === 'learner' || r.includes('student') || (!u.role && u.email);
                    });
                    let sum = 0;
                    let count = 0;
                    learners.forEach(u => {
                        // reuse helper to get a numeric score from the user object
                        const s = (typeof getScoreFromUser === 'function') ? getScoreFromUser(u) : (Number(u.totalScore) || 0);
                        if (s != null && !Number.isNaN(s) && Number(s) > 0) {
                            sum += Number(s);
                            count++;
                        }
                    });
                    const avg = count > 0 ? (sum / count) : 0;
                    // show with one decimal and percent sign
                    avgEl.textContent = `${avg.toFixed(1)}%`;
                }
            } catch (err) {
                console.error('Error computing average score', err);
            }
            // Compute users active today (lastActive timestamp is today)
            try {
                const activeTodayEl = document.getElementById('active-today');
                if (activeTodayEl) {
                    const today = new Date();
                    today.setHours(0, 0, 0, 0);
                    const tomorrow = new Date(today);
                    tomorrow.setDate(tomorrow.getDate() + 1);

                    const activeTodayCount = users.filter(user => {
                        if (!user.lastActive) return false;
                        let lastActiveMs = 0;
                        // Parse lastActive in multiple formats (same logic as loadUsers)
                        if (typeof user.lastActive === 'number') lastActiveMs = Number(user.lastActive);
                        else if (typeof user.lastActive === 'string') {
                            const parsed = Date.parse(user.lastActive);
                            lastActiveMs = Number.isNaN(parsed) ? 0 : parsed;
                        } else if (user.lastActive._seconds) {
                            lastActiveMs = Number(user.lastActive._seconds) * 1000;
                        } else if (typeof user.lastActive.toDate === 'function') {
                            try { lastActiveMs = new Date(user.lastActive.toDate()).getTime(); } catch(e) { lastActiveMs = 0; }
                        }
                        if (lastActiveMs === 0) return false;
                        const lastActiveDate = new Date(lastActiveMs);
                        return lastActiveDate >= today && lastActiveDate < tomorrow;
                    }).length;

                    activeTodayEl.textContent = String(activeTodayCount);
                }
            } catch (err) {
                console.error('Error computing active today count', err);
            }
            // Fetch progress aggregation to compute total quizzes completed for dashboard
            try {
                const quizzesEl = document.getElementById('quizzes-completed');
                if (quizzesEl) {
                    const pr = await fetch('http://localhost:5000/api/progress');
                    if (pr.ok) {
                        const payload = await pr.json();
                        const progress = Array.isArray(payload.progress) ? payload.progress : (payload.progress || []);
                        const totalQuizzes = progress.reduce((acc, p) => acc + (Number(p.quizzesCompleted) || 0), 0);
                        quizzesEl.textContent = String(totalQuizzes);
                    } else {
                        // leave blank or show 0 on failure
                        quizzesEl.textContent = '0';
                    }
                }
            } catch (err) {
                console.error('Error fetching progress for dashboard quizzes count', err);
            }
        } catch (err) {
            console.error('Error loading dashboard stats', err);
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

    /** ---------------- Server-backed Leaderboard ---------------- */
    // Render a simple leaderboard list (name + score + optional school)
    function renderLeaderboardFromServer(entries) {
        const container = document.getElementById('leaderboard-list');
        if (!container) return console.error('❌ #leaderboard-list not found');
        container.innerHTML = '';

        if (!entries || entries.length === 0) {
            container.innerHTML = '<p class="muted">No leaderboard entries found.</p>';
            return;
        }

        entries.forEach((e, idx) => {
            const item = document.createElement('div');
            item.className = 'activity-item leaderboard-item';

            const avatar = document.createElement('div');
            avatar.className = 'activity-avatar';
            const initials = (e.name || '').split(' ').slice(0,2).map(s=>s[0]||'').join('').toUpperCase() || 'U';
            avatar.textContent = initials;

            const content = document.createElement('div');
            content.className = 'activity-content';
            const title = document.createElement('h4');
            title.textContent = `${idx + 1}. ${e.name || 'Unknown'}`;
            const meta = document.createElement('p');
            meta.textContent = e.school ? `${e.school} • Score: ${e.score}` : `Score: ${e.score}`;
            content.appendChild(title);
            content.appendChild(meta);

            const scoreEl = document.createElement('div');
            scoreEl.className = 'activity-time';
            scoreEl.textContent = String(e.score != null ? e.score : '0');

            item.appendChild(avatar);
            item.appendChild(content);
            item.appendChild(scoreEl);
            container.appendChild(item);
        });
    }

    // Load learners from /api/users, then fetch per-learner score from /api/users/:id/score
    async function loadLeaderboardFromServer(limit = 10) {
        const container = document.getElementById('leaderboard-list');
        if (!container) return console.error('❌ #leaderboard-list not found');
        container.innerHTML = '<p class="muted">Loading leaderboard...</p>';

        try {
            const res = await fetch('http://localhost:5000/api/users');
            if (!res.ok) {
                container.innerHTML = '<p class="error">Failed to fetch users for leaderboard.</p>';
                return;
            }
            const payload = await res.json();
            const users = Array.isArray(payload.users) ? payload.users : (Array.isArray(payload) ? payload : (payload.users || []));

            // Only learners (server tags users with role: 'learner')
            const learners = users.filter(u => {
                const r = (u.role || '').toString().toLowerCase();
                return r === 'learner' || r.includes('student') || (!u.role && u.email); // fallback assume users collection are learners
            });

            // Map id -> user for school lookup
            const userById = {};
            learners.forEach(u => { userById[u.id] = u; });

            // Fetch scores concurrently (but keep requests reasonable)
            const scorePromises = learners.map(u =>
                fetch(`http://localhost:5000/api/users/${encodeURIComponent(u.id)}/score`).then(r => {
                    if (!r.ok) return { id: u.id, name: u.fullName || u.displayName || u.email, totalScore: 0 };
                    return r.json();
                }).catch(() => ({ id: u.id, name: u.fullName || u.displayName || u.email, totalScore: 0 }))
            );

            const scores = await Promise.all(scorePromises);

            const merged = scores.map(s => {
                const id = s.id || s.userId || null;
                const user = id && userById[id] ? userById[id] : learners.find(x => x.id === id) || {};
                return {
                    id: id || user.id,
                    name: s.name || user.fullName || user.displayName || user.email || 'Unknown',
                    school: user.school || user.schoolName || user.school_id || '',
                    score: Number(s.totalScore || s.score || 0) || 0
                };
            });

            merged.sort((a,b) => (b.score || 0) - (a.score || 0));
            renderLeaderboardFromServer(merged.slice(0, limit));

        } catch (err) {
            console.error('Error loading leaderboard from server', err);
            container.innerHTML = '<p class="error">Error loading leaderboard.</p>';
        }
    }

    /** ---------------- Leaderboard ---------------- */
    // Try to render a friendly leaderboard into #leaderboard-list
    function renderLeaderboard(entries) {
        const container = document.getElementById('leaderboard-list');
        if (!container) return console.error('❌ #leaderboard-list not found');

        container.innerHTML = '';
        if (!entries || entries.length === 0) {
            container.innerHTML = '<p class="muted">No leaderboard entries found.</p>';
            return;
        }
        // Top 3 highlighted
        const top = entries.slice(0,3);
        const others = entries.slice(3);

        const topWrap = document.createElement('div');
        topWrap.className = 'leaderboard-top';
        top.forEach((e, idx) => {
            const card = document.createElement('div');
            card.className = 'top-card';

            const rank = document.createElement('div');
            rank.className = `top-rank rank-${idx+1}`;
            rank.textContent = `${idx+1}`;

            const avatar = document.createElement('div');
            avatar.className = 'top-avatar';
            const initials = (e.name || 'U').split(' ').slice(0,2).map(s=>s[0]||'').join('').toUpperCase();
            avatar.textContent = initials || 'U';

            const nameEl = document.createElement('div');
            nameEl.className = 'top-name';
            nameEl.textContent = e.name || 'Unknown';

            const schoolEl = document.createElement('div');
            schoolEl.className = 'top-school';
            schoolEl.textContent = e.school || e.schoolName || e.school_id || '';

            const scoreEl = document.createElement('div');
            scoreEl.className = 'top-score';
            scoreEl.textContent = String(e.score != null ? e.score : 0);

            card.appendChild(rank);
            card.appendChild(avatar);
            card.appendChild(nameEl);
            card.appendChild(schoolEl);
            card.appendChild(scoreEl);
            topWrap.appendChild(card);
        });
        container.appendChild(topWrap);

        if (others.length > 0) {
            const listWrap = document.createElement('div');
            listWrap.className = 'leaderboard-list-others';
            others.forEach((e, idx) => {
                const item = document.createElement('div');
                item.className = 'activity-item leaderboard-item small';

                const avatar = document.createElement('div');
                avatar.className = 'activity-avatar';
                const initials = (e.name || 'U').split(' ').slice(0,2).map(s=>s[0]||'').join('').toUpperCase();
                avatar.textContent = initials || 'U';

                const content = document.createElement('div');
                content.className = 'activity-content';
                const title = document.createElement('h4');
                title.textContent = `${idx + 4}. ${e.name || 'Unknown'}`;
                const meta = document.createElement('p');
                meta.textContent = `${e.school ? e.school + ' • ' : ''}Score: ${e.score != null ? e.score : 0}`;
                content.appendChild(title);
                content.appendChild(meta);

                const time = document.createElement('div');
                time.className = 'activity-time';
                time.textContent = String(e.score != null ? e.score : '0');

                item.appendChild(avatar);
                item.appendChild(content);
                item.appendChild(time);
                listWrap.appendChild(item);
            });
            container.appendChild(listWrap);
        }
    }

    // Heuristic: look for common numeric score fields on a user object
    function getScoreFromUser(u) {
        if (!u) return 0;
        const keys = ['totalScore','score','points','xp','experience','total_points','totalxp','totalScorePoints'];
        for (const k of keys) {
            if (Object.prototype.hasOwnProperty.call(u, k) && u[k] != null) {
                const v = Number(u[k]);
                if (!Number.isNaN(v)) return v;
            }
        }
        // try nested stats object
        if (u.stats && typeof u.stats === 'object') {
            for (const k of keys) {
                if (Object.prototype.hasOwnProperty.call(u.stats, k) && u.stats[k] != null) {
                    const v = Number(u.stats[k]);
                    if (!Number.isNaN(v)) return v;
                }
            }
        }
        return 0;
    }

    async function loadLeaderboard(limit = 10) {
        const container = document.getElementById('leaderboard-list');
        if (!container) return console.error('❌ #leaderboard-list not found');
        container.innerHTML = '<p class="muted">Loading leaderboard...</p>';

        // Try server-provided leaderboard endpoint first
        try {
            const res = await fetch('http://localhost:5000/api/leaderboard');
            if (res.ok) {
                const data = await res.json();
                const entries = Array.isArray(data) ? data : (Array.isArray(data.leaderboard) ? data.leaderboard : (data.entries || []));
                // normalize role and include only learners
                const normalized = entries.map(en => ({
                    name: en.name || en.fullName || en.displayName || en.email || 'Unknown',
                    score: Number(en.score||en.points||en.totalScore||0)||0,
                    role: (en.role||en.userRole||'').toString()
                })).filter(e => {
                    const r = (e.role || '').toLowerCase();
                    // only include learners/students
                    return r.includes('learner') || r.includes('student');
                });
                renderLeaderboard(normalized.slice(0, limit));
                return;
            }
            // fallthrough to fetching users
        } catch (err) {
            console.debug('No server leaderboard endpoint or error fetching it, falling back to /api/users', err);
        }

        // Fallback: fetch all users and compute scores client-side
        try {
            const res = await fetch('http://localhost:5000/api/users');
            if (!res.ok) {
                renderLeaderboard([]);
                return;
            }
            const payload = await res.json();
            const users = Array.isArray(payload.users) ? payload.users : (Array.isArray(payload) ? payload : (payload.users || []));

            const computed = users.map(u => ({ name: u.fullName || u.displayName || u.email || 'Unknown', score: getScoreFromUser(u), role: (u.role||'').toString() }))
                // include only learners (exclude teachers)
                .filter(u => {
                    const r = (u.role || '').toLowerCase();
                    return r.includes('learner') || r.includes('student');
                });

            computed.sort((a,b) => (b.score||0) - (a.score||0));
            renderLeaderboard(computed.slice(0, limit));
        } catch (err) {
            console.error('Error loading leaderboard', err);
            container.innerHTML = '<p class="error">Error loading leaderboard.</p>';
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
            } else if (sectionId === 'progress') {
                setTimeout(loadProgress, 50);
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
                    } else if (sectionId === 'dashboard') {
                        loadDashboardStats();
                    } else if (sectionId === 'users') {
                    loadUsers();
                } else if (sectionId === 'leaderboards') {
                    loadLeaderboardFromServer();
                } else if (sectionId === 'progress') {
                    loadProgress();
                }
            }
        });
    });

    /** ---------------- Progress Table ---------------- */
    async function loadProgress() {
        const tbody = document.getElementById('progress-table-body');
        if (!tbody) return console.error('❌ #progress-table-body not found');
        tbody.innerHTML = `<tr><td colspan="5">Loading progress...</td></tr>`;

        try {
            const res = await fetch('http://localhost:5000/api/progress');
            if (!res.ok) {
                tbody.innerHTML = `<tr><td colspan="5">Failed to load progress</td></tr>`;
                return;
            }
            const payload = await res.json();
            const progress = Array.isArray(payload.progress) ? payload.progress : (payload.progress || []);

            if (progress.length === 0) {
                tbody.innerHTML = `<tr><td colspan="5">No progress data</td></tr>`;
                return;
            }

            tbody.innerHTML = '';
            // compute top performers (avgScore >= 90) and overall progress (mean of avgScores)
            try {
                const topCount = progress.filter(p => p.avgScore != null && Number(p.avgScore) >= 90).length;
                // compute overall average across learners that have a numeric avgScore
                const numeric = progress.map(p => (p.avgScore != null && !Number.isNaN(Number(p.avgScore))) ? Number(p.avgScore) : null).filter(x => x != null);
                const overallAvg = numeric.length > 0 ? (numeric.reduce((a,b) => a + b, 0) / numeric.length) : 0;

                // update the specific placeholders we added in the Progress section
                const topEl = document.getElementById('top-performers-value');
                const overallEl = document.getElementById('overall-progress-value');
                if (topEl) topEl.textContent = String(topCount);
                if (overallEl) overallEl.textContent = `${overallAvg.toFixed(1)}%`;
            } catch (e) {
                console.debug('Failed to update Progress stats', e);
            }
            progress.forEach(p => {
                const tr = document.createElement('tr');
                const avgText = (p.avgScore == null) ? '-' : (Number(p.avgScore).toFixed(1) + '%');
                tr.innerHTML = `
                    <td>${escapeHtml(p.name || '-')}</td>
                    <td>${escapeHtml(p.grade || '-')}</td>
                    <td>${escapeHtml(p.school || '-')}</td>
                    <td>${escapeHtml(avgText)}</td>
                    <td>${String(p.quizzesCompleted || 0)}</td>
                `;
                tbody.appendChild(tr);
            });
        } catch (err) {
            console.error('Error loading progress', err);
            tbody.innerHTML = `<tr><td colspan="5">Error loading progress</td></tr>`;
        }
    }

});