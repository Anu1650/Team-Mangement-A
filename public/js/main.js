// Configuration
const CONFIG = {
    appName: 'ProjectPulse AI',
    version: '1.0.0'
};

// Storage Utility
const StorageUtil = {
    // Initialize data
    init: function() {
        if (!localStorage.getItem('companies')) {
            localStorage.setItem('companies', JSON.stringify([]));
        }
        if (!localStorage.getItem('users')) {
            localStorage.setItem('users', JSON.stringify([]));
        }
        if (!localStorage.getItem('currentUser')) {
            localStorage.setItem('currentUser', JSON.stringify(null));
        }
        if (!localStorage.getItem('otpStore')) {
            localStorage.setItem('otpStore', JSON.stringify({}));
        }
    },

    // Companies
    getCompanies: function() {
        return JSON.parse(localStorage.getItem('companies')) || [];
    },
    
    saveCompanies: function(companies) {
        localStorage.setItem('companies', JSON.stringify(companies));
    },
    
    // Users
    getUsers: function() {
        return JSON.parse(localStorage.getItem('users')) || [];
    },
    
    saveUsers: function(users) {
        localStorage.setItem('users', JSON.stringify(users));
    },
    
    // Current User
    getCurrentUser: function() {
        return JSON.parse(localStorage.getItem('currentUser'));
    },
    
    setCurrentUser: function(user) {
        localStorage.setItem('currentUser', JSON.stringify(user));
    },
    
    // OTP Store
    getOTP: function(email) {
        const otpStore = JSON.parse(localStorage.getItem('otpStore')) || {};
        return otpStore[email];
    },
    
    saveOTP: function(email, otpData) {
        const otpStore = JSON.parse(localStorage.getItem('otpStore')) || {};
        otpStore[email] = otpData;
        localStorage.setItem('otpStore', JSON.stringify(otpStore));
    },
    
    removeOTP: function(email) {
        const otpStore = JSON.parse(localStorage.getItem('otpStore')) || {};
        delete otpStore[email];
        localStorage.setItem('otpStore', JSON.stringify(otpStore));
    },
    
    logout: function() {
        localStorage.setItem('currentUser', JSON.stringify(null));
        window.location.href = 'login.html';
    }
};

// Initialize storage
StorageUtil.init();

// Generate random 6-digit OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Generate company code (format: ABC123456)
function generateCompanyCode() {
    const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const randomLetters = letters.charAt(Math.floor(Math.random() * 26)) +
                          letters.charAt(Math.floor(Math.random() * 26)) +
                          letters.charAt(Math.floor(Math.random() * 26));
    const randomNumbers = Math.floor(100000 + Math.random() * 900000).toString();
    return randomLetters + randomNumbers;
}

// Generate slug from company name
function generateSlug(companyName) {
    return companyName
        .toLowerCase()
        .replace(/[^\w\s-]/g, '')
        .replace(/\s+/g, '-')
        .replace(/--+/g, '-')
        .trim();
}

// Check if company exists
function checkCompanyExists(companyName, companySlug) {
    const companies = StorageUtil.getCompanies();
    return companies.some(c => 
        c.companyName.toLowerCase() === companyName.toLowerCase() || 
        c.slug === companySlug
    );
}

// Check if email exists
function checkEmailExists(email) {
    const users = StorageUtil.getUsers();
    return users.some(u => u.email === email);
}

// Handle registration form submission
function handleRegistration(event) {
    event.preventDefault();
    
    // Get form data
    const userData = {
        fullName: document.getElementById('fullName')?.value.trim() || '',
        email: document.getElementById('email')?.value.trim() || '',
        password: document.getElementById('password')?.value || '',
        confirmPassword: document.getElementById('confirmPassword')?.value || '',
        companyName: document.getElementById('companyName')?.value.trim() || '',
        position: document.getElementById('position')?.value || '',
        teamSize: document.getElementById('teamSize')?.value || '',
        industry: document.getElementById('industry')?.value || ''
    };

    // Validate form
    if (!validateRegistration(userData)) {
        return;
    }

    // Check if email already exists
    if (checkEmailExists(userData.email)) {
        showMessage('Email already registered. Please login instead.', 'error');
        return;
    }

    // Generate slug
    const companySlug = generateSlug(userData.companyName);
    
    // Check if company exists
    if (checkCompanyExists(userData.companyName, companySlug)) {
        showMessage('Company name already exists. Please choose a different name.', 'error');
        return;
    }

    // Generate OTP
    const otp = generateOTP();
    const expiryTime = Date.now() + 10 * 60 * 1000; // 10 minutes expiry
    
    // Store OTP
    StorageUtil.saveOTP(userData.email, {
        otp: otp,
        expiry: expiryTime,
        userData: userData,
        companySlug: companySlug
    });

    // Show OTP step
    document.getElementById('step1')?.classList.add('hidden');
    document.getElementById('step2')?.classList.remove('hidden');
    document.getElementById('verificationEmail').textContent = userData.email;
    
    // Start timer
    startResendTimer();
    
    // Show success message
    showMessage(`Verification code sent to ${userData.email}`, 'success', 'otpMessage');
    
    // Log OTP for demo (remove in production)
    console.log('Your OTP is:', otp);
}

// Validate registration form
function validateRegistration(data) {
    // Check required fields
    if (!data.fullName || !data.email || !data.password || !data.companyName || !data.position || !data.teamSize) {
        showMessage('Please fill in all required fields', 'error');
        return false;
    }
    
    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(data.email)) {
        showMessage('Please enter a valid email address', 'error');
        return false;
    }
    
    // Check password match
    if (data.password !== data.confirmPassword) {
        showMessage('Passwords do not match', 'error');
        return false;
    }
    
    // Check password length
    if (data.password.length < 6) {
        showMessage('Password must be at least 6 characters', 'error');
        return false;
    }
    
    // Check terms
    const termsCheckbox = document.getElementById('terms');
    if (!termsCheckbox || !termsCheckbox.checked) {
        showMessage('Please accept the terms and conditions', 'error');
        return false;
    }
    
    return true;
}

// Handle OTP verification
function handleOTPVerification(event) {
    event.preventDefault();
    
    // Collect OTP from inputs
    const otpInputs = document.querySelectorAll('.otp-input[data-index]');
    let enteredOTP = '';
    otpInputs.forEach(input => {
        enteredOTP += input.value;
    });
    
    if (enteredOTP.length !== 6) {
        showMessage('Please enter the 6-digit verification code', 'error', 'otpMessage');
        return;
    }
    
    const email = document.getElementById('verificationEmail')?.textContent;
    
    if (!email) {
        showMessage('Session expired. Please register again.', 'error', 'otpMessage');
        return;
    }
    
    // Get stored OTP data
    const storedData = StorageUtil.getOTP(email);
    
    if (!storedData) {
        showMessage('OTP expired or not found. Please register again.', 'error', 'otpMessage');
        return;
    }
    
    // Check expiry
    if (Date.now() > storedData.expiry) {
        StorageUtil.removeOTP(email);
        showMessage('OTP has expired. Please register again.', 'error', 'otpMessage');
        return;
    }
    
    // Verify OTP
    if (enteredOTP !== storedData.otp) {
        showMessage('Invalid verification code. Please try again.', 'error', 'otpMessage');
        return;
    }
    
    // OTP verified - create account
    createAccount(storedData.userData, storedData.companySlug);
}

// Create account after OTP verification
function createAccount(userData, companySlug) {
    // Get existing data
    const companies = StorageUtil.getCompanies();
    const users = StorageUtil.getUsers();
    
    // Generate IDs
    const companyId = 'comp_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    const userId = 'user_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    const companyCode = generateCompanyCode();
    
    // Create company
    const newCompany = {
        id: companyId,
        companyName: userData.companyName,
        slug: companySlug,
        email: userData.email,
        companyCode: companyCode,
        industry: userData.industry || '',
        teamSize: userData.teamSize,
        createdAt: new Date().toISOString(),
        status: 'active',
        subscription: 'trial'
    };
    
    // Create admin user
    const newUser = {
        id: userId,
        companyId: companyId,
        companyCode: companyCode,
        fullName: userData.fullName,
        email: userData.email,
        password: btoa(userData.password), // Simple encoding for demo
        position: userData.position,
        role: 'admin',
        createdAt: new Date().toISOString()
    };
    
    // Save to storage
    companies.push(newCompany);
    users.push(newUser);
    
    StorageUtil.saveCompanies(companies);
    StorageUtil.saveUsers(users);
    
    // Remove OTP data
    StorageUtil.removeOTP(userData.email);
    
    // Set current user
    StorageUtil.setCurrentUser({
        id: userId,
        companyId: companyId,
        email: userData.email,
        fullName: userData.fullName,
        role: 'admin',
        companyName: userData.companyName,
        companyCode: companyCode,
        companySlug: companySlug
    });
    
    // Show success modal
    showSuccessModal(userData.companyName, companySlug, companyCode);
}

// Handle login
function handleLogin(event) {
    event.preventDefault();
    
    const email = document.getElementById('email')?.value.trim() || '';
    const password = document.getElementById('password')?.value || '';
    
    if (!email || !password) {
        showMessage('Please enter email and password', 'error');
        return;
    }
    
    const users = StorageUtil.getUsers();
    const companies = StorageUtil.getCompanies();
    
    // Find user
    const user = users.find(u => u.email === email);
    
    if (!user) {
        showMessage('Invalid email or password', 'error');
        return;
    }
    
    // Check password
    const decodedPassword = atob(user.password);
    if (decodedPassword !== password) {
        showMessage('Invalid email or password', 'error');
        return;
    }
    
    // Get company info
    const company = companies.find(c => c.id === user.companyId);
    
    if (!company) {
        showMessage('Company not found', 'error');
        return;
    }
    
    // Set current user
    StorageUtil.setCurrentUser({
        id: user.id,
        companyId: user.companyId,
        email: user.email,
        fullName: user.fullName,
        role: user.role,
        companyName: company.companyName,
        companyCode: company.companyCode,
        companySlug: company.slug
    });
    
    showMessage('Login successful! Redirecting...', 'success');
    
    setTimeout(() => {
        window.location.href = 'dashboard.html';
    }, 1500);
}

// Show success modal
function showSuccessModal(companyName, companySlug, companyCode) {
    const modal = document.getElementById('successModal');
    if (modal) {
        document.getElementById('successCompanyName').textContent = companyName;
        document.getElementById('successCompanySlug').textContent = companySlug;
        document.getElementById('modalCompanyFolder').textContent = companySlug + '/';
        document.getElementById('generatedCode').textContent = companyCode;
        modal.classList.remove('hidden');
    }
}

// Resend OTP
function resendOTP() {
    const email = document.getElementById('verificationEmail')?.textContent;
    
    if (!email) {
        showMessage('Session expired. Please register again.', 'error', 'otpMessage');
        return;
    }
    
    const storedData = StorageUtil.getOTP(email);
    
    if (!storedData) {
        showMessage('Session expired. Please register again.', 'error', 'otpMessage');
        return;
    }
    
    // Generate new OTP
    const newOTP = generateOTP();
    const newExpiry = Date.now() + 10 * 60 * 1000;
    
    // Update stored OTP
    StorageUtil.saveOTP(email, {
        ...storedData,
        otp: newOTP,
        expiry: newExpiry
    });
    
    // Clear OTP inputs
    document.querySelectorAll('.otp-input[data-index]').forEach(input => {
        input.value = '';
    });
    document.getElementById('otpCode').value = '';
    
    // Restart timer
    startResendTimer();
    
    showMessage('New verification code sent!', 'success', 'otpMessage');
    
    // Log OTP for demo
    console.log('Your new OTP is:', newOTP);
}

// Start resend timer
function startResendTimer() {
    const resendBtn = document.getElementById('resendOtpBtn');
    const timerElement = document.getElementById('timer');
    const countdownElement = document.getElementById('countdown');
    
    if (!resendBtn || !timerElement || !countdownElement) return;
    
    resendBtn.disabled = true;
    timerElement.classList.remove('hidden');
    
    let timeLeft = 60;
    countdownElement.textContent = timeLeft;
    
    const timer = setInterval(() => {
        timeLeft--;
        countdownElement.textContent = timeLeft;
        
        if (timeLeft <= 0) {
            clearInterval(timer);
            resendBtn.disabled = false;
            timerElement.classList.add('hidden');
        }
    }, 1000);
    
    // Store timer to clear if needed
    window.resendTimer = timer;
}

// Setup OTP inputs
function setupOTPInputs() {
    const otpInputs = document.querySelectorAll('.otp-input[data-index]');
    
    otpInputs.forEach((input, index) => {
        input.addEventListener('input', (e) => {
            // Allow only numbers
            e.target.value = e.target.value.replace(/[^0-9]/g, '');
            
            // Move to next input
            if (e.target.value.length === 1 && index < otpInputs.length - 1) {
                otpInputs[index + 1].focus();
            }
            
            // Update hidden field
            let otp = '';
            otpInputs.forEach(input => {
                otp += input.value;
            });
            const otpField = document.getElementById('otpCode');
            if (otpField) otpField.value = otp;
        });
        
        input.addEventListener('keydown', (e) => {
            // Handle backspace
            if (e.key === 'Backspace' && !e.target.value && index > 0) {
                otpInputs[index - 1].focus();
            }
        });
        
        // Handle paste
        input.addEventListener('paste', (e) => {
            e.preventDefault();
            const pasteData = e.clipboardData.getData('text').replace(/[^0-9]/g, '');
            
            if (pasteData.length === 6) {
                otpInputs.forEach((input, i) => {
                    input.value = pasteData[i] || '';
                });
                otpInputs[5].focus();
                
                // Update hidden field
                const otpField = document.getElementById('otpCode');
                if (otpField) otpField.value = pasteData;
            }
        });
    });
}

// Copy company code
function copyCompanyCode() {
    const code = document.getElementById('generatedCode')?.textContent;
    if (code) {
        navigator.clipboard.writeText(code).then(() => {
            const copyBtn = document.getElementById('copyCodeBtn');
            if (copyBtn) {
                const originalHTML = copyBtn.innerHTML;
                copyBtn.innerHTML = '<span class="material-symbols-outlined text-green-600">check</span>';
                
                setTimeout(() => {
                    copyBtn.innerHTML = originalHTML;
                }, 2000);
            }
        });
    }
}

// Check authentication
function checkAuth() {
    const currentUser = StorageUtil.getCurrentUser();
    const currentPage = window.location.pathname.split('/').pop();
    
    const publicPages = ['index.html', 'login.html', 'register-company.html'];
    
    if (!currentUser && !publicPages.includes(currentPage)) {
        window.location.href = 'login.html';
        return false;
    }
    
    return currentUser;
}

// Load dashboard data
function loadDashboardData() {
    const currentUser = StorageUtil.getCurrentUser();
    
    if (!currentUser) {
        window.location.href = 'login.html';
        return;
    }
    
    // Update user info
    const elements = {
        'userName': currentUser.fullName,
        'companyName': currentUser.companyName,
        'userRole': currentUser.role,
        'userEmail': currentUser.email,
        'companyCode': currentUser.companyCode
    };
    
    for (const [id, value] of Object.entries(elements)) {
        const element = document.getElementById(id);
        if (element) element.textContent = value;
    }
    
    // Load company details
    loadCompanyDetails(currentUser.companyId);
}

// Load company details
function loadCompanyDetails(companyId) {
    const companies = StorageUtil.getCompanies();
    const company = companies.find(c => c.id === companyId);
    
    if (company) {
        const detailsElement = document.getElementById('companyDetails');
        if (detailsElement) {
            detailsElement.innerHTML = `
                <p><strong>Company:</strong> ${company.companyName}</p>
                <p><strong>Code:</strong> ${company.companyCode}</p>
                <p><strong>Industry:</strong> ${company.industry || 'Not specified'}</p>
                <p><strong>Team Size:</strong> ${company.teamSize}</p>
                <p><strong>Created:</strong> ${new Date(company.createdAt).toLocaleDateString()}</p>
                <p><strong>Status:</strong> <span class="px-2 py-1 bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300 rounded-full text-xs">${company.status}</span></p>
            `;
        }
    }
}

// Show message function
function showMessage(message, type = 'info', containerId = 'message') {
    const messageElement = document.getElementById(containerId);
    if (messageElement) {
        messageElement.textContent = message;
        messageElement.className = `mb-6 p-4 rounded-lg ${
            type === 'error' 
                ? 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300' 
                : 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300'
        }`;
        messageElement.classList.remove('hidden');
        
        setTimeout(() => {
            messageElement.classList.add('hidden');
        }, 5000);
    }
}

// Logout
function logout() {
    StorageUtil.logout();
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    // Check authentication
    checkAuth();
    
    // Setup OTP inputs if on registration page
    if (document.querySelector('.otp-input')) {
        setupOTPInputs();
    }
    
    // Setup form handlers
    const registrationForm = document.getElementById('registrationForm');
    if (registrationForm) {
        registrationForm.addEventListener('submit', handleRegistration);
    }
    
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }
    
    const otpForm = document.getElementById('otpForm');
    if (otpForm) {
        otpForm.addEventListener('submit', handleOTPVerification);
    }
    
    // Resend OTP button
    const resendBtn = document.getElementById('resendOtpBtn');
    if (resendBtn) {
        resendBtn.addEventListener('click', resendOTP);
    }
    
    // Back to registration button
    const backBtn = document.getElementById('backToRegistrationBtn');
    if (backBtn) {
        backBtn.addEventListener('click', () => {
            document.getElementById('step1')?.classList.remove('hidden');
            document.getElementById('step2')?.classList.add('hidden');
            
            // Clear timer
            if (window.resendTimer) {
                clearInterval(window.resendTimer);
            }
        });
    }
    
    // Copy code button
    const copyBtn = document.getElementById('copyCodeBtn');
    if (copyBtn) {
        copyBtn.addEventListener('click', copyCompanyCode);
    }
    
    // Go to dashboard button
    const dashboardBtn = document.getElementById('goToDashboardBtn');
    if (dashboardBtn) {
        dashboardBtn.addEventListener('click', () => {
            window.location.href = 'dashboard.html';
        });
    }
    
    // Load dashboard data if on dashboard
    if (window.location.pathname.includes('dashboard')) {
        loadDashboardData();
    }
    
    // Set current year in footer
    const yearElement = document.getElementById('currentYear');
    if (yearElement) {
        yearElement.textContent = new Date().getFullYear();
    }
});