const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs').promises;
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const dotenv = require('dotenv');
const nodemailer = require('nodemailer');
const OpenAI = require('openai');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize OpenAI with new API key
const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Helper function to get base URL dynamically
function getBaseUrl(req) {
    // Check if we're in production (Render) or development
    if (process.env.NODE_ENV === 'production') {
        // For Render, use the environment variable or construct from request
        return process.env.RENDER_EXTERNAL_URL || `${req.protocol}://${req.get('host')}`;
    }
    return `http://localhost:${PORT}`;
}

// Directory structure
const DATA_DIR = path.join(__dirname, 'data');
const MASTER_FILE = path.join(DATA_DIR, 'master.json');
const COMPANIES_DIR = path.join(DATA_DIR, 'companies');
const OTP_DIR = path.join(DATA_DIR, 'otp');
const CHATS_DIR = path.join(DATA_DIR, 'chats');

// Initialize directories and files
async function initializeDataFiles() {
    try {
        await fs.mkdir(DATA_DIR, { recursive: true });
        await fs.mkdir(COMPANIES_DIR, { recursive: true });
        await fs.mkdir(OTP_DIR, { recursive: true });
        await fs.mkdir(CHATS_DIR, { recursive: true });
        
        try {
            await fs.access(MASTER_FILE);
        } catch {
            await fs.writeFile(MASTER_FILE, JSON.stringify({
                companies: [],
                stats: {
                    totalCompanies: 0,
                    totalUsers: 0,
                    createdAt: new Date().toISOString()
                }
            }, null, 2));
        }
    } catch (error) {
        console.error('Error initializing data files:', error);
    }
}

initializeDataFiles();

// ==================== MASTER DATA ====================

async function readMaster() {
    const data = await fs.readFile(MASTER_FILE, 'utf8');
    return JSON.parse(data);
}

async function writeMaster(master) {
    await fs.writeFile(MASTER_FILE, JSON.stringify(master, null, 2));
}

// ==================== COMPANY-SPECIFIC DATA ====================

function getCompanyDir(companyId) {
    return path.join(COMPANIES_DIR, companyId);
}

function getCompanyInfoPath(companyId) {
    return path.join(getCompanyDir(companyId), 'company-info.json');
}

function getCompanyUsersPath(companyId) {
    return path.join(getCompanyDir(companyId), 'users.json');
}

function getCompanySettingsPath(companyId) {
    return path.join(getCompanyDir(companyId), 'settings.json');
}

// Get chat history path for a user (organized by company/user)
function getUserChatPath(companyId, userId) {
    const companyChatDir = path.join(CHATS_DIR, companyId);
    return path.join(companyChatDir, `${userId}.json`);
}

// Initialize company files
async function initializeCompanyFiles(company) {
    const companyDir = getCompanyDir(company.id);
    await fs.mkdir(companyDir, { recursive: true });
    
    await fs.writeFile(getCompanyInfoPath(company.id), JSON.stringify({
        id: company.id,
        companyName: company.companyName,
        companyCode: company.companyCode,
        slug: company.slug,
        email: company.email,
        createdAt: company.createdAt,
        status: 'active',
        industry: company.industry || '',
        teamSize: company.teamSize || ''
    }, null, 2));
    
    await fs.writeFile(getCompanyUsersPath(company.id), JSON.stringify([], null, 2));
    
    await fs.writeFile(getCompanySettingsPath(company.id), JSON.stringify({
        timezone: 'UTC',
        dateFormat: 'MM/DD/YYYY',
        weekStartsOn: 'Monday',
        updatedAt: new Date().toISOString()
    }, null, 2));
    
    const companyChatDir = path.join(CHATS_DIR, company.id);
    await fs.mkdir(companyChatDir, { recursive: true });
}

// Read company users
async function readCompanyUsers(companyId) {
    try {
        const data = await fs.readFile(getCompanyUsersPath(companyId), 'utf8');
        return JSON.parse(data);
    } catch (error) {
        return [];
    }
}

// Write company users
async function writeCompanyUsers(companyId, users) {
    await fs.writeFile(getCompanyUsersPath(companyId), JSON.stringify(users, null, 2));
}

// Read company info
async function readCompanyInfo(companyId) {
    try {
        const data = await fs.readFile(getCompanyInfoPath(companyId), 'utf8');
        return JSON.parse(data);
    } catch (error) {
        return null;
    }
}

// Read company settings
async function readCompanySettings(companyId) {
    try {
        const data = await fs.readFile(getCompanySettingsPath(companyId), 'utf8');
        return JSON.parse(data);
    } catch (error) {
        return {
            timezone: 'UTC',
            dateFormat: 'MM/DD/YYYY',
            weekStartsOn: 'Monday',
            updatedAt: new Date().toISOString()
        };
    }
}

// Write company settings
async function writeCompanySettings(companyId, settings) {
    await fs.writeFile(getCompanySettingsPath(companyId), JSON.stringify(settings, null, 2));
}

// ==================== CHAT HISTORY FUNCTIONS (By Username) ====================

// Get user details by userId
async function getUserById(companyId, userId) {
    const users = await readCompanyUsers(companyId);
    return users.find(u => u.id === userId);
}

// Get chat history with user details
async function getUserChatHistory(companyId, userId) {
    try {
        const user = await getUserById(companyId, userId);
        const chatPath = getUserChatPath(companyId, userId);
        const data = await fs.readFile(chatPath, 'utf8');
        const history = JSON.parse(data);
        
        // Add user info to history
        return {
            userId: userId,
            userName: user ? user.fullName : 'Unknown User',
            userEmail: user ? user.email : '',
            messages: history.messages || []
        };
    } catch (error) {
        const user = await getUserById(companyId, userId);
        return { 
            userId, 
            userName: user ? user.fullName : 'Unknown User',
            userEmail: user ? user.email : '',
            messages: [] 
        };
    }
}

// Save chat message with user info
async function saveUserChatMessage(companyId, userId, message) {
    const companyChatDir = path.join(CHATS_DIR, companyId);
    await fs.mkdir(companyChatDir, { recursive: true });
    
    const user = await getUserById(companyId, userId);
    const chatPath = getUserChatPath(companyId, userId);
    let history = await getUserChatHistory(companyId, userId);
    
    // Add message with timestamp
    const messageWithMeta = {
        ...message,
        timestamp: message.timestamp || new Date().toISOString(),
        userName: user ? user.fullName : 'Unknown User'
    };
    
    history.messages.push(messageWithMeta);
    
    // Keep only last 100 messages
    if (history.messages.length > 100) {
        history.messages = history.messages.slice(-100);
    }
    
    // Save with metadata
    const historyToSave = {
        userId: userId,
        userName: user ? user.fullName : 'Unknown User',
        userEmail: user ? user.email : '',
        lastUpdated: new Date().toISOString(),
        totalMessages: history.messages.length,
        messages: history.messages
    };
    
    await fs.writeFile(chatPath, JSON.stringify(historyToSave, null, 2));
    return historyToSave;
}

// Get all chat histories for a company (admin only)
async function getAllCompanyChats(companyId) {
    try {
        const companyChatDir = path.join(CHATS_DIR, companyId);
        const files = await fs.readdir(companyChatDir);
        const chats = [];
        
        for (const file of files) {
            if (file.endsWith('.json')) {
                const chatPath = path.join(companyChatDir, file);
                const data = await fs.readFile(chatPath, 'utf8');
                const chat = JSON.parse(data);
                chats.push({
                    userId: chat.userId,
                    userName: chat.userName,
                    userEmail: chat.userEmail,
                    lastUpdated: chat.lastUpdated,
                    totalMessages: chat.totalMessages,
                    preview: chat.messages.slice(-3) // Last 3 messages as preview
                });
            }
        }
        
        return chats.sort((a, b) => new Date(b.lastUpdated) - new Date(a.lastUpdated));
    } catch (error) {
        return [];
    }
}

// ==================== OTP STORAGE ====================

function getOTPPath(email) {
    const sanitizedEmail = email.replace(/[@.]/g, '_');
    return path.join(OTP_DIR, `${sanitizedEmail}.json`);
}

async function saveOTP(email, otpData) {
    await fs.writeFile(getOTPPath(email), JSON.stringify(otpData, null, 2));
}

async function readOTP(email) {
    try {
        const data = await fs.readFile(getOTPPath(email), 'utf8');
        return JSON.parse(data);
    } catch (error) {
        return null;
    }
}

async function deleteOTP(email) {
    try {
        await fs.unlink(getOTPPath(email));
    } catch (error) {}
}

// ==================== HELPER FUNCTIONS ====================

function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

function generateCompanyCode() {
    const letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const randomLetters = letters.charAt(Math.floor(Math.random() * 26)) +
                          letters.charAt(Math.floor(Math.random() * 26)) +
                          letters.charAt(Math.floor(Math.random() * 26));
    const randomNumbers = Math.floor(100000 + Math.random() * 900000).toString();
    return randomLetters + randomNumbers;
}

function generateSlug(companyName) {
    return companyName
        .toLowerCase()
        .replace(/[^\w\s-]/g, '')
        .replace(/\s+/g, '-')
        .replace(/--+/g, '-')
        .trim();
}

// Email configuration
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Send OTP email
async function sendOTPEmail(toEmail, otp, purpose, baseUrl) {
    const subject = purpose === 'registration' 
        ? 'Welcome to ProjectPulse AI - Verify Your Email' 
        : 'ProjectPulse AI - Password Reset OTP';
    
    const html = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px;">
            <div style="text-align: center; margin-bottom: 30px;">
                <h1 style="color: #137fec; margin-bottom: 5px;">ProjectPulse AI</h1>
                <p style="color: #666; font-size: 14px;">Engineering Intelligence Platform</p>
            </div>
            
            <div style="background-color: #f5f5f5; padding: 20px; border-radius: 8px; text-align: center;">
                <h2 style="color: #333; margin-bottom: 10px;">${purpose === 'registration' ? 'Email Verification' : 'Password Reset'}</h2>
                <p style="color: #666; margin-bottom: 20px;">
                    ${purpose === 'registration' 
                        ? 'Thank you for registering with ProjectPulse AI. Please use the following OTP to verify your email address:' 
                        : 'We received a request to reset your password. Please use the following OTP to proceed:'}
                </p>
                
                <div style="background-color: #137fec; color: white; font-size: 36px; font-weight: bold; padding: 15px; border-radius: 8px; letter-spacing: 5px; margin: 20px 0;">
                    ${otp}
                </div>
                
                <p style="color: #999; font-size: 12px; margin-top: 20px;">
                    This OTP is valid for 10 minutes. If you didn't request this, please ignore this email.
                </p>
            </div>
            
            <div style="text-align: center; margin-top: 30px; color: #999; font-size: 12px;">
                <p>&copy; 2026 ProjectPulse AI. All rights reserved.</p>
                <p>This is an automated message, please do not reply.</p>
            </div>
        </div>
    `;
    
    try {
        await transporter.sendMail({
            from: `"ProjectPulse AI" <${process.env.EMAIL_USER}>`,
            to: toEmail,
            subject: subject,
            html: html
        });
        console.log(`✅ OTP email sent to ${toEmail}`);
        return true;
    } catch (error) {
        console.error('❌ Error sending email:', error);
        return false;
    }
}

// Send invitation email
async function sendInvitationEmail(email, fullName, tempPassword, companyCode, baseUrl) {
    const subject = 'Welcome to ProjectPulse AI - Your Account Details';
    
    const html = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 10px;">
            <div style="text-align: center; margin-bottom: 30px;">
                <h1 style="color: #137fec; margin-bottom: 5px;">ProjectPulse AI</h1>
                <p style="color: #666; font-size: 14px;">Engineering Intelligence Platform</p>
            </div>
            
            <div style="background-color: #f5f5f5; padding: 20px; border-radius: 8px;">
                <h2 style="color: #333; margin-bottom: 10px;">Welcome to the team, ${fullName}!</h2>
                <p style="color: #666; margin-bottom: 20px;">
                    You've been invited to join ProjectPulse AI. Here are your login details:
                </p>
                
                <div style="background-color: #fff; padding: 15px; border-radius: 8px; margin: 20px 0;">
                    <p style="margin: 5px 0;"><strong>Company Code:</strong> ${companyCode}</p>
                    <p style="margin: 5px 0;"><strong>Email:</strong> ${email}</p>
                    <p style="margin: 5px 0;"><strong>Temporary Password:</strong> ${tempPassword}</p>
                </div>
                
                <p style="color: #666; font-size: 14px;">
                    Please login and change your password immediately.
                </p>
                
                <div style="text-align: center; margin-top: 25px;">
                    <a href="${baseUrl}/login.html" 
                       style="background-color: #137fec; color: white; padding: 12px 30px; 
                              text-decoration: none; border-radius: 5px; font-weight: bold;">
                        Login to Your Account
                    </a>
                </div>
            </div>
            
            <div style="text-align: center; margin-top: 30px; color: #999; font-size: 12px;">
                <p>&copy; 2026 ProjectPulse AI. All rights reserved.</p>
                <p>This is an automated message, please do not reply.</p>
            </div>
        </div>
    `;
    
    try {
        await transporter.sendMail({
            from: `"ProjectPulse AI" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: subject,
            html: html
        });
        console.log(`✅ Invitation email sent to ${email}`);
        return true;
    } catch (error) {
        console.error('❌ Error sending invitation:', error);
        return false;
    }
}

// Authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

// Admin only middleware
function requireAdmin(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
}

// ==================== OTP ROUTES ====================

app.post('/api/otp/send', async (req, res) => {
    try {
        const { email, purpose } = req.body;
        const baseUrl = getBaseUrl(req);
        
        if (!email || !purpose) {
            return res.status(400).json({ error: 'Email and purpose are required' });
        }
        
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        
        const master = await readMaster();
        
        if (purpose === 'password-reset') {
            let userFound = false;
            
            for (const company of master.companies) {
                const users = await readCompanyUsers(company.id);
                if (users.some(u => u.email === email)) {
                    userFound = true;
                    break;
                }
            }
            
            if (!userFound) {
                return res.status(404).json({ error: 'No account found with this email' });
            }
        }
        
        if (purpose === 'registration') {
            let emailExists = false;
            
            for (const company of master.companies) {
                const users = await readCompanyUsers(company.id);
                if (users.some(u => u.email === email)) {
                    emailExists = true;
                    break;
                }
            }
            
            if (emailExists) {
                return res.status(400).json({ error: 'Email already registered' });
            }
        }
        
        const otp = generateOTP();
        const expiryTime = Date.now() + 10 * 60 * 1000;
        
        await saveOTP(email, {
            otp,
            expiry: expiryTime,
            purpose,
            createdAt: new Date().toISOString()
        });
        
        const emailSent = await sendOTPEmail(email, otp, purpose, baseUrl);
        
        if (!emailSent) {
            return res.status(500).json({ error: 'Failed to send OTP email' });
        }
        
        res.json({ 
            message: `OTP sent to ${email}`,
            expiresIn: 600,
            otp: process.env.NODE_ENV === 'development' ? otp : undefined
        });
        
    } catch (error) {
        console.error('Error sending OTP:', error);
        res.status(500).json({ error: 'Failed to send OTP' });
    }
});

app.post('/api/otp/verify', async (req, res) => {
    try {
        const { email, otp, purpose } = req.body;
        
        if (!email || !otp || !purpose) {
            return res.status(400).json({ error: 'Email, OTP, and purpose are required' });
        }
        
        const storedData = await readOTP(email);
        
        if (!storedData) {
            return res.status(400).json({ error: 'OTP not found or expired' });
        }
        
        if (storedData.purpose !== purpose) {
            return res.status(400).json({ error: 'Invalid OTP for this purpose' });
        }
        
        if (Date.now() > storedData.expiry) {
            await deleteOTP(email);
            return res.status(400).json({ error: 'OTP has expired' });
        }
        
        if (storedData.otp !== otp) {
            return res.status(400).json({ error: 'Invalid OTP' });
        }
        
        await deleteOTP(email);
        
        res.json({ 
            message: 'OTP verified successfully',
            verified: true
        });
        
    } catch (error) {
        console.error('Error verifying OTP:', error);
        res.status(500).json({ error: 'Failed to verify OTP' });
    }
});

// ==================== COMPANY ROUTES ====================

app.get('/api/companies/check', async (req, res) => {
    try {
        const { slug } = req.query;
        const master = await readMaster();
        const exists = master.companies.some(c => c.slug === slug);
        res.json({ exists });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/companies/check-code/:code', async (req, res) => {
    try {
        const { code } = req.params;
        const master = await readMaster();
        const company = master.companies.find(c => c.companyCode === code);
        
        if (!company) {
            return res.status(404).json({ error: 'Invalid company code' });
        }
        
        const companyInfo = await readCompanyInfo(company.id);
        
        res.json({ 
            exists: true, 
            companyName: companyInfo.companyName,
            companyId: company.id
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/companies/:companyId', authenticateToken, async (req, res) => {
    try {
        if (req.user.companyId !== req.params.companyId) {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        const companyInfo = await readCompanyInfo(req.params.companyId);
        
        if (!companyInfo) {
            return res.status(404).json({ error: 'Company not found' });
        }
        
        res.json(companyInfo);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== AUTH ROUTES ====================

app.post('/api/auth/check-email', async (req, res) => {
    try {
        const { email } = req.body;
        
        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }
        
        const master = await readMaster();
        let emailExists = false;
        
        for (const company of master.companies) {
            const users = await readCompanyUsers(company.id);
            if (users.some(u => u.email === email)) {
                emailExists = true;
                break;
            }
        }
        
        res.json({ exists: emailExists });
    } catch (error) {
        console.error('Error checking email:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/auth/register-company', async (req, res) => {
    try {
        const { companyName, email, fullName, position, password, teamSize, industry } = req.body;
        
        console.log('Registration attempt:', { email, companyName, fullName, position });
        
        if (!companyName || !email || !fullName || !position || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        
        if (password.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters' });
        }
        
        const master = await readMaster();
        let emailExists = false;
        
        for (const company of master.companies) {
            const users = await readCompanyUsers(company.id);
            if (users.some(u => u.email === email)) {
                emailExists = true;
                break;
            }
        }
        
        if (emailExists) {
            return res.status(400).json({ error: 'Email already registered' });
        }
        
        const companyCode = generateCompanyCode();
        const slug = generateSlug(companyName);
        
        if (master.companies.some(c => c.slug === slug)) {
            return res.status(400).json({ error: 'Company name already exists' });
        }
        
        const companyId = uuidv4();
        const newCompany = {
            id: companyId,
            companyName,
            companyCode,
            slug,
            email,
            industry,
            teamSize,
            createdAt: new Date().toISOString()
        };
        
        await initializeCompanyFiles(newCompany);
        
        master.companies.push({
            id: companyId,
            companyName,
            companyCode,
            slug,
            email,
            createdAt: newCompany.createdAt
        });
        master.stats.totalCompanies = master.companies.length;
        await writeMaster(master);
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            id: uuidv4(),
            email,
            fullName,
            position,
            password: hashedPassword,
            role: 'admin',
            status: 'active',
            createdAt: new Date().toISOString(),
            lastLogin: null,
            lastActive: null
        };
        
        const companyUsers = await readCompanyUsers(companyId);
        companyUsers.push(newUser);
        await writeCompanyUsers(companyId, companyUsers);
        
        master.stats.totalUsers += 1;
        await writeMaster(master);
        
        const token = jwt.sign(
            { 
                userId: newUser.id, 
                companyId, 
                email, 
                role: 'admin',
                companyCode 
            },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        console.log('Registration successful for:', email);
        
        res.status(201).json({
            message: 'Company registered successfully',
            token,
            user: {
                id: newUser.id,
                fullName: newUser.fullName,
                email: newUser.email,
                role: newUser.role,
                companyId,
                companyName,
                companyCode,
                position: newUser.position,
                status: newUser.status
            }
        });
        
    } catch (error) {
        console.error('Error registering company:', error);
        res.status(500).json({ error: 'Failed to register company' });
    }
});

app.post('/api/auth/register-team', async (req, res) => {
    try {
        const { companyCode, email, fullName, position, password } = req.body;
        
        console.log('Team registration attempt:', { email, companyCode, fullName, position });
        
        if (!companyCode || !email || !fullName || !position || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        
        if (password.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters' });
        }
        
        const master = await readMaster();
        const company = master.companies.find(c => c.companyCode === companyCode);
        
        if (!company) {
            return res.status(400).json({ error: 'Invalid company code' });
        }
        
        const companyUsers = await readCompanyUsers(company.id);
        if (companyUsers.some(u => u.email === email)) {
            return res.status(400).json({ error: 'Email already registered in this company' });
        }
        
        for (const otherCompany of master.companies) {
            if (otherCompany.id !== company.id) {
                const otherUsers = await readCompanyUsers(otherCompany.id);
                if (otherUsers.some(u => u.email === email)) {
                    return res.status(400).json({ error: 'Email already registered in another company' });
                }
            }
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            id: uuidv4(),
            email,
            fullName,
            position,
            password: hashedPassword,
            role: 'member',
            status: 'active',
            createdAt: new Date().toISOString(),
            lastLogin: null,
            lastActive: null
        };
        
        companyUsers.push(newUser);
        await writeCompanyUsers(company.id, companyUsers);
        
        master.stats.totalUsers += 1;
        await writeMaster(master);
        
        const token = jwt.sign(
            { 
                userId: newUser.id, 
                companyId: company.id, 
                email, 
                role: 'member',
                companyCode: company.companyCode
            },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.status(201).json({
            message: 'Team member registered successfully',
            token,
            user: {
                id: newUser.id,
                fullName: newUser.fullName,
                email: newUser.email,
                role: newUser.role,
                companyId: company.id,
                companyName: company.companyName,
                companyCode: company.companyCode,
                position: newUser.position,
                status: newUser.status
            }
        });
        
    } catch (error) {
        console.error('Error registering team member:', error);
        res.status(500).json({ error: 'Failed to register team member' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }
        
        const master = await readMaster();
        let foundUser = null;
        let foundCompany = null;
        
        for (const company of master.companies) {
            const users = await readCompanyUsers(company.id);
            const user = users.find(u => u.email === email);
            if (user) {
                foundUser = user;
                foundCompany = company;
                break;
            }
        }
        
        if (!foundUser) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        if (foundUser.status !== 'active') {
            return res.status(401).json({ error: 'Account is deactivated' });
        }
        
        const validPassword = await bcrypt.compare(password, foundUser.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        foundUser.lastLogin = new Date().toISOString();
        foundUser.lastActive = new Date().toISOString();
        
        const companyUsers = await readCompanyUsers(foundCompany.id);
        const userIndex = companyUsers.findIndex(u => u.id === foundUser.id);
        companyUsers[userIndex] = foundUser;
        await writeCompanyUsers(foundCompany.id, companyUsers);
        
        const token = jwt.sign(
            { 
                userId: foundUser.id, 
                companyId: foundCompany.id, 
                email: foundUser.email, 
                role: foundUser.role,
                companyCode: foundCompany.companyCode
            },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({
            message: 'Login successful',
            token,
            user: {
                id: foundUser.id,
                fullName: foundUser.fullName,
                email: foundUser.email,
                role: foundUser.role,
                companyId: foundCompany.id,
                companyName: foundCompany.companyName,
                companyCode: foundCompany.companyCode,
                position: foundUser.position,
                status: foundUser.status,
                lastActive: foundUser.lastActive
            }
        });
        
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).json({ error: 'Failed to login' });
    }
});

app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const baseUrl = getBaseUrl(req);
        
        if (!email) {
            return res.status(400).json({ error: 'Email is required' });
        }
        
        const master = await readMaster();
        let userFound = false;
        
        for (const company of master.companies) {
            const users = await readCompanyUsers(company.id);
            if (users.some(u => u.email === email)) {
                userFound = true;
                break;
            }
        }
        
        if (!userFound) {
            return res.status(404).json({ error: 'No account found with this email' });
        }
        
        const otp = generateOTP();
        const expiryTime = Date.now() + 10 * 60 * 1000;
        
        await saveOTP(email, {
            otp,
            expiry: expiryTime,
            purpose: 'password-reset',
            createdAt: new Date().toISOString()
        });
        
        const emailSent = await sendOTPEmail(email, otp, 'password-reset', baseUrl);
        
        if (!emailSent) {
            return res.status(500).json({ error: 'Failed to send OTP email' });
        }
        
        res.json({ 
            message: 'Password reset OTP sent to your email',
            expiresIn: 600,
            otp: process.env.NODE_ENV === 'development' ? otp : undefined
        });
        
    } catch (error) {
        console.error('Error in forgot password:', error);
        res.status(500).json({ error: 'Failed to process request' });
    }
});

app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;
        
        if (!email || !otp || !newPassword) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        
        if (newPassword.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters' });
        }
        
        const storedOTP = await readOTP(email);
        
        if (!storedOTP || storedOTP.otp !== otp || storedOTP.purpose !== 'password-reset') {
            return res.status(400).json({ error: 'Invalid OTP' });
        }
        
        if (Date.now() > storedOTP.expiry) {
            await deleteOTP(email);
            return res.status(400).json({ error: 'OTP has expired' });
        }
        
        const master = await readMaster();
        let userUpdated = false;
        
        for (const company of master.companies) {
            const users = await readCompanyUsers(company.id);
            const userIndex = users.findIndex(u => u.email === email);
            
            if (userIndex !== -1) {
                const hashedPassword = await bcrypt.hash(newPassword, 10);
                users[userIndex].password = hashedPassword;
                await writeCompanyUsers(company.id, users);
                userUpdated = true;
                break;
            }
        }
        
        if (!userUpdated) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        await deleteOTP(email);
        
        res.json({ message: 'Password reset successfully' });
        
    } catch (error) {
        console.error('Error resetting password:', error);
        res.status(500).json({ error: 'Failed to reset password' });
    }
});

// ==================== USER ROUTES ====================

app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const users = await readCompanyUsers(req.user.companyId);
        const user = users.find(u => u.id === req.user.userId);
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const companyInfo = await readCompanyInfo(req.user.companyId);
        
        res.json({
            id: user.id,
            fullName: user.fullName,
            email: user.email,
            position: user.position,
            role: user.role,
            companyId: req.user.companyId,
            companyName: companyInfo?.companyName,
            companyCode: req.user.companyCode,
            createdAt: user.createdAt,
            lastLogin: user.lastLogin,
            lastActive: user.lastActive,
            status: user.status
        });
        
    } catch (error) {
        console.error('Error fetching profile:', error);
        res.status(500).json({ error: 'Failed to fetch profile' });
    }
});

app.put('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        const { fullName, position } = req.body;
        
        const users = await readCompanyUsers(req.user.companyId);
        const userIndex = users.findIndex(u => u.id === req.user.userId);
        
        if (userIndex === -1) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        if (fullName) users[userIndex].fullName = fullName;
        if (position) users[userIndex].position = position;
        
        await writeCompanyUsers(req.user.companyId, users);
        
        res.json({
            message: 'Profile updated successfully',
            user: {
                id: users[userIndex].id,
                fullName: users[userIndex].fullName,
                email: users[userIndex].email,
                position: users[userIndex].position,
                role: users[userIndex].role,
                status: users[userIndex].status
            }
        });
        
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

app.post('/api/user/heartbeat', authenticateToken, async (req, res) => {
    try {
        const users = await readCompanyUsers(req.user.companyId);
        const userIndex = users.findIndex(u => u.id === req.user.userId);
        
        if (userIndex === -1) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        users[userIndex].lastActive = new Date().toISOString();
        await writeCompanyUsers(req.user.companyId, users);
        
        res.json({ success: true });
    } catch (error) {
        console.error('Error updating heartbeat:', error);
        res.status(500).json({ error: 'Failed to update status' });
    }
});

app.post('/api/user/change-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        
        if (newPassword.length < 8) {
            return res.status(400).json({ error: 'New password must be at least 8 characters' });
        }
        
        const users = await readCompanyUsers(req.user.companyId);
        const userIndex = users.findIndex(u => u.id === req.user.userId);
        
        if (userIndex === -1) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const validPassword = await bcrypt.compare(currentPassword, users[userIndex].password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }
        
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        users[userIndex].password = hashedPassword;
        await writeCompanyUsers(req.user.companyId, users);
        
        res.json({ message: 'Password changed successfully' });
        
    } catch (error) {
        console.error('Error changing password:', error);
        res.status(500).json({ error: 'Failed to change password' });
    }
});

// ==================== TEAM MANAGEMENT ====================

app.get('/api/team', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const users = await readCompanyUsers(req.user.companyId);
        
        // Calculate online status (active in last 5 minutes)
        const fiveMinutesAgo = Date.now() - 5 * 60 * 1000;
        
        const teamMembers = users.map(u => ({
            id: u.id,
            fullName: u.fullName,
            email: u.email,
            position: u.position,
            role: u.role,
            status: u.status,
            isOnline: u.lastActive ? new Date(u.lastActive).getTime() > fiveMinutesAgo : false,
            lastActive: u.lastActive,
            createdAt: u.createdAt,
            lastLogin: u.lastLogin
        }));
        
        res.json(teamMembers);
        
    } catch (error) {
        console.error('Error fetching team:', error);
        res.status(500).json({ error: 'Failed to fetch team' });
    }
});

app.post('/api/team/create-employee', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { email, fullName, position, role } = req.body;
        const baseUrl = getBaseUrl(req);
        
        if (!email || !fullName || !position) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        
        const users = await readCompanyUsers(req.user.companyId);
        
        if (users.some(u => u.email === email)) {
            return res.status(400).json({ error: 'Email already exists in this company' });
        }
        
        const tempPassword = generateSecurePassword();
        const hashedPassword = await bcrypt.hash(tempPassword, 10);
        
        const newUser = {
            id: uuidv4(),
            email,
            fullName,
            position,
            password: hashedPassword,
            role: role || 'member',
            status: 'active',
            createdAt: new Date().toISOString(),
            lastLogin: null,
            lastActive: null
        };
        
        users.push(newUser);
        await writeCompanyUsers(req.user.companyId, users);
        
        // Send invitation email with temp password and dynamic base URL
        await sendInvitationEmail(email, fullName, tempPassword, req.user.companyCode, baseUrl);
        
        res.status(201).json({
            message: 'Team member created successfully',
            user: {
                id: newUser.id,
                fullName: newUser.fullName,
                email: newUser.email,
                position: newUser.position,
                role: newUser.role,
                status: newUser.status
            }
        });
        
    } catch (error) {
        console.error('Error creating employee:', error);
        res.status(500).json({ error: 'Failed to create team member' });
    }
});

app.put('/api/team/:userId/role', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { role } = req.body;
        const { userId } = req.params;
        
        if (!role || !['admin', 'member'].includes(role)) {
            return res.status(400).json({ error: 'Invalid role' });
        }
        
        if (userId === req.user.userId) {
            return res.status(400).json({ error: 'Cannot change your own role' });
        }
        
        const users = await readCompanyUsers(req.user.companyId);
        const userIndex = users.findIndex(u => u.id === userId);
        
        if (userIndex === -1) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        users[userIndex].role = role;
        await writeCompanyUsers(req.user.companyId, users);
        
        res.json({ 
            message: 'User role updated successfully',
            user: {
                id: users[userIndex].id,
                fullName: users[userIndex].fullName,
                role: users[userIndex].role,
                status: users[userIndex].status,
                isOnline: users[userIndex].lastActive ? 
                    new Date(users[userIndex].lastActive).getTime() > Date.now() - 5 * 60 * 1000 : false
            }
        });
        
    } catch (error) {
        console.error('Error updating user role:', error);
        res.status(500).json({ error: 'Failed to update user role' });
    }
});

app.put('/api/team/:userId/status', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { status } = req.body;
        const { userId } = req.params;
        
        if (!status || !['active', 'inactive'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }
        
        if (userId === req.user.userId) {
            return res.status(400).json({ error: 'Cannot change your own status' });
        }
        
        const users = await readCompanyUsers(req.user.companyId);
        const userIndex = users.findIndex(u => u.id === userId);
        
        if (userIndex === -1) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        users[userIndex].status = status;
        await writeCompanyUsers(req.user.companyId, users);
        
        res.json({ 
            message: `User ${status === 'active' ? 'activated' : 'deactivated'} successfully`,
            user: {
                id: users[userIndex].id,
                fullName: users[userIndex].fullName,
                role: users[userIndex].role,
                status: users[userIndex].status,
                isOnline: status === 'active' && users[userIndex].lastActive ? 
                    new Date(users[userIndex].lastActive).getTime() > Date.now() - 5 * 60 * 1000 : false
            }
        });
        
    } catch (error) {
        console.error('Error updating user status:', error);
        res.status(500).json({ error: 'Failed to update user status' });
    }
});

app.delete('/api/team/:userId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        
        if (userId === req.user.userId) {
            return res.status(400).json({ error: 'Cannot remove yourself' });
        }
        
        const users = await readCompanyUsers(req.user.companyId);
        const userIndex = users.findIndex(u => u.id === userId);
        
        if (userIndex === -1) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        users.splice(userIndex, 1);
        await writeCompanyUsers(req.user.companyId, users);
        
        const master = await readMaster();
        master.stats.totalUsers -= 1;
        await writeMaster(master);
        
        res.json({ message: 'User removed successfully' });
        
    } catch (error) {
        console.error('Error removing user:', error);
        res.status(500).json({ error: 'Failed to remove user' });
    }
});

// ==================== CHAT ROUTES ====================

// Send message and get AI response
app.post('/api/chat/message', authenticateToken, async (req, res) => {
    try {
        const { message, model } = req.body;
        
        if (!message) {
            return res.status(400).json({ error: 'Message is required' });
        }
        
        // Get user info
        const users = await readCompanyUsers(req.user.companyId);
        const user = users.find(u => u.id === req.user.userId);
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Save user message
        await saveUserChatMessage(req.user.companyId, req.user.userId, {
            role: 'user',
            content: message,
            userName: user.fullName
        });
        
        // Get company context
        const companyInfo = await readCompanyInfo(req.user.companyId);
        
        // Create system prompt with company context
        const systemPrompt = `You are ProjectPulse AI, a helpful assistant for engineering teams. 
Current context:
- Company: ${companyInfo.companyName}
- User: ${user.fullName} (${req.user.role})
- Team size: ${users.length} members

Provide helpful, concise responses about project management, coding, team collaboration, and engineering best practices.`;
        
        // Get last 10 messages for context
        const history = await getUserChatHistory(req.user.companyId, req.user.userId);
        const recentMessages = history.messages.slice(-10);
        
        const messages = [
            { role: 'system', content: systemPrompt },
            ...recentMessages.map(m => ({ role: m.role, content: m.content })),
            { role: 'user', content: message }
        ];
        
        // Call OpenAI with new API key
        const completion = await openai.chat.completions.create({
            model: model || 'gpt-3.5-turbo',
            messages: messages,
            temperature: 0.7,
            max_tokens: 500
        });
        
        const aiResponse = completion.choices[0].message.content;
        
        // Save AI response
        await saveUserChatMessage(req.user.companyId, req.user.userId, {
            role: 'assistant',
            content: aiResponse,
            model: model || 'gpt-3.5-turbo',
            tokens: completion.usage?.total_tokens,
            userName: 'AI Assistant'
        });
        
        res.json({
            message: aiResponse,
            model: model || 'gpt-3.5-turbo',
            tokens: completion.usage?.total_tokens
        });
        
    } catch (error) {
        console.error('Error in chat:', error);
        
        if (error.code === 'insufficient_quota') {
            res.status(429).json({ error: 'OpenAI API quota exceeded. Please check your billing.' });
        } else if (error.code === 'invalid_api_key') {
            res.status(401).json({ error: 'Invalid OpenAI API key' });
        } else {
            res.status(500).json({ error: 'Failed to get AI response' });
        }
    }
});

// Get user's chat history
app.get('/api/chat/history', authenticateToken, async (req, res) => {
    try {
        const history = await getUserChatHistory(req.user.companyId, req.user.userId);
        res.json(history);
    } catch (error) {
        console.error('Error loading chat history:', error);
        res.status(500).json({ error: 'Failed to load chat history' });
    }
});

// Get all chats in company (admin only)
app.get('/api/chat/company/all', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const chats = await getAllCompanyChats(req.user.companyId);
        res.json(chats);
    } catch (error) {
        console.error('Error loading company chats:', error);
        res.status(500).json({ error: 'Failed to load company chats' });
    }
});

// Get specific user's chat (admin only)
app.get('/api/chat/user/:userId', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        const history = await getUserChatHistory(req.user.companyId, userId);
        res.json(history);
    } catch (error) {
        console.error('Error loading user chat:', error);
        res.status(500).json({ error: 'Failed to load user chat' });
    }
});

// Clear user's chat history
app.delete('/api/chat/history', authenticateToken, async (req, res) => {
    try {
        const user = await getUserById(req.user.companyId, req.user.userId);
        const chatPath = getUserChatPath(req.user.companyId, req.user.userId);
        
        const emptyHistory = {
            userId: req.user.userId,
            userName: user ? user.fullName : 'Unknown User',
            userEmail: user ? user.email : '',
            lastUpdated: new Date().toISOString(),
            totalMessages: 0,
            messages: []
        };
        
        await fs.writeFile(chatPath, JSON.stringify(emptyHistory, null, 2));
        res.json({ message: 'Chat history cleared' });
    } catch (error) {
        console.error('Error clearing chat history:', error);
        res.status(500).json({ error: 'Failed to clear chat history' });
    }
});

// ==================== COMPANY SETTINGS ====================

app.get('/api/company/settings', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const settings = await readCompanySettings(req.user.companyId);
        res.json(settings);
        
    } catch (error) {
        console.error('Error fetching settings:', error);
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});

app.put('/api/company/settings', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { timezone, dateFormat, weekStartsOn } = req.body;
        
        const settings = await readCompanySettings(req.user.companyId);
        
        if (timezone) settings.timezone = timezone;
        if (dateFormat) settings.dateFormat = dateFormat;
        if (weekStartsOn) settings.weekStartsOn = weekStartsOn;
        
        settings.updatedAt = new Date().toISOString();
        settings.updatedBy = req.user.userId;
        
        await writeCompanySettings(req.user.companyId, settings);
        
        res.json({
            message: 'Settings updated successfully',
            settings
        });
        
    } catch (error) {
        console.error('Error updating settings:', error);
        res.status(500).json({ error: 'Failed to update settings' });
    }
});

// ==================== ADMIN DASHBOARD ====================

app.get('/api/admin/companies', async (req, res) => {
    try {
        const master = await readMaster();
        const companies = [];
        
        for (const company of master.companies) {
            const users = await readCompanyUsers(company.id);
            companies.push({
                ...company,
                userCount: users.length,
                activeUsers: users.filter(u => u.status === 'active').length,
                onlineNow: users.filter(u => u.lastActive && 
                    new Date(u.lastActive).getTime() > Date.now() - 5 * 60 * 1000).length
            });
        }
        
        res.json({
            companies,
            stats: master.stats
        });
    } catch (error) {
        console.error('Error fetching companies:', error);
        res.status(500).json({ error: 'Failed to fetch companies' });
    }
});

// ==================== UTILITY FUNCTIONS ====================

function generateSecurePassword() {
    const length = 12;
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    let password = "";
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * charset.length);
        password += charset[randomIndex];
    }
    return password;
}

// ==================== HEALTH CHECK ====================

app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        environment: process.env.NODE_ENV || 'development',
        baseUrl: getBaseUrl(req)
    });
});

// ==================== SERVER START ====================

app.listen(PORT, () => {
    console.log(`\n🚀 Server is running on port ${PORT}`);
    console.log(`📁 Data directory: ${DATA_DIR}`);
    console.log(`📁 Companies directory: ${COMPANIES_DIR}`);
    console.log(`📁 Chats directory: ${CHATS_DIR}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🤖 OpenAI: ${process.env.OPENAI_API_KEY ? 'Configured with new key' : 'Not configured'}`);
    console.log(`📧 Email: ${process.env.EMAIL_USER ? 'Configured' : 'Not configured'}`);
    console.log(`\n📡 Endpoints:`);
    console.log(`   - Health: http://localhost:${PORT}/api/health`);
    console.log(`   - Auth: http://localhost:${PORT}/api/auth/*`);
    console.log(`   - OTP: http://localhost:${PORT}/api/otp/*`);
    console.log(`   - Team: http://localhost:${PORT}/api/team/*`);
    console.log(`   - Chat: http://localhost:${PORT}/api/chat/*`);
    console.log(`   - User: http://localhost:${PORT}/api/user/*`);
    console.log(`   - Admin: http://localhost:${PORT}/api/admin/companies`);
    console.log(`\n✅ Chat history saved by username in: ${CHATS_DIR}`);
    console.log(`   Format: /data/chats/[companyId]/[userId].json`);
    console.log(`   Each file contains user name, email, and full chat history\n`);
});

module.exports = app;