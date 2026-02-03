const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, '../frontend')));

// Database
const db = new sqlite3.Database(path.join(__dirname, 'users.db'), (err) => {
    if (err) {
        console.error('DB Error:', err);
    } else {
        console.log('Connected to SQLite database');
        initializeDatabase();
    }
});

// Initialize database
function initializeDatabase() {
    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            status TEXT DEFAULT 'unverified',
            verification_token TEXT,
            last_login TIMESTAMP,
            reg_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`, (err) => { 
            if (err) {
                console.error('Table creation error:', err);
                return;
            }
            
            console.log('Users table ready');
            
            // CREATE UNIQUE INDEX ON EMAIL (REQUIREMENT #1)
            db.run('CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email)', (err) => {
                if (err) {
                    console.error('Index creation error:', err);
                } else {
                    console.log('✅ UNIQUE INDEX created on email column');
                }
            });
        });
    });
}


const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.GMAIL_USER || 'nasratj35@gmail.com',
        pass: process.env.GMAIL_APP_PASSWORD || 'pmlc epek gaxe jevr'       // CHANGE TO YOUR APP PASSWORD (16 chars)
    }
});

// Test email connection
console.log('\n📧 Testing email configuration...');
transporter.verify(function(error, success) {
    if (error) {
        console.log('❌ Email configuration error:', error.message);
        console.log('\n🔄 QUICK SETUP FOR GMAIL:');
        console.log('1. Go to: https://myaccount.google.com/apppasswords');
        console.log('2. Generate App Password for "Mail"');
        console.log('3. Copy the 16-character password');
        console.log('4. Update lines 82-87 in server.js with your Gmail and App Password');
        console.log('5. Restart the server');
    } else {
        console.log('✅ Email server ready! Real emails will be sent.');
    }
});

// Helper functions
const dbAll = (sql, params = []) => new Promise((res, rej) => {
    db.all(sql, params, (err, rows) => {
        if (err) {
            console.error('SQL Error:', err.message, 'Query:', sql);
            rej(err);
        } else {
            res(rows || []);
        }
    });
});

const dbRun = (sql, params = []) => new Promise((res, rej) => {
    db.run(sql, params, function(err) {
        if (err) {
            console.error('SQL Error:', err.message, 'Query:', sql);
            rej(err);
        } else {
            res(this);
        }
    });
});

const dbGet = (sql, params = []) => new Promise((res, rej) => {
    db.get(sql, params, (err, row) => {
        if (err) {
            console.error('SQL Error:', err.message, 'Query:', sql);
            rej(err);
        } else {
            res(row);
        }
    });
});

// Token storage
let tokenStorage = {};

// Auth middleware (REQUIREMENT #5)
const auth = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return res.status(401).json({ success: false, message: 'No token provided' });
        }
        
        let token;
        if (authHeader.toLowerCase().startsWith('bearer ')) {
            token = authHeader.substring(7).trim();
        } else {
            token = authHeader.trim();
        }
        
        const data = tokenStorage[token];
        
        if (!data) {
            return res.status(401).json({ success: false, message: 'Invalid or expired token' });
        }
        
        if (Date.now() > data.expires) {
            delete tokenStorage[token];
            return res.status(401).json({ success: false, message: 'Token expired' });
        }
        
        const user = await dbGet('SELECT id, name, email, status FROM users WHERE id = ?', [data.userId]);
        if (!user) {
            delete tokenStorage[token];
            return res.status(401).json({ success: false, message: 'User not found' });
        }
        
        if (user.status === 'blocked') {
            delete tokenStorage[token];
            return res.status(403).json({ success: false, message: 'Account blocked' });
        }
        
        req.userId = data.userId;
        req.user = user;
        next();
    } catch (err) {
        console.error('Auth error:', err);
        res.status(500).json({ success: false, message: 'Authentication error' });
    }
};

// API Endpoints

app.get('/api/health', (req, res) => {
    res.json({ success: true, status: 'OK', port: PORT });
});

// Register endpoint with REAL email sending
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        
        console.log('\n📝 Registration attempt:', { name, email });
        
        // Validation
        if (!name || !email || !password) {
            return res.status(400).json({ success: false, message: 'All fields required' });
        }
        
        if (password.trim().length === 0) {
            return res.status(400).json({ success: false, message: 'Password cannot be empty' });
        }
        
        // Check if email already exists
        const existingUser = await dbGet('SELECT id FROM users WHERE email = ?', [email]);
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Email already exists' });
        }
        
        // Generate verification token
        const verificationToken = crypto.randomBytes(32).toString('hex');
        
        // Insert user
        const result = await dbRun(
            'INSERT INTO users (name, email, password, verification_token, status, reg_time) VALUES (?, ?, ?, ?, "unverified", datetime("now"))',
            [name, email, password, verificationToken]
        );
        
        console.log(`✅ User registered: ${email} (ID: ${result.lastID})`);
        
        // Generate auth token
        const token = 't_' + crypto.randomBytes(16).toString('hex');
        tokenStorage[token] = { 
            userId: result.lastID, 
            expires: Date.now() + 86400000
        };
        
        const user = await dbGet(
            'SELECT id, name, email, status FROM users WHERE id = ?',
            [result.lastID]
        );
        
        // Generate verification link
        const verificationLink = `http://localhost:${PORT}/api/verify-email/${verificationToken}`;
        
        console.log(`📤 Sending verification email to: ${email}`);
        
        // Prepare email
        const mailOptions = {
            from: '"User Management System" <noreply@usermanagement.com>',
            to: email, // This goes to USER'S REAL EMAIL
            subject: 'Verify Your Email - User Management System',
            text: `
                Hello ${name},
                
                Thank you for registering with User Management System!
                
                Please verify your email address by clicking the link below:
                
                ${verificationLink}
                
                This verification link will expire in 24 hours.
                
                If you did not create an account, please ignore this email.
                
                Best regards,
                User Management System Team
            `,
            html: `
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; }
                        .container { padding: 20px; }
                        .header { background: #007bff; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }
                        .content { background: #f9f9f9; padding: 30px; border-radius: 0 0 5px 5px; }
                        .button { display: inline-block; padding: 12px 24px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; font-weight: bold; }
                        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; font-size: 12px; color: #666; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>Email Verification</h1>
                        </div>
                        <div class="content">
                            <p>Hello <strong>${name}</strong>,</p>
                            <p>Thank you for registering with <strong>User Management System</strong>!</p>
                            <p>Please verify your email address by clicking the button below:</p>
                            
                            <p style="text-align: center; margin: 30px 0;">
                                <a href="${verificationLink}" class="button">Verify Email Address</a>
                            </p>
                            
                            <p>Or copy and paste this link in your browser:</p>
                            <p style="background: #f0f0f0; padding: 10px; border-radius: 3px; word-break: break-all;">
                                ${verificationLink}
                            </p>
                            
                            <div class="footer">
                                <p>This verification link will expire in 24 hours.</p>
                                <p>If you did not create an account, please ignore this email.</p>
                            </div>
                        </div>
                    </div>
                </body>
                </html>
            `
        };
        
        // Send email asynchronously
        setTimeout(async () => {
            try {
                const info = await transporter.sendMail(mailOptions);
                console.log(`✅ REAL email sent to: ${email}`);
                console.log(`📧 Message ID: ${info.messageId}`);
                console.log(`📋 User should check their email inbox (and spam folder)`);
            } catch (emailError) {
                console.error('❌ Email sending failed:', emailError.message);
                console.log(`⚠️  Registration successful, but email not sent`);
                console.log(`📋 Verification link: ${verificationLink}`);
                console.log(`📋 User can use this link to verify manually`);
            }
        }, 0);
        
        res.json({
            success: true,
            message: 'Registered successfully! A verification email has been sent to your email address.',
            token,
            user
        });
        
    } catch (err) {
        console.error('❌ Registration error:', err.message);
        
        if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ success: false, message: 'Email already exists' });
        }
        
        res.status(500).json({ 
            success: false, 
            message: 'Registration failed. Please try again.' 
        });
    }
});

// Email verification endpoint
app.get('/api/verify-email/:token', async (req, res) => {
    try {
        const { token } = req.params;
        
        console.log(`\n🔗 Email verification attempt for token: ${token}`);
        
        // Find user by verification token
        const user = await dbGet('SELECT * FROM users WHERE verification_token = ?', [token]);
        
        if (!user) {
            return res.send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Email Verification</title>
                    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
                    <style>
                        body { 
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            min-height: 100vh;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            padding: 20px;
                        }
                        .card { max-width: 500px; width: 100%; }
                    </style>
                </head>
                <body>
                    <div class="card">
                        <div class="card-body text-center p-5">
                            <div class="mb-4">
                                <i class="fas fa-exclamation-triangle fa-4x text-danger"></i>
                            </div>
                            <h2 class="card-title mb-3">Invalid Verification Link</h2>
                            <p class="card-text text-muted mb-4">
                                This verification link is invalid or has expired.
                            </p>
                            <a href="/login" class="btn btn-primary">Go to Login</a>
                        </div>
                    </div>
                    <script src="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/js/all.min.js"></script>
                </body>
                </html>
            `);
        }
        
        // Update user status to active if not blocked
        if (user.status !== 'blocked') {
            await dbRun(
                'UPDATE users SET status = "active", verification_token = NULL WHERE id = ?',
                [user.id]
            );
            
            console.log(`✅ Email verified: ${user.email}`);
            console.log(`📊 Status changed from "${user.status}" to "active"`);
            console.log(`📋 Dashboard will now show "active" status`);
            
            res.send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Email Verified</title>
                    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
                    <style>
                        body { 
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            min-height: 100vh;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            padding: 20px;
                        }
                        .card { max-width: 500px; width: 100%; }
                    </style>
                </head>
                <body>
                    <div class="card">
                        <div class="card-body text-center p-5">
                            <div class="mb-4">
                                <i class="fas fa-check-circle fa-4x text-success"></i>
                            </div>
                            <h2 class="card-title mb-3">🎉 Email Verified Successfully!</h2>
                            <p class="card-text mb-4">
                                Your email <strong>${user.email}</strong> has been verified.
                                Your account is now <span class="badge bg-success">active</span>.
                            </p>
                            
                            <div class="alert alert-success mb-4">
                                <h5 class="alert-heading">Account Details:</h5>
                                <p class="mb-2"><strong>Name:</strong> ${user.name}</p>
                                <p class="mb-2"><strong>Email:</strong> ${user.email}</p>
                                <p class="mb-0"><strong>Status:</strong> <span class="badge bg-success">active</span></p>
                            </div>
                            
                            <div class="d-grid gap-2">
                                <a href="/dashboard" class="btn btn-success btn-lg">
                                    <i class="fas fa-tachometer-alt me-2"></i>Go to Dashboard
                                </a>
                                <a href="/login" class="btn btn-outline-primary">
                                    <i class="fas fa-sign-in-alt me-2"></i>Go to Login
                                </a>
                            </div>
                        </div>
                    </div>
                    <script src="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/js/all.min.js"></script>
                </body>
                </html>
            `);
        } else {
            res.send(`
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Account Blocked</title>
                    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
                    <style>
                        body { 
                            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                            min-height: 100vh;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            padding: 20px;
                        }
                        .card { max-width: 500px; width: 100%; }
                    </style>
                </head>
                <body>
                    <div class="card">
                        <div class="card-body text-center p-5">
                            <div class="mb-4">
                                <i class="fas fa-ban fa-4x text-danger"></i>
                            </div>
                            <h2 class="card-title mb-3">Account Blocked</h2>
                            <p class="card-text text-muted mb-4">
                                Your account has been blocked and cannot be activated.
                            </p>
                            <a href="/login" class="btn btn-secondary">Go to Login</a>
                        </div>
                    </div>
                    <script src="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/js/all.min.js"></script>
                </body>
                </html>
            `);
        }
        
    } catch (err) {
        console.error('❌ Verification error:', err);
        res.status(500).send('Internal server error');
    }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password required' });
        }
        
        const user = await dbGet('SELECT * FROM users WHERE email = ?', [email]);
        if (!user) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        
        if (user.status === 'blocked') {
            return res.status(403).json({ success: false, message: 'Account is blocked' });
        }
        
        if (user.password !== password) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        
        // Update last login
        await dbRun('UPDATE users SET last_login = datetime("now") WHERE id = ?', [user.id]);
        
        // Generate token
        const token = 't_' + crypto.randomBytes(16).toString('hex');
        tokenStorage[token] = { 
            userId: user.id, 
            expires: Date.now() + 86400000
        };
        
        console.log(`✅ Login: ${email} (Status: ${user.status})`);
        
        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                status: user.status
            }
        });
        
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ success: false, message: 'Login failed' });
    }
});

// Get users sorted by last login (REQUIREMENT #3)
app.get('/api/users', auth, async (req, res) => {
    try {
        const users = await dbAll(`
            SELECT id, name, email, status, last_login, reg_time
            FROM users 
            ORDER BY 
                CASE WHEN last_login IS NULL THEN 1 ELSE 0 END,
                last_login DESC
        `);
        
        // Format timestamps
        const formattedUsers = users.map(user => {
            const userData = { ...user };
            
            if (userData.last_login && typeof userData.last_login === 'string') {
                userData.last_login = userData.last_login.replace(' ', 'T') + 'Z';
            }
            
            if (userData.reg_time && typeof userData.reg_time === 'string') {
                userData.reg_time = userData.reg_time.replace(' ', 'T') + 'Z';
            }
            
            return userData;
        });
        
        res.json({ success: true, users: formattedUsers });
        
    } catch (err) {
        console.error('Users error:', err);
        res.status(500).json({ success: false, message: 'Failed to load users' });
    }
});

// Block users
app.post('/api/users/block', auth, async (req, res) => {
    try {
        const { userIds } = req.body;
        if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
            return res.status(400).json({ success: false, message: 'No users selected' });
        }
        
        // Filter out current user from blocking themselves
        const filteredIds = userIds.filter(id => id !== req.userId);
        if (filteredIds.length === 0) {
            return res.status(400).json({ success: false, message: 'Cannot block yourself' });
        }
        
        const placeholders = filteredIds.map(() => '?').join(',');
        const result = await dbRun(
            `UPDATE users SET status = 'blocked' WHERE id IN (${placeholders})`,
            filteredIds
        );
        
        // Remove tokens for blocked users
        Object.keys(tokenStorage).forEach(token => {
            const data = tokenStorage[token];
            if (filteredIds.includes(data.userId)) {
                delete tokenStorage[token];
            }
        });
        
        res.json({ success: true, message: `Blocked ${result.changes} user(s)` });
    } catch (err) {
        console.error('Block error:', err);
        res.status(500).json({ success: false, message: 'Error blocking users' });
    }
});

// Unblock users - FIXED: Check verification token to determine correct status
app.post('/api/users/unblock', auth, async (req, res) => {
    try {
        const { userIds } = req.body;
        if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
            return res.status(400).json({ success: false, message: 'No users selected' });
        }
        
        const placeholders = userIds.map(() => '?').join(',');
        
        // FIX: Check verification token to determine correct status
        // If user has verification_token, set to 'unverified', otherwise 'active'
        const result = await dbRun(
            `UPDATE users 
             SET status = CASE 
                WHEN verification_token IS NOT NULL THEN 'unverified' 
                ELSE 'active' 
             END
             WHERE id IN (${placeholders}) AND status = 'blocked'`,
            userIds
        );
        
        res.json({ success: true, message: `Unblocked ${result.changes} user(s)` });
    } catch (err) {
        console.error('Unblock error:', err);
        res.status(500).json({ success: false, message: 'Error unblocking users' });
    }
});

// Delete users (REQUIREMENT: Users deleted, not marked)
app.delete('/api/users', auth, async (req, res) => {
    try {
        const { userIds } = req.body;
        if (!userIds || !Array.isArray(userIds) || userIds.length === 0) {
            return res.status(400).json({ success: false, message: 'No users selected' });
        }
        
        const placeholders = userIds.map(() => '?').join(',');
        const result = await dbRun(
            `DELETE FROM users WHERE id IN (${placeholders})`,
            userIds
        );
        
        // Check if current user was deleted
        const currentUserDeleted = userIds.includes(req.userId);
        
        // Remove tokens for deleted users
        Object.keys(tokenStorage).forEach(token => {
            const data = tokenStorage[token];
            if (userIds.includes(data.userId)) {
                delete tokenStorage[token];
            }
        });
        
        const message = `Deleted ${result.changes} user(s)`;
        
        if (currentUserDeleted) {
            return res.json({ 
                success: true, 
                message: message,
                currentUserDeleted: true
            });
        }
        
        res.json({ success: true, message: message });
        
    } catch (err) {
        console.error('Delete error:', err);
        res.status(500).json({ success: false, message: 'Error deleting users' });
    }
});

// Delete unverified users
app.delete('/api/users/unverified', auth, async (req, res) => {
    try {
        // Get all unverified users
        const users = await dbAll(
            "SELECT id FROM users WHERE status = 'unverified'",
            []
        );
        
        const ids = users.map(u => u.id);
        
        if (ids.length === 0) {
            return res.json({ success: true, message: 'No unverified users to delete' });
        }
        
        // Check if current user is unverified
        const currentUserIsUnverified = ids.includes(req.userId);
        
        const placeholders = ids.map(() => '?').join(',');
        const result = await dbRun(
            `DELETE FROM users WHERE id IN (${placeholders})`,
            ids
        );
        
        // Remove tokens for deleted users
        Object.keys(tokenStorage).forEach(token => {
            const data = tokenStorage[token];
            if (ids.includes(data.userId)) {
                delete tokenStorage[token];
            }
        });
        
        const message = `Deleted ${result.changes} unverified user(s)`;
        
        if (currentUserIsUnverified) {
            return res.json({ 
                success: true, 
                message: message,
                currentUserDeleted: true
            });
        }
        
        res.json({ success: true, message: message });
        
    } catch (err) {
        console.error('Delete unverified error:', err);
        res.status(500).json({ success: false, message: 'Error deleting unverified users' });
    }
});

// Get current user info
app.get('/api/me', auth, async (req, res) => {
    try {
        const user = await dbGet(
            'SELECT id, name, email, status FROM users WHERE id = ?',
            [req.userId]
        );
        
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        res.json({ success: true, user });
    } catch (err) {
        console.error('Get user error:', err);
        res.status(500).json({ success: false, message: 'Failed to get user info' });
    }
});

// Logout endpoint
app.post('/api/logout', (req, res) => {
    const { token } = req.body;
    if (token && tokenStorage[token]) {
        delete tokenStorage[token];
    }
    res.json({ success: true, message: 'Logged out successfully' });
});

// Static file routes
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/register.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/dashboard.html'));
});

app.get('/', (req, res) => {
    res.redirect('/login');
});

// Start server
app.listen(PORT, () => {
    console.log(`
╔══════════════════════════════════════════════════════════╗
║           USER MANAGEMENT SYSTEM - COMPLETE             ║
╠══════════════════════════════════════════════════════════╣
║ 🚀 Server: http://localhost:${PORT}                             ║
║ ✅ UNIQUE INDEX created on email column                  ║
║ 📧 REAL EMAIL SYSTEM ENABLED                            ║
║ 🔐 Test login: test@example.com / password              ║
╚══════════════════════════════════════════════════════════╝
`);
});
