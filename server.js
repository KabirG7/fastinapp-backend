const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

// Debug logging
console.log('🚀 Starting server...');
console.log('📡 Port:', PORT);
console.log('🔐 JWT Secret exists:', !!JWT_SECRET);
console.log('🌍 Environment:', process.env.NODE_ENV || 'development');

// CORS Configuration - Allow all for now to test
app.use(cors({
  origin: true, // Allow all origins for debugging
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// Health check endpoint - MUST WORK
app.get('/', (req, res) => {
  res.json({ 
    status: 'Server is running!', 
    timestamp: new Date().toISOString(),
    port: PORT 
  });
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'API is healthy!', 
    timestamp: new Date().toISOString() 
  });
});

// MongoDB connection with better error handling
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://mongo:WUMdxkOIsKhXSHCoQtfMplBesCmYTmYS@tramway.proxy.rlwy.net:35416';

console.log('🔗 Connecting to MongoDB...');
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => {
  console.log('✅ Connected to MongoDB successfully');
})
.catch(err => {
  console.error('❌ MongoDB connection error:', err.message);
  // Don't exit - let the app run without DB for debugging
});

// User schema
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const User = mongoose.model('User', userSchema);

// Fasting Session schema
const fastingSessionSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  username: {
    type: String,
    required: true
  },
  protocol: {
    type: String,
    required: true,
    enum: ['12:12', '14:10', '16:8', '18:6', '20:4']
  },
  durationHours: {
    type: Number,
    required: true
  },
  startTime: {
    type: Date,
    required: true
  },
  endTime: {
    type: Date
  },
  status: {
    type: String,
    default: 'active',
    enum: ['active', 'completed', 'cancelled']
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const FastingSession = mongoose.model('FastingSession', fastingSessionSchema);

// Auth middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error('JWT verification failed:', err.message);
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Test route for debugging CORS
app.post('/api/test', (req, res) => {
  console.log('📨 Test POST request received');
  console.log('Headers:', req.headers);
  console.log('Body:', req.body);
  res.json({ 
    message: 'POST request successful!',
    receivedData: req.body,
    timestamp: new Date().toISOString()
  });
});

// Auth Routes with better error logging
app.post('/api/auth/register', async (req, res) => {
  try {
    console.log('📝 Registration attempt:', { username: req.body.username, email: req.body.email });
    
    const { username, email, password } = req.body;

    // Validation
    if (!username || !email || !password) {
      console.log('❌ Validation failed: Missing fields');
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password.length < 6) {
      console.log('❌ Validation failed: Password too short');
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });

    if (existingUser) {
      console.log('❌ User already exists');
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create user
    const newUser = new User({
      username,
      email,
      password: hashedPassword
    });

    const savedUser = await newUser.save();
    console.log('✅ User created successfully:', savedUser.username);

    // Generate token
    const token = jwt.sign(
      { userId: savedUser._id, username: savedUser.username },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: savedUser._id,
        username: savedUser.username,
        email: savedUser.email
      }
    });
  } catch (error) {
    console.error('❌ Registration error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Login with better logging
app.post('/api/auth/login', async (req, res) => {
  try {
    console.log('🔐 Login attempt:', { username: req.body.username });
    
    const { username, password } = req.body;

    if (!username || !password) {
      console.log('❌ Login failed: Missing credentials');
      return res.status(400).json({ error: 'Username and password are required' });
    }

    // Find user
    const user = await User.findOne({ 
      $or: [{ username }, { email: username }] 
    });

    if (!user) {
      console.log('❌ Login failed: User not found');
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      console.log('❌ Login failed: Invalid password');
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    console.log('✅ Login successful:', user.username);

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error('❌ Login error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Add all your other routes here (fasting routes)...
// [Include all the fasting routes from your original code]

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('💥 Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server with better error handling
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Fasting Tracker Server running on http://0.0.0.0:${PORT}`);
  console.log(`🌍 Health check: http://0.0.0.0:${PORT}/api/health`);
}).on('error', (err) => {
  console.error('❌ Server failed to start:', err);
});