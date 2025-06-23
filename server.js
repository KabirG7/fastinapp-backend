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

// CORS Configuration - Fixed for Railway
app.use(cors({
  origin: [
    'https://fastinapp-frontend-production.up.railway.app',
    'http://localhost:3000',
    'http://localhost:5173'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// Health check endpoint
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
    timestamp: new Date().toISOString(),
    mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// MongoDB connection with better error handling
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://MoviesUser:123@maincluster.da70ufc.mongodb.net/fasting?retryWrites=true&w=majority';

console.log('🔗 Connecting to MongoDB...');
mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  maxPoolSize: 10,
  serverSelectionTimeoutMS: 5000,
  socketTimeoutMS: 45000,
})
.then(() => {
  console.log('✅ Connected to MongoDB successfully');
})
.catch(err => {
  console.error('❌ MongoDB connection error:', err.message);
});

// Handle MongoDB connection errors after initial connection
mongoose.connection.on('error', (err) => {
  console.error('❌ MongoDB connection error:', err.message);
});

mongoose.connection.on('disconnected', () => {
  console.log('⚠️ MongoDB disconnected');
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

// Test route for debugging
app.post('/api/test', (req, res) => {
  console.log('📨 Test POST request received');
  res.json({ 
    message: 'POST request successful!',
    timestamp: new Date().toISOString()
  });
});

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    console.log('📝 Registration attempt:', { username: req.body.username, email: req.body.email });
    
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });

    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      email,
      password: hashedPassword
    });

    const savedUser = await newUser.save();
    console.log('✅ User created successfully:', savedUser.username);

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

app.post('/api/auth/login', async (req, res) => {
  try {
    console.log('🔐 Login attempt:', { username: req.body.username });
    
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const user = await User.findOne({ 
      $or: [{ username }, { email: username }] 
    });

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

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

// Fasting Routes
app.get('/api/fasting/sessions', authenticateToken, async (req, res) => {
  try {
    console.log('📊 Fetching fasting sessions for user:', req.user.username);
    
    const sessions = await FastingSession.find({ userId: req.user.userId })
      .sort({ createdAt: -1 })
      .limit(10);
    
    console.log('✅ Found', sessions.length, 'sessions');
    res.json(sessions);
  } catch (error) {
    console.error('❌ Error fetching sessions:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/fasting/start', authenticateToken, async (req, res) => {
  try {
    console.log('🏁 Starting new fasting session for:', req.user.username);
    
    const { protocol, durationHours } = req.body;
    
    if (!protocol || !durationHours) {
      return res.status(400).json({ error: 'Protocol and duration are required' });
    }

    const activeSession = await FastingSession.findOne({
      userId: req.user.userId,
      status: 'active'
    });

    if (activeSession) {
      return res.status(400).json({ error: 'You already have an active fasting session' });
    }

    const newSession = new FastingSession({
      userId: req.user.userId,
      username: req.user.username,
      protocol,
      durationHours,
      startTime: new Date(),
      status: 'active'
    });

    const savedSession = await newSession.save();
    console.log('✅ Fasting session started:', savedSession._id);
    
    res.status(201).json(savedSession);
  } catch (error) {
    console.error('❌ Error starting fasting session:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/fasting/current', authenticateToken, async (req, res) => {
  try {
    console.log('🔍 Getting current session for:', req.user.username);
    
    const activeSession = await FastingSession.findOne({
      userId: req.user.userId,
      status: 'active'
    });

    if (!activeSession) {
      return res.json({ message: 'No active fasting session' });
    }

    res.json(activeSession);
  } catch (error) {
    console.error('❌ Error fetching current session:', error);
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/fasting/end/:sessionId', authenticateToken, async (req, res) => {
  try {
    console.log('🏁 Ending fasting session:', req.params.sessionId);
    
    const session = await FastingSession.findOne({
      _id: req.params.sessionId,
      userId: req.user.userId,
      status: 'active'
    });

    if (!session) {
      return res.status(404).json({ error: 'Active session not found' });
    }

    session.endTime = new Date();
    session.status = 'completed';
    
    const updatedSession = await session.save();
    console.log('✅ Session completed:', updatedSession._id);
    
    res.json(updatedSession);
  } catch (error) {
    console.error('❌ Error ending session:', error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/fasting/cancel/:sessionId', authenticateToken, async (req, res) => {
  try {
    console.log('❌ Cancelling fasting session:', req.params.sessionId);
    
    const session = await FastingSession.findOne({
      _id: req.params.sessionId,
      userId: req.user.userId,
      status: 'active'
    });

    if (!session) {
      return res.status(404).json({ error: 'Active session not found' });
    }

    session.status = 'cancelled';
    
    const updatedSession = await session.save();
    console.log('✅ Session cancelled:', updatedSession._id);
    
    res.json(updatedSession);
  } catch (error) {
    console.error('❌ Error cancelling session:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get user stats
app.get('/api/fasting/stats', authenticateToken, async (req, res) => {
  try {
    console.log('📈 Getting stats for:', req.user.username);
    
    const completedSessions = await FastingSession.find({
      userId: req.user.userId,
      status: 'completed'
    });

    const totalSessions = completedSessions.length;
    const totalHours = completedSessions.reduce((sum, session) => {
      return sum + session.durationHours;
    }, 0);

    const stats = {
      totalSessions,
      totalHours,
      averageHours: totalSessions > 0 ? Math.round(totalHours / totalSessions) : 0,
      longestFast: completedSessions.length > 0 
        ? Math.max(...completedSessions.map(s => s.durationHours)) 
        : 0
    };

    res.json(stats);
  } catch (error) {
    console.error('❌ Error fetching stats:', error);
    res.status(500).json({ error: error.message });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('💥 Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Fasting Tracker Server running on http://0.0.0.0:${PORT}`);
  console.log(`🌍 Health check: http://0.0.0.0:${PORT}/api/health`);
}).on('error', (err) => {
  console.error('❌ Server failed to start:', err);
});