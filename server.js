const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = 'your-secret-key-change-this-in-production';

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Atlas connection
mongoose.connect('mongodb+srv://MoviesUser:123@maincluster.da70ufc.mongodb.net/fasting?retryWrites=true&w=majority', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

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
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Auth Routes
// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });

    if (existingUser) {
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
    res.status(500).json({ error: error.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    // Find user
    const user = await User.findOne({ 
      $or: [{ username }, { email: username }] 
    });

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

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
    res.status(500).json({ error: error.message });
  }
});

// Fasting Routes
// Get active fasting session
app.get('/api/fasting/active', authenticateToken, async (req, res) => {
  try {
    const activeSession = await FastingSession.findOne({
      userId: req.user.userId,
      status: 'active'
    }).sort({ createdAt: -1 });

    res.json(activeSession);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Start new fasting session
app.post('/api/fasting/start', authenticateToken, async (req, res) => {
  try {
    const { protocol, durationHours } = req.body;

    if (!protocol || !durationHours) {
      return res.status(400).json({ error: 'Protocol and duration are required' });
    }

    // Check if user already has an active session
    const existingSession = await FastingSession.findOne({
      userId: req.user.userId,
      status: 'active'
    });

    if (existingSession) {
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
    res.status(201).json(savedSession);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// End fasting session
app.put('/api/fasting/end', authenticateToken, async (req, res) => {
  try {
    const activeSession = await FastingSession.findOneAndUpdate(
      {
        userId: req.user.userId,
        status: 'active'
      },
      {
        endTime: new Date(),
        status: 'completed'
      },
      { new: true }
    );

    if (!activeSession) {
      return res.status(404).json({ error: 'No active fasting session found' });
    }

    res.json({
      message: 'Fasting session completed successfully',
      session: activeSession
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Cancel fasting session
app.put('/api/fasting/cancel', authenticateToken, async (req, res) => {
  try {
    const activeSession = await FastingSession.findOneAndUpdate(
      {
        userId: req.user.userId,
        status: 'active'
      },
      {
        endTime: new Date(),
        status: 'cancelled'
      },
      { new: true }
    );

    if (!activeSession) {
      return res.status(404).json({ error: 'No active fasting session found' });
    }

    res.json({
      message: 'Fasting session cancelled',
      session: activeSession
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get fasting history
app.get('/api/fasting/history', authenticateToken, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 10;
    const sessions = await FastingSession.find({ userId: req.user.userId })
      .sort({ createdAt: -1 })
      .limit(limit);

    res.json(sessions);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get fasting stats
app.get('/api/fasting/stats', authenticateToken, async (req, res) => {
  try {
    const totalSessions = await FastingSession.countDocuments({ userId: req.user.userId });
    const completedSessions = await FastingSession.countDocuments({ 
      userId: req.user.userId, 
      status: 'completed' 
    });
    
    const recentSessions = await FastingSession.find({ 
      userId: req.user.userId,
      status: 'completed',
      createdAt: { $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } // Last 30 days
    });

    const totalHoursFasted = recentSessions.reduce((total, session) => {
      if (session.endTime && session.startTime) {
        const duration = (session.endTime - session.startTime) / (1000 * 60 * 60);
        return total + duration;
      }
      return total;
    }, 0);

    res.json({
      totalSessions,
      completedSessions,
      completionRate: totalSessions > 0 ? Math.round((completedSessions / totalSessions) * 100) : 0,
      totalHoursFasted: Math.round(totalHoursFasted * 100) / 100,
      recentSessionsCount: recentSessions.length
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.listen(PORT, () => {
  console.log(`Fasting Tracker Server running on http://localhost:${PORT}`);
});