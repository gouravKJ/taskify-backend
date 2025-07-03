const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const cors = require('cors');
const http = require('http');
const socketIo = require('socket.io');
require('dotenv').config();

const server = http.createServer(app);
const io = socketIo(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(() => console.log("Connection error"));

// schemas
const userSchema = mongoose.Schema({
  username: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});
const User = mongoose.model('user', userSchema);

const taskSchema = mongoose.Schema({
  title: { type: String, required: true },
  description: String,
  assigneduser: { type: mongoose.Schema.Types.ObjectId, ref: 'user' },
  status: { type: String, enum: ['Todo', 'In Progress', 'Done'], default: 'Todo' },
  priority: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' }
}, { timestamps: true });
const Task = mongoose.model('task', taskSchema);

const actionLogSchema = mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'user' },
  task: { type: mongoose.Schema.Types.ObjectId, ref: 'task' },
  action: String,
  timeStamp: { type: Date, default: Date.now }
});
const ActionLog = mongoose.model('actionlog', actionLogSchema);

// middleware
const auth = async (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded.id;
    next();
  } catch (err) {
    return res.status(401).json({ message: 'Invalid token' });
  }
};

// Routes
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: 'User already exists' });

    const hashed = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashed });
    await newUser.save();
    res.json(newUser);
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const found = await User.findOne({ email });
    if (!found) return res.status(400).json({ message: 'User not found' });

    const match = await bcrypt.compare(password, found.password);
    if (!match) return res.status(400).json({ message: 'Invalid credentials' });

    const token = jwt.sign({ id: found._id }, process.env.JWT_SECRET);
    res.json({ token, userId: found._id });
  } catch (err) {
    res.status(500).json({ message: 'Server error' });
  }
});

//all users
app.get('/api/users', auth, async (req, res) => {
  const users = await User.find({}, 'username');
  res.json(users);
});

//all tasks with assigned user populated
app.get('/api/tasks', auth, async (req, res) => {
  const tasks = await Task.find().populate('assigneduser', 'username');
  res.json(tasks);
});

//activity logs with user populated
app.get('/api/tasks/logs', auth, async (req, res) => {
  const logs = await ActionLog.find()
    .sort({ timeStamp: -1 })
    .limit(20)
    .populate('user', 'username')
    .populate('task', 'title');
  res.json(logs);
});

//socket connection
io.on('connection', (socket) => {
  console.log('🟢 user connected:', socket.id);

  // Add Task
  socket.on('addtask', async (data) => {
    if (!data.assigneduser) delete data.assigneduser;

    const createdTask = await Task.create(data);
    const newTask = await Task.findById(createdTask._id).populate('assigneduser', 'username');

    await ActionLog.create({
      user: data.assigneduser || null,
      task: newTask._id,
      action: 'created',
    });

    io.emit('taskadded', newTask);
  });

  //  Update Task
  socket.on('updatetask', async ({ taskId, updates, userId }) => {
    if (updates.assigneduser === '') {
      delete updates.assigneduser;
    }

    const updatedTask = await Task.findByIdAndUpdate(taskId, updates, { new: true }).populate('assigneduser', 'username');

    await ActionLog.create({
      user: userId,
      task: taskId,
      action: 'updated',
    });

    io.emit('taskupdated', updatedTask);
  });

  // Delete Task
  socket.on('deletetask', async ({ taskId, userId }) => {
    await Task.findByIdAndDelete(taskId);
    await ActionLog.create({
      user: userId,
      task: taskId,
      action: 'deleted',
    });

    io.emit('taskdeleted', taskId);
  });

  socket.on('disconnect', () => {
    console.log('🔴 user disconnected:', socket.id);
  });
});


const PORT = process.env.PORT || 3000;
server.listen(PORT,'0.0.0.0',() => {
  console.log(`server running at ${PORT}`);
});
