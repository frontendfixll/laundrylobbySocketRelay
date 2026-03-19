require('dotenv').config();

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const jwt = require('jsonwebtoken');

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET;
const RELAY_API_KEY = process.env.RELAY_API_KEY;

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

// ============================================
// CORS & Middleware
// ============================================
app.use(cors({ origin: ALLOWED_ORIGINS.length > 0 ? ALLOWED_ORIGINS : '*', credentials: true }));
app.use(express.json({ limit: '1mb' }));

// ============================================
// Socket.IO Server
// ============================================
const io = new Server(server, {
  cors: {
    origin: ALLOWED_ORIGINS.length > 0 ? ALLOWED_ORIGINS : '*',
    methods: ['GET', 'POST'],
    credentials: true
  },
  transports: ['websocket', 'polling'],
  pingInterval: 25000,
  pingTimeout: 20000
});

// ============================================
// Connection Tracking
// ============================================
// Maps: userId -> Set of socket IDs
const userSockets = new Map();
// Maps: socketId -> { userId, role, tenantId }
const socketMeta = new Map();

function addUserSocket(userId, socketId, meta) {
  if (!userSockets.has(userId)) {
    userSockets.set(userId, new Set());
  }
  userSockets.get(userId).add(socketId);
  socketMeta.set(socketId, { userId, ...meta });
}

function removeSocket(socketId) {
  const meta = socketMeta.get(socketId);
  if (meta) {
    const sockets = userSockets.get(meta.userId);
    if (sockets) {
      sockets.delete(socketId);
      if (sockets.size === 0) userSockets.delete(meta.userId);
    }
    socketMeta.delete(socketId);
  }
}

// ============================================
// Socket.IO Authentication Middleware
// ============================================
io.use((socket, next) => {
  const token = socket.handshake.auth?.token || socket.handshake.query?.token;

  if (!token) {
    return next(new Error('Authentication token required'));
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    // Support both User and SuperAdmin token formats
    socket.userId = decoded.userId || decoded.adminId || decoded.id;
    socket.userRole = decoded.role || socket.handshake.auth?.role || 'user';
    socket.tenantId = decoded.tenancy || decoded.tenantId || null;
    socket.userEmail = decoded.email || null;

    if (!socket.userId) {
      return next(new Error('Invalid token: no user ID'));
    }

    next();
  } catch (err) {
    return next(new Error('Invalid or expired token'));
  }
});

// ============================================
// Socket.IO Connection Handler
// ============================================
io.on('connection', (socket) => {
  const { userId, userRole, tenantId } = socket;

  console.log(`✅ Connected: ${userId} (${userRole}) [${socket.id}]`);

  // Track this connection
  addUserSocket(userId, socket.id, { role: userRole, tenantId });

  // Join user-specific room
  socket.join(`user:${userId}`);

  // Join role-based room
  if (userRole) {
    socket.join(`role:${userRole}`);
  }

  // Join tenant rooms
  if (tenantId) {
    socket.join(`tenant:${tenantId}`);
    if (userRole) {
      socket.join(`tenant:${tenantId}:role:${userRole}`);
    }
  }

  // Confirm connection to client
  socket.emit('connected', { userId, role: userRole, tenantId });
  socket.emit('connection_confirmed', { userId, role: userRole, tenantId });

  // ---- Client Events ----

  socket.on('ping', () => {
    socket.emit('pong');
  });

  socket.on('notification_ack', (data) => {
    console.log(`📬 ACK from ${userId}: ${data?.notificationId}`);
    socket.emit('ack_confirmed', { notificationId: data?.notificationId });
  });

  socket.on('markNotificationRead', (data) => {
    socket.emit('notificationMarkedRead', { notificationId: data?.notificationId, success: true });
  });

  socket.on('markMultipleAsRead', (data) => {
    socket.emit('notificationsMarkedRead', { notificationIds: data?.notificationIds, success: true });
  });

  socket.on('getUnreadCount', () => {
    // Relay doesn't have DB access — clients should fetch from API
    // But we emit 0 to satisfy the initial handshake
    socket.emit('unreadCount', { count: 0, source: 'relay' });
  });

  socket.on('joinRoom', (data) => {
    if (data?.room) {
      socket.join(data.room);
      socket.emit('roomJoined', { room: data.room });
    }
  });

  socket.on('leaveRoom', (data) => {
    if (data?.room) {
      socket.leave(data.room);
      socket.emit('roomLeft', { room: data.room });
    }
  });

  socket.on('subscribe_channel', (data) => {
    if (data?.channel) {
      socket.join(data.channel);
      socket.emit('subscription_confirmed', { channel: data.channel });
    }
  });

  socket.on('unsubscribe_channel', (data) => {
    if (data?.channel) {
      socket.leave(data.channel);
      socket.emit('unsubscription_confirmed', { channel: data.channel });
    }
  });

  socket.on('notificationViewed', (data) => {
    // Broadcast to other admins in same tenant
    if (tenantId) {
      socket.to(`tenant:${tenantId}`).emit('notificationViewed', { ...data, viewedBy: userId });
    }
  });

  socket.on('claimNotification', (data) => {
    if (tenantId) {
      socket.to(`tenant:${tenantId}`).emit('notificationClaimed', { ...data, claimedBy: userId });
    }
  });

  socket.on('user_status', (data) => {
    if (tenantId) {
      io.to(`tenant:${tenantId}`).emit('user_status_changed', { userId, ...data });
    }
  });

  socket.on('disconnect', (reason) => {
    console.log(`❌ Disconnected: ${userId} [${socket.id}] - ${reason}`);
    removeSocket(socket.id);
  });

  socket.on('error', (err) => {
    console.error(`Socket error for ${userId}:`, err.message);
  });
});

// ============================================
// Relay API Authentication Middleware
// ============================================
function authenticateRelay(req, res, next) {
  const apiKey = req.headers['x-relay-api-key'];
  if (!apiKey || apiKey !== RELAY_API_KEY) {
    return res.status(401).json({ error: 'Invalid relay API key' });
  }
  next();
}

// ============================================
// Relay REST API - Backend sends events here
// ============================================

/**
 * POST /relay/emit
 * Body: { target, event, data }
 *
 * target can be:
 *   { userId: "..." }                        → emit to specific user
 *   { tenantId: "..." }                      → emit to all users in tenant
 *   { tenantId: "...", role: "..." }          → emit to specific role in tenant
 *   { role: "..." }                           → emit to all users with role
 *   { room: "..." }                           → emit to specific room
 *   { broadcast: true }                       → emit to everyone
 */
app.post('/relay/emit', authenticateRelay, (req, res) => {
  try {
    const { target, event, data } = req.body;

    if (!target || !event) {
      return res.status(400).json({ error: 'Missing target or event' });
    }

    let recipientCount = 0;

    if (target.userId) {
      const room = `user:${target.userId}`;
      const sockets = io.sockets.adapter.rooms.get(room);
      recipientCount = sockets ? sockets.size : 0;
      io.to(room).emit(event, data);
    } else if (target.tenantId && target.role) {
      const room = `tenant:${target.tenantId}:role:${target.role}`;
      const sockets = io.sockets.adapter.rooms.get(room);
      recipientCount = sockets ? sockets.size : 0;
      io.to(room).emit(event, data);
    } else if (target.tenantId) {
      const room = `tenant:${target.tenantId}`;
      const sockets = io.sockets.adapter.rooms.get(room);
      recipientCount = sockets ? sockets.size : 0;
      io.to(room).emit(event, data);
    } else if (target.role) {
      const room = `role:${target.role}`;
      const sockets = io.sockets.adapter.rooms.get(room);
      recipientCount = sockets ? sockets.size : 0;
      io.to(room).emit(event, data);
    } else if (target.room) {
      const sockets = io.sockets.adapter.rooms.get(target.room);
      recipientCount = sockets ? sockets.size : 0;
      io.to(target.room).emit(event, data);
    } else if (target.broadcast) {
      recipientCount = io.sockets.sockets.size;
      io.emit(event, data);
    } else {
      return res.status(400).json({ error: 'Invalid target' });
    }

    res.json({ success: true, event, recipientCount });
  } catch (error) {
    console.error('Relay emit error:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /relay/emit-batch
 * Body: { events: [{ target, event, data }, ...] }
 * Send multiple events in one HTTP call (reduces latency)
 */
app.post('/relay/emit-batch', authenticateRelay, (req, res) => {
  try {
    const { events } = req.body;

    if (!Array.isArray(events)) {
      return res.status(400).json({ error: 'events must be an array' });
    }

    let totalRecipients = 0;

    for (const { target, event, data } of events) {
      if (!target || !event) continue;

      if (target.userId) {
        io.to(`user:${target.userId}`).emit(event, data);
      } else if (target.tenantId && target.role) {
        io.to(`tenant:${target.tenantId}:role:${target.role}`).emit(event, data);
      } else if (target.tenantId) {
        io.to(`tenant:${target.tenantId}`).emit(event, data);
      } else if (target.role) {
        io.to(`role:${target.role}`).emit(event, data);
      } else if (target.broadcast) {
        io.emit(event, data);
      }
      totalRecipients++;
    }

    res.json({ success: true, processed: totalRecipients });
  } catch (error) {
    console.error('Relay batch error:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================
// Health & Stats
// ============================================
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    uptime: process.uptime(),
    connections: io.sockets.sockets.size,
    trackedUsers: userSockets.size,
    timestamp: new Date().toISOString()
  });
});

app.get('/stats', authenticateRelay, (req, res) => {
  const rooms = {};
  for (const [roomName, sockets] of io.sockets.adapter.rooms) {
    // Skip individual socket rooms
    if (!socketMeta.has(roomName)) {
      rooms[roomName] = sockets.size;
    }
  }

  res.json({
    totalConnections: io.sockets.sockets.size,
    trackedUsers: userSockets.size,
    rooms,
    uptime: process.uptime()
  });
});

app.get('/', (req, res) => {
  res.json({
    service: 'LaundryLobby Socket Relay',
    version: '1.0.0',
    status: 'running',
    connections: io.sockets.sockets.size
  });
});

// ============================================
// Start Server
// ============================================
server.listen(PORT, () => {
  console.log('='.repeat(50));
  console.log(`🔌 Socket Relay Server running on port ${PORT}`);
  console.log(`📡 WebSocket: ws://localhost:${PORT}`);
  console.log(`🏥 Health: http://localhost:${PORT}/health`);
  console.log('='.repeat(50));
});
