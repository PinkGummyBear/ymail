import fs from 'fs';
import net from 'net';
import tls from 'tls';
import { EventEmitter } from 'events';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
const SALT_ROUNDS = 12;
import { promisify } from 'util';
import cors from 'cors';
import WebSocket from 'ws';
import sqlite3Pkg from 'sqlite3';
const sqlite3 = sqlite3Pkg.verbose();
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import express from 'express';
import path from 'path';


const app = express();

app.use(express.static("public"));


// Additional dependencies (ES Module syntax)
import nodemailer from 'nodemailer';
import Imap from 'imap';
import { simpleParser } from 'mailparser';
import validator from 'validator';
import winston from 'winston';
import rateLimit from 'express-rate-limit';


// ============================================================================
// LOGGING SETUP
// ============================================================================

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

// ============================================================================
// CONFIGURATION & CONSTANTS
// ============================================================================

const config = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'config.json'))
);

// FIX #5: Abszolút elérési út az adatbázishoz
config.storage.dbpath = path.resolve(__dirname, config.storage.dbpath);

// Email bridge configuration
config.emailBridge = {
  enabled: process.env.EMAIL_BRIDGE_ENABLED === 'true',
  smtp: {
    host: process.env.SMTP_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.SMTP_PORT) || 587,
    secure: false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  },
  imap: {
    user: process.env.IMAP_USER,
    password: process.env.IMAP_PASS,
    host: process.env.IMAP_HOST || 'imap.gmail.com',
    port: parseInt(process.env.IMAP_PORT) || 993,
    tls: true,
    tlsOptions: { rejectUnauthorized: false }
  },
  pollInterval: 60000
};

const MAX_BUFFER_SIZE = 10 * 1024 * 1024;
const MAX_EMAIL_LENGTH = 255;
const MAX_SUBJECT_LENGTH = 998;
const MAX_BODY_LENGTH = 1048576;
const MAX_RECIPIENTS = 100;
const HASHCASH_MAX_AGE_HOURS = 24;

const rateLimits = new Map();
const RATE_LIMIT_WINDOW = 60000;
const RATE_LIMIT_MAX_COMMANDS = 100;

// ============================================================================
// DATABASE SETUP
// ============================================================================

let db = null;
let dbReady = false;

// Promisify helpers
const runAsync = (db, sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err) {
      if (err) reject(err);
      else resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
};

const getAsync = (db, sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) reject(err);
      else resolve(row);
    });
  });
};

const allAsync = (db, sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) reject(err);
      else resolve(rows);
    });
  });
};

const execAsync = (db, sql) => {
  return new Promise((resolve, reject) => {
    db.exec(sql, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
};

// ============================================================================
// DATABASE INITIALIZATION - JAVÍTOTT VERZIÓ
// ============================================================================

async function setupDatabase() {
  logger.info('🔧 Starting database initialization...');
  logger.info('📁 Database path:', config.storage.dbpath);

  const dbExists = fs.existsSync(config.storage.dbpath);
  
  if (dbExists) {
    logger.info('📂 Existing database file found');
  } else {
    logger.info('🆕 Creating new database file');
  }

  return new Promise((resolve, reject) => {
    db = new sqlite3.Database(config.storage.dbpath, sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, async (err) => {
      if (err) {
        logger.error('❌ Failed to open database:', err);
        return reject(err);
      }

      logger.info('✅ Database file opened successfully');

      try {
        // Promisify methods
        db.runAsync = (sql, params) => runAsync(db, sql, params);
        db.getAsync = (sql, params) => getAsync(db, sql, params);
        db.allAsync = (sql, params) => allAsync(db, sql, params);
        db.execAsync = (sql) => execAsync(db, sql);

        // FIX #4: Integrity check
        if (dbExists) {
          logger.info('🔍 Running integrity check on existing database...');
          const integrityResult = await db.getAsync('PRAGMA integrity_check;');
          
          if (!integrityResult || integrityResult.integrity_check !== 'ok') {
            logger.error('❌ DATABASE CORRUPTION DETECTED!');
            logger.error('🔥 Please delete the following files and restart:');
            logger.error('   - ' + config.storage.dbpath);
            logger.error('   - ' + config.storage.dbpath + '-wal');
            logger.error('   - ' + config.storage.dbpath + '-shm');
            logger.error('   - ' + config.storage.dbpath + '-journal');
            throw new Error('Database integrity check failed');
          }
          
          logger.info('✅ Database integrity check passed');
        }

        // FIX #3: PRAGMA configuration (DELETE mode for Windows)
        logger.info('⚙️ Configuring database pragmas...');
        
        await db.runAsync('PRAGMA foreign_keys = ON;');
        logger.info('✓ Foreign keys enabled');
        
        await db.runAsync('PRAGMA journal_mode = DELETE;');
        logger.info('✓ Journal mode: DELETE (Windows-safe)');
        
        await db.runAsync('PRAGMA synchronous = NORMAL;');
        logger.info('✓ Synchronous mode: NORMAL');
        
        await db.runAsync('PRAGMA temp_store = MEMORY;');
        logger.info('✓ Temp store: MEMORY');

        // Create base tables
        logger.info('📊 Creating base tables...');
        
        await db.runAsync(`CREATE TABLE IF NOT EXISTS users (
          username TEXT PRIMARY KEY,
          email TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          email_verified INTEGER DEFAULT 0,
          verification_token TEXT,
          signature TEXT,
          preferences TEXT
        )`);
        logger.info('✓ users table ready');

        await db.runAsync(`CREATE TABLE IF NOT EXISTS tokens (
          jti TEXT PRIMARY KEY,
          sub TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
          issued_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL,
          revoked_at INTEGER
        )`);
        logger.info('✓ tokens table ready');

        await db.runAsync(`CREATE TABLE IF NOT EXISTS messages (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          sender TEXT NOT NULL,
          subject TEXT NOT NULL,
          body TEXT NOT NULL,
          ts INTEGER NOT NULL,
          in_reply_to INTEGER REFERENCES messages(id) ON DELETE SET NULL,
          thread_id INTEGER,
          is_deleted INTEGER DEFAULT 0,
          external_message_id TEXT,
          is_draft INTEGER DEFAULT 0
        )`);
        logger.info('✓ messages table ready');

        await db.runAsync(`CREATE TABLE IF NOT EXISTS message_recipients (
          message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
          recipient TEXT NOT NULL,
          type TEXT CHECK(type IN ('to','cc','bcc')),
          is_read INTEGER DEFAULT 0,
          is_deleted INTEGER DEFAULT 0,
          read_receipt_sent INTEGER DEFAULT 0,
          PRIMARY KEY(message_id, recipient, type)
        )`);
        logger.info('✓ message_recipients table ready');

        await db.runAsync(`CREATE TABLE IF NOT EXISTS parts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
          parent_part INTEGER,
          part_type TEXT NOT NULL,
          disposition TEXT,
          cid TEXT,
          filename TEXT,
          data BLOB NOT NULL
        )`);
        logger.info('✓ parts table ready');

        await db.runAsync(`CREATE TABLE IF NOT EXISTS labels (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
          name TEXT NOT NULL,
          color TEXT DEFAULT '#3b82f6',
          UNIQUE(user_email, name)
        )`);
        logger.info('✓ labels table ready');

        await db.runAsync(`CREATE TABLE IF NOT EXISTS message_labels (
          message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
          label_id INTEGER NOT NULL REFERENCES labels(id) ON DELETE CASCADE,
          PRIMARY KEY(message_id, label_id)
        )`);
        logger.info('✓ message_labels table ready');

        await db.runAsync(`CREATE TABLE IF NOT EXISTS filters (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
          name TEXT NOT NULL,
          condition_type TEXT NOT NULL,
          condition_value TEXT NOT NULL,
          action_type TEXT NOT NULL,
          action_value TEXT,
          priority INTEGER DEFAULT 0,
          enabled INTEGER DEFAULT 1
        )`);
        logger.info('✓ filters table ready');

        await db.runAsync(`CREATE TABLE IF NOT EXISTS templates (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
          name TEXT NOT NULL,
          subject TEXT,
          body TEXT NOT NULL,
          UNIQUE(user_email, name)
        )`);
        logger.info('✓ templates table ready');

        await db.runAsync(`CREATE TABLE IF NOT EXISTS contacts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
          contact_email TEXT NOT NULL,
          display_name TEXT,
          notes TEXT,
          added_at INTEGER NOT NULL,
          UNIQUE(user_email, contact_email)
        )`);
        logger.info('✓ contacts table ready');

        await db.runAsync(`CREATE TABLE IF NOT EXISTS blocked_senders (
          user_email TEXT NOT NULL REFERENCES users(email) ON DELETE CASCADE,
          blocked_email TEXT NOT NULL,
          blocked_at INTEGER NOT NULL,
          PRIMARY KEY(user_email, blocked_email)
        )`);
        logger.info('✓ blocked_senders table ready');

        await db.runAsync(`CREATE TABLE IF NOT EXISTS external_emails (
          internal_message_id INTEGER REFERENCES messages(id) ON DELETE CASCADE,
          external_message_id TEXT NOT NULL,
          direction TEXT CHECK(direction IN ('incoming', 'outgoing')),
          synced_at INTEGER NOT NULL,
          PRIMARY KEY(internal_message_id, external_message_id)
        )`);
        logger.info('✓ external_emails table ready');

        // FIX #2: FTS5 virtual table AFTER base tables
        logger.info('🔍 Creating FTS5 virtual table...');
        
        // Töröltük a content_rowid='id' részt!
await db.runAsync(`CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts 
                   USING fts5(subject, body, content='messages')`);
        logger.info('✓ messages_fts virtual table ready');

       

        // Create indexes
        logger.info('📇 Creating indexes...');
        
        await db.runAsync(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`);
        await db.runAsync(`CREATE INDEX IF NOT EXISTS idx_tokens_sub ON tokens(sub)`);
        await db.runAsync(`CREATE INDEX IF NOT EXISTS idx_tokens_jti ON tokens(jti)`);
        await db.runAsync(`CREATE INDEX IF NOT EXISTS idx_msg_thread ON messages(thread_id)`);
        await db.runAsync(`CREATE INDEX IF NOT EXISTS idx_msg_sender ON messages(sender)`);
        await db.runAsync(`CREATE INDEX IF NOT EXISTS idx_msg_ts ON messages(ts)`);
        await db.runAsync(`CREATE INDEX IF NOT EXISTS idx_msg_draft ON messages(is_draft)`);
        await db.runAsync(`CREATE INDEX IF NOT EXISTS idx_recipient ON message_recipients(recipient)`);
        await db.runAsync(`CREATE INDEX IF NOT EXISTS idx_parts_msg ON parts(message_id)`);
        await db.runAsync(`CREATE INDEX IF NOT EXISTS idx_labels_user ON labels(user_email)`);
        await db.runAsync(`CREATE INDEX IF NOT EXISTS idx_filters_user ON filters(user_email)`);
        await db.runAsync(`CREATE INDEX IF NOT EXISTS idx_contacts_user ON contacts(user_email)`);
        await db.runAsync(`CREATE INDEX IF NOT EXISTS idx_external_internal ON external_emails(internal_message_id)`);
        await db.runAsync(`CREATE INDEX IF NOT EXISTS idx_external_external ON external_emails(external_message_id)`);
        
        logger.info('✓ All indexes created');

        // Final integrity check
        logger.info('🔍 Final integrity check...');
        const finalCheck = await db.getAsync('PRAGMA integrity_check;');
        
        if (!finalCheck || finalCheck.integrity_check !== 'ok') {
          throw new Error('Final integrity check failed');
        }
        
        logger.info('✅ Final integrity check passed');

        dbReady = true;
        logger.info('🟢 DATABASE READY - Server can now accept requests');
        
        resolve(db);

      } catch (error) {
        logger.error('❌ Database initialization failed:', error);
        
        if (db) {
          db.close((closeErr) => {
            if (closeErr) logger.error('Failed to close database:', closeErr);
          });
        }
        
        reject(error);
      }
    });
  });
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function validateEmail(email) {
  if (!email || typeof email !== 'string') return false;
  if (email.length > MAX_EMAIL_LENGTH) return false;
  
  const internalRegex = /^[^\s$]+\$[^\s$]+\.[^\s$]+$/;
  const externalRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  
  return internalRegex.test(email) || externalRegex.test(email);
}

function isExternalEmail(email) {
  return email.includes('@') && !email.includes('$');
}

function convertToInternalFormat(email) {
  return email.replace('@', '$');
}

function convertToExternalFormat(email) {
  return email.replace('$', '@');
}

function sanitizeInput(text, maxLength = 10000) {
  if (typeof text !== 'string') return '';
  return validator.escape(text).substring(0, maxLength);
}

function validateSubject(subject) {
  if (typeof subject !== 'string') return false;
  return subject.length <= MAX_SUBJECT_LENGTH;
}

function validateBody(body) {
  if (typeof body !== 'string') return false;
  return body.length <= MAX_BODY_LENGTH;
}

function checkRateLimit(email) {
  const now = Date.now();
  const limit = rateLimits.get(email);
  if (!limit || now > limit.resetTime) {
    rateLimits.set(email, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return true;
  }
  if (limit.count >= RATE_LIMIT_MAX_COMMANDS) return false;
  limit.count++;
  return true;
}

function verifyHashcash(token, resource) {
  if (!token || typeof token !== 'string') return false;
  const parts = token.split(':');
  if (parts.length !== 7) return false;
  const [ver, bits, date, res] = parts;
  if (parseInt(ver, 10) !== config.hashcash.version) return false;
  if (parseInt(bits, 10) < config.hashcash.difficultyBits) return false;
  if (res !== resource) return false;
  try {
    const year = parseInt(date.slice(0, 2), 10) + 2000;
    const month = parseInt(date.slice(2, 4), 10) - 1;
    const day = parseInt(date.slice(4, 6), 10);
    const stampDate = new Date(year, month, day);
    if (isNaN(stampDate.getTime())) return false;
    const now = new Date();
    const ageHours = (now - stampDate) / (1000 * 60 * 60);
    if (ageHours > HASHCASH_MAX_AGE_HOURS || ageHours < -1) return false;
  } catch (e) {
    return false;
  }
  const hash = crypto.createHash('sha1').update(token).digest();
  let zeroBits = 0;
  for (const byte of hash) {
    if (byte === 0) {
      zeroBits += 8;
      continue;
    }
    for (let mask = 0x80; mask > 0; mask >>= 1) {
      if ((byte & mask) === 0) zeroBits++;
      else return zeroBits >= config.hashcash.difficultyBits;
    }
    break;
  }
  return zeroBits >= config.hashcash.difficultyBits;
}

function makeFrame(obj) {
  const buf = Buffer.from(JSON.stringify(obj));
  const frame = Buffer.alloc(4 + buf.length);
  frame.writeUInt32BE(buf.length, 0);
  buf.copy(frame, 4);
  return frame;
}

async function verifyMessageAccess(messageId, userEmail, type = 'any') {
  if (type === 'sender') {
    const row = await db.getAsync(`SELECT 1 FROM messages WHERE id = ? AND sender = ?`, [messageId, userEmail]);
    return !!row;
  }
  if (type === 'recipient') {
    const row = await db.getAsync(`SELECT 1 FROM message_recipients WHERE message_id = ? AND recipient = ?`, [messageId, userEmail]);
    return !!row;
  }
  const row = await db.getAsync(
    `SELECT 1 FROM messages m LEFT JOIN message_recipients r ON r.message_id = m.id
     WHERE m.id = ? AND (m.sender = ? OR r.recipient = ?)`,
    [messageId, userEmail, userEmail]
  );
  return !!row;
}

// ============================================================================
// EMAIL BRIDGE - SMTP/IMAP INTEGRATION
// ============================================================================

let smtpTransport = null;
let imapClient = null;

if (config.emailBridge.enabled) {
  smtpTransport = nodemailer.createTransport(config.emailBridge.smtp);
  
  smtpTransport.verify((error, success) => {
    if (error) {
      logger.error('SMTP connection failed:', error);
    } else {
      logger.info('✅ SMTP bridge ready');
    }
  });

  async function sendToExternalEmail(internalSender, externalRecipient, subject, body, messageId) {
    try {
      const mailOptions = {
        from: `"${internalSender}" <${config.emailBridge.smtp.auth.user}>`,
        to: externalRecipient,
        subject: subject,
        text: body,
        html: body.replace(/\n/g, '<br>'),
        headers: {
          'X-Internal-Sender': internalSender,
          'X-Internal-Message-ID': messageId
        }
      };

      const info = await smtpTransport.sendMail(mailOptions);
      logger.info(`📧 Sent external email: ${info.messageId}`);
      
      await db.runAsync(
        `INSERT INTO external_emails (internal_message_id, external_message_id, direction, synced_at)
         VALUES (?, ?, 'outgoing', ?)`,
        [messageId, info.messageId, Math.floor(Date.now() / 1000)]
      );
      
      return info;
    } catch (error) {
      logger.error('Failed to send external email:', error);
      throw error;
    }
  }

  function startImapPolling() {
    let processingEmails = false;

    async function pollEmails() {
      if (processingEmails) return;
      processingEmails = true;

      try {
        const imap = new Imap(config.emailBridge.imap);

        imap.once('ready', () => {
          imap.openBox('INBOX', false, async (err, box) => {
            if (err) {
              logger.error('IMAP openBox error:', err);
              imap.end();
              return;
            }

            imap.search(['UNSEEN'], async (err, results) => {
              if (err) {
                logger.error('IMAP search error:', err);
                imap.end();
                return;
              }

              if (!results || results.length === 0) {
                logger.debug('No new emails');
                imap.end();
                return;
              }

              const fetch = imap.fetch(results, { bodies: '', markSeen: true });

              fetch.on('message', (msg) => {
                msg.on('body', (stream) => {
                  simpleParser(stream, async (err, parsed) => {
                    if (err) {
                      logger.error('Email parse error:', err);
                      return;
                    }

                    try {
                      const fromExternal = parsed.from.value[0].address;
                      const toExternal = parsed.to.value[0].address;
                      
                      const fromInternal = convertToInternalFormat(fromExternal);
                      const toInternal = convertToInternalFormat(toExternal);
                      
                      const user = await db.getAsync(
                        `SELECT email FROM users WHERE email = ?`,
                        [toInternal]
                      );

                      if (!user) {
                        logger.warn(`Received email for non-existent user: ${toInternal}`);
                        return;
                      }

                      const blocked = await db.getAsync(
                        `SELECT 1 FROM blocked_senders WHERE user_email = ? AND blocked_email = ?`,
                        [toInternal, fromInternal]
                      );

                      if (blocked) {
                        logger.info(`Blocked email from: ${fromInternal}`);
                        return;
                      }

                      const now = Math.floor(Date.now() / 1000);

const result = await db.runAsync(
  `INSERT INTO messages (sender, subject, body, ts, external_message_id)
   VALUES (?, ?, ?, ?, ?)`,
  [
    fromInternal,
    parsed.subject || '(No subject)',
    parsed.text || '',
    now,
    parsed.messageId
  ]
);

const messageId = result.lastID;

// recipients
await db.runAsync(
  `INSERT INTO message_recipients (message_id, recipient, type)
   VALUES (?, ?, 'to')`,
  [messageId, toInternal]
);

// external mapping
await db.runAsync(
  `INSERT INTO external_emails (internal_message_id, external_message_id, direction, synced_at)
   VALUES (?, ?, 'incoming', ?)`,
  [messageId, parsed.messageId, now]
);

// 🔥 FTS KÜLÖN – TRIGGER HELYETT
try {
  await db.runAsync(
    `INSERT INTO messages_fts(rowid, subject, body)
     VALUES (?, ?, ?)`,
    [
      messageId,
      parsed.subject || '(No subject)',
      parsed.text || ''
    ]
  );
} catch (ftsErr) {
  logger.warn('FTS insert failed for incoming email', ftsErr.message);
}

logger.info(`📬 Received external email from ${fromExternal}`);

                    } catch (error) {
                      logger.error('Failed to process email:', error);
                    }
                  });
                });
              });

              fetch.once('error', (err) => {
                logger.error('IMAP fetch error:', err);
              });

              fetch.once('end', () => {
                imap.end();
              });
            });
          });
        });

        imap.once('error', (err) => {
          logger.error('IMAP connection error:', err);
        });

        imap.once('end', () => {
          logger.debug('IMAP connection ended');
          processingEmails = false;
        });

        imap.connect();

      } catch (error) {
        logger.error('IMAP polling error:', error);
        processingEmails = false;
      }
    }

    setInterval(pollEmails, config.emailBridge.pollInterval);
    pollEmails();

    logger.info('✅ IMAP polling started');
  }

  startImapPolling();
}

// ============================================================================
// FILTERS & AUTO-PROCESSING
// ============================================================================

async function applyFilters(messageId, userEmail) {
  try {
    const filters = await db.allAsync(
      `SELECT * FROM filters WHERE user_email = ? AND enabled = 1 ORDER BY priority ASC`,
      [userEmail]
    );

    const message = await db.getAsync(
      `SELECT * FROM messages WHERE id = ?`,
      [messageId]
    );

    if (!message) return;

    for (const filter of filters) {
      try {
        let matches = false;

        switch (filter.condition_type) {
          case 'from':
            matches = message.sender.toLowerCase().includes(filter.condition_value.toLowerCase());
            break;
          case 'subject':
            matches = message.subject.toLowerCase().includes(filter.condition_value.toLowerCase());
            break;
          case 'body':
            matches = message.body.toLowerCase().includes(filter.condition_value.toLowerCase());
            break;
        }

        if (matches) {
          switch (filter.action_type) {
            case 'label':
              const label = await db.getAsync(
                `SELECT id FROM labels WHERE user_email = ? AND name = ?`,
                [userEmail, filter.action_value]
              );
              if (label) {
                await db.runAsync(
                  `INSERT OR IGNORE INTO message_labels (message_id, label_id) VALUES (?, ?)`,
                  [messageId, label.id]
                );
              }
              break;
            case 'delete':
              await db.runAsync(
                `UPDATE message_recipients SET is_deleted = 1 WHERE message_id = ? AND recipient = ?`,
                [messageId, userEmail]
              );
              break;
            case 'mark_read':
              await db.runAsync(
                `UPDATE message_recipients SET is_read = 1 WHERE message_id = ? AND recipient = ?`,
                [messageId, userEmail]
              );
              break;
          }

          logger.info(`Applied filter "${filter.name}" to message ${messageId}`);
        }
      } catch (filterActionErr) {
        logger.warn(`Failed to apply filter action for filter ${filter.id}:`, filterActionErr.message);
      }
    }
  } catch (error) {
    logger.error('Error in applyFilters:', error);
    throw error;
  }
}

// ============================================================================
// FRAMER CLASS
// ============================================================================

class Framer extends EventEmitter {
  constructor() {
    super();
    this.buf = Buffer.alloc(0);
  }
  push(chunk) {
    this.buf = Buffer.concat([this.buf, chunk]);
    if (this.buf.length > MAX_BUFFER_SIZE) {
      this.emit('error', new Error('Buffer size exceeded'));
      this.buf = Buffer.alloc(0);
      return;
    }
    while (this.buf.length >= 4) {
      const len = this.buf.readUInt32BE(0);
      if (len > MAX_BUFFER_SIZE) {
        this.emit('error', new Error('Message too large'));
        this.buf = Buffer.alloc(0);
        return;
      }
      if (this.buf.length >= 4 + len) {
        const msgBuf = this.buf.slice(4, 4 + len);
        this.buf = this.buf.slice(4 + len);
        try {
          const obj = JSON.parse(msgBuf.toString());
          this.emit('message', obj);
        } catch (e) {
          this.emit('error', new Error('Invalid JSON'));
        }
      } else break;
    }
  }
}

// ============================================================================
// CONNECTION HANDLER
// ============================================================================

function initSecureConnection(socket) {
  logger.info('🔒 Secure client connected:', socket.remoteAddress);
  let authenticated = false;
  let sender = null;
  let currentJti = null;
  const framer = new Framer();

  function sendResponse(obj, reqId) {
    if (typeof reqId === 'number') obj.requestId = reqId;
    try {
      socket.write(makeFrame(obj));
    } catch (err) {
      logger.error('sendResponse error:', err);
    }
  }

  socket.on('data', chunk => framer.push(chunk));

  framer.on('message', async msg => {
    try {
      const reqId = msg.requestId;
      
      if (!msg || typeof msg.command !== 'string') {
        sendResponse({ code: 400, error: 'Invalid message' }, reqId);
        return;
      }

      logger.debug('📬 Command:', msg.command, 'from:', sender || 'unauthenticated');

      // ===== PING =====
      if (msg.command === 'PING') {
        sendResponse({ code: 200, result: 'OK' }, reqId);
        return;
      }

      // ===== REGISTER =====
      if (msg.command === 'REGISTER') {
        const { email, password } = msg;
        
        if (!validateEmail(email)) {
          sendResponse({ code: 400, error: 'Invalid email' }, reqId);
          return;
        }
        
        if (!password || typeof password !== 'string' || password.length < 8) {
          sendResponse({ code: 400, error: 'Password must be at least 8 characters' }, reqId);
          return;
        }
        
        try {
          const hash = await bcrypt.hash(password, SALT_ROUNDS);
          const now = Math.floor(Date.now() / 1000);
          const [localPart] = email.split(/[$@]/);
          const verificationToken = crypto.randomBytes(32).toString('hex');
          
          await db.runAsync(
            `INSERT INTO users(username, email, password_hash, created_at, verification_token)
             VALUES(?, ?, ?, ?, ?)`,
            [localPart, email, hash, now, verificationToken]
          );
          
          sendResponse({ code: 200, result: 'Registered', verificationRequired: true }, reqId);
          logger.info(`New user registered: ${email}`);
          return;
        } catch (e) {
          if (/UNIQUE constraint/.test(e.message)) {
            sendResponse({ code: 409, error: 'Email already in use' }, reqId);
            return;
          }
          logger.error('REGISTER error:', e);
          sendResponse({ code: 500, error: 'Database error' }, reqId);
          return;
        }
      }

      // ===== LOGIN =====
      if (msg.command === 'LOGIN') {
        const { email, password } = msg;
        
        if (!validateEmail(email)) {
          sendResponse({ code: 400, error: 'Invalid email' }, reqId);
          return;
        }
        
        if (!password || typeof password !== 'string') {
          sendResponse({ code: 400, error: 'Missing password' }, reqId);
          return;
        }
        
        try {
          const row = await db.getAsync(
            `SELECT password_hash, email, email_verified FROM users WHERE email = ?`,
            [email]
          );
          
          if (!row) {
            sendResponse({ code: 404, error: 'No such user' }, reqId);
            return;
          }
          
          const match = await bcrypt.compare(password, row.password_hash);
          if (!match) {
            sendResponse({ code: 401, error: 'Bad credentials' }, reqId);
            return;
          }
          
          const jti = uuidv4();
          const now = Math.floor(Date.now() / 1000);
          const expiry = now + config.jwt.tokenExpirySeconds;
          const token = jwt.sign(
            { iss: config.jwt.issuer, sub: row.email, jti },
            privateKey,
            { algorithm: 'RS256', expiresIn: config.jwt.tokenExpirySeconds }
          );
          
          await db.runAsync(
            `INSERT INTO tokens(jti, sub, issued_at, expires_at) VALUES(?, ?, ?, ?)`,
            [jti, row.email, now, expiry]
          );
          
          sendResponse({ 
            code: 200, 
            token,
            emailVerified: !!row.email_verified
          }, reqId);
          
          logger.info(`User logged in: ${email}`);
          return;
        } catch (e) {
          logger.error('LOGIN error:', e);
          sendResponse({ code: 500, error: 'Server error' }, reqId);
          return;
        }
      }

      // ===== AUTH =====
      if (!authenticated) {
        if (msg.command === 'AUTH' && typeof msg.token === 'string') {
          try {
            const payload = jwt.verify(msg.token, publicKey, { issuer: config.jwt.issuer });
            const row = await db.getAsync(`SELECT revoked_at FROM tokens WHERE jti = ?`, [payload.jti]);
            
            if (!row) {
              sendResponse({ code: 401, error: 'Invalid token' }, reqId);
              socket.end();
              return;
            }
            
            if (row.revoked_at) {
              sendResponse({ code: 401, error: 'Token revoked' }, reqId);
              socket.end();
              return;
            }
            
            authenticated = true;
            sender = payload.sub;
            currentJti = payload.jti;
            sendResponse({ code: 200, result: 'OK' }, reqId);
            logger.info(`User authenticated: ${sender}`);
            return;
          } catch (err) {
            logger.error('AUTH error:', err.message);
            sendResponse({ code: 401, error: 'Unauthorized' }, reqId);
            socket.end();
            return;
          }
        } else {
          sendResponse({ code: 530, error: 'Authenticate first' }, reqId);
          return;
        }
      }

      // Rate limiting
      if (!checkRateLimit(sender)) {
        sendResponse({ code: 429, error: 'Rate limit exceeded' }, reqId);
        return;
      }

      // ===== LOGOUT =====
      if (msg.command === 'LOGOUT') {
        await db.runAsync(
          `UPDATE tokens SET revoked_at = ? WHERE jti = ?`,
          [Math.floor(Date.now() / 1000), currentJti]
        );
        sendResponse({ code: 200, result: 'Logged out' }, reqId);
        socket.end();
        logger.info(`User logged out: ${sender}`);
        return;
      }

    // ===== REPLY (Javított, Thread-biztos verzió) =====
// ===== REPLY =====
if (msg.command === 'REPLY') {
  const parent_id = parseInt(msg.parent_id || msg.id);
  let { subject, body } = msg;
  
  if (!subject || (typeof subject === 'string' && subject.trim() === "")) {
    subject = "Re: (no subject)";
  }

  if (!parent_id || !body) {
    logger.warn('REPLY parameter error:', { parent_id, subject: !!subject, body: !!body });
    sendResponse({ code: 400, error: 'Invalid parameters', requestId: reqId }, reqId);
    return; // ✅ Already has return
  }

  try {
    const parent = await db.getAsync(
      'SELECT id, thread_id, sender, subject FROM messages WHERE id = ?',
      [parent_id]
    );

    if (!parent) {
      sendResponse({ code: 404, error: 'Parent message not found' }, reqId);
      return; // ✅ Already has return
    }

    const threadId = parent.thread_id || parent.id;
    const now = Math.floor(Date.now() / 1000);
    
    // Ensure subject has "Re:" prefix
    if (!subject.startsWith('Re:')) {
      subject = 'Re: ' + (parent.subject || '(no subject)');
    }

    await db.runAsync('BEGIN IMMEDIATE');

    try {
      const result = await db.runAsync(
        `INSERT INTO messages (sender, subject, body, ts, in_reply_to, thread_id) 
         VALUES (?, ?, ?, ?, ?, ?)`,
        [sender, subject, body, now, parent_id, threadId]
      );
      
      const newMessageId = result.lastID;

      // Add recipient (reply to the original sender)
      await db.runAsync(
        `INSERT INTO message_recipients (message_id, recipient, type) VALUES (?, ?, 'to')`,
        [newMessageId, parent.sender]
      );

      await db.runAsync('COMMIT');

      // Update FTS
      await db.runAsync(
        `INSERT INTO messages_fts(rowid, subject, body) VALUES (?, ?, ?)`,
        [newMessageId, subject, body]
      ).catch(e => logger.warn('FTS reply error:', e.message));

      sendResponse({ 
        code: 200, 
        command: 'REPLY', 
        result: 'Sent', 
        messageId: newMessageId 
      }, reqId);
      
      return; // ✅ ADD THIS RETURN!

    } catch (innerErr) {
      await db.runAsync('ROLLBACK');
      throw innerErr;
    }

  } catch (err) {
    logger.error('REPLY error:', err);
    sendResponse({ code: 500, error: 'Server error' }, reqId);
    return; // ✅ ADD THIS RETURN!
  }
}


      // ===== SAVE_DRAFT =====
      if (msg.command === 'SAVE_DRAFT') {
        const { to = '', cc = '', subject = '', body = '', draft_id } = msg;
        
        try {
          const now = Math.floor(Date.now() / 1000);
          
          if (draft_id) {
            await db.runAsync(
              `UPDATE messages SET subject = ?, body = ?, ts = ? WHERE id = ? AND sender = ? AND is_draft = 1`,
              [sanitizeInput(subject), sanitizeInput(body, MAX_BODY_LENGTH), now, draft_id, sender]
            );
            sendResponse({ code: 200, result: 'Draft updated', draftId: draft_id }, reqId);
          } else {
            const result = await db.runAsync(
              `INSERT INTO messages (sender, subject, body, ts, is_draft) VALUES (?, ?, ?, ?, 1)`,
              [sender, sanitizeInput(subject), sanitizeInput(body, MAX_BODY_LENGTH), now]
            );
            sendResponse({ code: 200, result: 'Draft saved', draftId: result.lastID }, reqId);
          }
          
          return;
        } catch (err) {
          logger.error('SAVE_DRAFT error:', err);
          sendResponse({ code: 500, error: 'Server error' }, reqId);
          return;
        }
      }

      // ===== LIST_DRAFTS =====
      if (msg.command === 'LIST_DRAFTS') {
        try {
          const drafts = await db.allAsync(
            `SELECT id, subject, body, ts FROM messages WHERE sender = ? AND is_draft = 1 ORDER BY ts DESC`,
            [sender]
          );
          sendResponse({ code: 200, drafts }, reqId);
          return;
        } catch (err) {
          logger.error('LIST_DRAFTS error:', err);
          sendResponse({ code: 500, error: 'Server error' }, reqId);
          return;
        }
      }

      // ===== DELETE_DRAFT =====
      // ===== DELETE_DRAFT (Javított, FTS-biztos verzió) =====
if (msg.command === 'DELETE_DRAFT') {
  const { draft_id } = msg;
  
  try {
    // 1. Megszerezzük a rowid-t a törlés előtt
    const row = await db.getAsync(
      "SELECT rowid FROM messages WHERE id = ? AND sender = ? AND is_draft = 1", 
      [draft_id, sender]
    );
    
    if (!row) {
      sendResponse({ code: 404, error: 'Draft not found' }, reqId);
      return;
    }

    await db.runAsync('BEGIN IMMEDIATE');
    try {
      // 2. Törlés a fő táblából
      await db.runAsync(
        `DELETE FROM messages WHERE id = ? AND sender = ? AND is_draft = 1`,
        [draft_id, sender]
      );
      await db.runAsync('COMMIT');
    } catch (err) {
      await db.runAsync('ROLLBACK');
      throw err;
    }

    // 3. 🔥 Manuális FTS törlés a rowid alapján
    try {
      await db.runAsync("DELETE FROM messages_fts WHERE rowid = ?", [row.rowid]);
    } catch (ftsErr) {
      logger.warn('FTS draft delete failed:', ftsErr.message);
    }

    sendResponse({ code: 200, result: 'Draft deleted' }, reqId);
  } catch (err) {
    logger.error('DELETE_DRAFT error:', err);
    sendResponse({ code: 500, error: 'Server error' }, reqId);
  }
}



      // ===== LIST =====
if (msg.command === 'LIST') {
  const { folder = 'inbox' } = msg;
  const offset = Math.max(0, parseInt(msg.offset) || 0);
  const limit = Math.min(Math.max(1, parseInt(msg.limit) || 20), 100);
  const sortBy = msg.sort_by === 'subject' ? 'subject' : 'ts';
  const sortOrder = msg.sort_desc === false ? 'ASC' : 'DESC';
  
  try {
    let rows;
    
    if (folder === 'inbox') {
      rows = await db.allAsync(
        `SELECT m.id, m.sender AS sender_name, m.subject, m.ts, r.is_read
         FROM messages m JOIN message_recipients r ON r.message_id = m.id
         WHERE r.recipient = ? AND r.is_deleted = 0 AND m.is_draft = 0
         ORDER BY m.${sortBy} ${sortOrder} LIMIT ? OFFSET ?`,
        [sender, limit, offset]
      );
    } else if (folder === 'sent') {
  rows = await db.allAsync(
    `SELECT m.id, 
     (SELECT group_concat(recipient, ', ') FROM message_recipients WHERE message_id = m.id AND type = 'to') AS sender_name,
     m.subject, m.ts, 0 AS is_read
     FROM messages m WHERE m.sender = ? AND m.is_deleted = 0 AND m.is_draft = 0
     ORDER BY m.${sortBy} ${sortOrder} LIMIT ? OFFSET ?`,
    [sender, limit, offset]
  );
    } else {
      sendResponse({ code: 400, error: 'Invalid folder' }, reqId);
      return;
    }

    // 🔥 JAVÍTÁS: Dátum korrigálása a kliens számára (másodperc -> ezredmásodperc)
    const formattedMessages = rows.map(row => ({
      ...row,
      ts: row.ts ? Number(row.ts) * 1000 : Date.now()
    }));
    
    sendResponse({ code: 200, messages: formattedMessages }, reqId);
    return;

  } catch (err) {
    logger.error('LIST error:', err);
    sendResponse({ code: 500, error: 'Server error' }, reqId);
    return;
  }
}
// ===== READ =====
if (msg.command === 'READ') {
  const { id } = msg;
  if (typeof id !== 'number') {
    sendResponse({ code: 400, error: 'Invalid id' }, reqId);
    return;
  }

  try {
    const message = await db.getAsync(
      `SELECT 
        m.id, 
        m.sender, 
        m.sender AS sender_name, 
        m.subject, 
        m.body, 
        m.ts, 
        m.thread_id,
        r.is_read, 
        (SELECT group_concat(recipient, ',') FROM message_recipients WHERE message_id = m.id AND type = 'to') AS to_addrs
      FROM messages m 
      LEFT JOIN message_recipients r ON r.message_id = m.id AND r.recipient = ?
      WHERE m.id = ? AND (m.sender = ? OR r.recipient = ?) AND m.is_draft = 0`,
      [sender, id, sender, sender]
    );

    if (!message) {
      sendResponse({ code: 404, error: 'Not found' }, reqId);
      return;
    }

    if (message.is_read === 0) {
      await db.runAsync(
        `UPDATE message_recipients SET is_read = 1 WHERE message_id = ? AND recipient = ?`,
        [id, sender]
      );
    }

    const parts = await db.allAsync(
      `SELECT id, part_type, filename, LENGTH(data) as size FROM parts WHERE message_id = ?`,
      [id]
    );
    message.parts = parts;

    // 🔥 DÁTUM JAVÍTÁS: szorzás 1000-rel a kliensnek
    if (message.ts) {
      message.ts = Number(message.ts) * 1000;
    }

    sendResponse({ code: 200, command: 'READ', message }, reqId);
    return;
  } catch (err) {
    logger.error('READ error:', err);
    sendResponse({ code: 500, error: 'Server error' }, reqId);
    return;
  }
}
    // ===== READ_SENT =====
if (msg.command === 'READ_SENT') {
  const { id } = msg;
  if (typeof id !== 'number') {
    sendResponse({ code: 400, error: 'Invalid id' }, reqId);
    return;
  }

  try {
    const message = await db.getAsync(
      `SELECT 
        id, 
        sender, 
        sender AS sender_name, 
        subject, 
        body, 
        ts, 
        thread_id 
      FROM messages 
      WHERE id = ? AND sender = ?`,
      [id, sender]
    );

    if (!message) {
      sendResponse({ code: 404, error: 'Sent message not found' }, reqId);
      return;
    }

    const recipients = await db.allAsync(
      `SELECT recipient, type, is_read FROM message_recipients WHERE message_id = ?`,
      [id]
    );
    message.recipients = recipients;
    
    // 🔥 DÁTUM JAVÍTÁS: szorzás 1000-rel a kliensnek
    if (message.ts) {
      message.ts = Number(message.ts) * 1000;
    }

    sendResponse({ code: 200, command: 'READ_SENT', message }, reqId);
  } catch (err) {
    logger.error('READ_SENT error:', err);
    sendResponse({ code: 500, error: 'Server error' }, reqId);
  }
}
      // ===== MARK =====
      if (msg.command === 'MARK') {
        const { id, read } = msg;
        
        if (typeof id !== 'number' || typeof read !== 'boolean') {
          sendResponse({ code: 400, error: 'Invalid parameters' }, reqId);
          return;
        }
        
        try {
          const result = await db.runAsync(
            `UPDATE message_recipients SET is_read = ? WHERE message_id = ? AND recipient = ?`,
            [read ? 1 : 0, id, sender]
          );
          
          if (result.changes === 0) {
            sendResponse({ code: 404, error: 'Not found' }, reqId);
            return;
          }
          
          sendResponse({ code: 200, result: 'OK' }, reqId);
          return;
        } catch (err) {
          logger.error('MARK error:', err);
          sendResponse({ code: 500, error: 'Server error' }, reqId);
          return;
        }
      }

      // ===== MARK_BATCH =====
      if (msg.command === 'MARK_BATCH') {
        const { ids, read } = msg;
        
        if (!Array.isArray(ids) || typeof read !== 'boolean') {
          sendResponse({ code: 400, error: 'Invalid parameters' }, reqId);
          return;
        }
        
        if (ids.length === 0) {
          sendResponse({ code: 200, result: 'OK', updated: 0 }, reqId);
          return;
        }
        
        try {
          const placeholders = ids.map(() => '?').join(',');
          const result = await db.runAsync(
            `UPDATE message_recipients SET is_read = ? WHERE message_id IN (${placeholders}) AND recipient = ?`,
            [read ? 1 : 0, ...ids, sender]
          );
          
          sendResponse({ code: 200, result: 'OK', updated: result.changes }, reqId);
          return;
        } catch (err) {
          logger.error('MARK_BATCH error:', err);
          sendResponse({ code: 500, error: 'Server error' }, reqId);
          return;
        }
      }

     // ===== DELETE (Logikai törlés - Soft Delete) =====
if (msg.command === 'DELETE') {
  const { id, folder } = msg;
  
  // JAVÍTÁS: id nem biztos, hogy number! Ha UUID-t használsz, vedd ki a typeof ellenőrzést.
  if (!id || !['inbox', 'sent'].includes(folder)) {
    sendResponse({ code: 400, error: 'Invalid parameters' }, reqId);
    return;
  }
  
  try {
    let result;
    
    // Itt csak egy jelzőt állítunk át, az FTS-hez NEM kell nyúlni!
    if (folder === 'inbox') {
      result = await db.runAsync(
        `UPDATE message_recipients SET is_deleted = 1 WHERE message_id = ? AND recipient = ?`,
        [id, sender]
      );
    } else {
      result = await db.runAsync(
        `UPDATE messages SET is_deleted = 1 WHERE id = ? AND sender = ?`,
        [id, sender]
      );
    }
    
    if (result.changes === 0) {
      sendResponse({ code: 404, error: 'Message not found or unauthorized' }, reqId);
      return;
    }
    
    sendResponse({ code: 200, result: 'Deleted' }, reqId);
  } catch (err) {
    logger.error('DELETE error:', err);
    sendResponse({ code: 500, error: 'Server error' }, reqId);
  }
}

      // ===== DELETE_BATCH =====
      if (msg.command === 'DELETE_BATCH') {
        const { ids, folder } = msg;
        
        if (!Array.isArray(ids) || !['inbox', 'sent'].includes(folder)) {
          sendResponse({ code: 400, error: 'Invalid parameters' }, reqId);
          return;
        }
        
        if (ids.length === 0) {
          sendResponse({ code: 200, result: 'Deleted', deleted: 0 }, reqId);
          return;
        }
        
        try {
          const placeholders = ids.map(() => '?').join(',');
          let result;
          
          if (folder === 'inbox') {
            result = await db.runAsync(
              `UPDATE message_recipients SET is_deleted = 1 WHERE message_id IN (${placeholders}) AND recipient = ?`,
              [...ids, sender]
            );
          } else {
            result = await db.runAsync(
              `UPDATE messages SET is_deleted = 1 WHERE id IN (${placeholders}) AND sender = ?`,
              [...ids, sender]
            );
          }
          
          sendResponse({ code: 200, result: 'Deleted', deleted: result.changes }, reqId);
          return;
        } catch (err) {
          logger.error('DELETE_BATCH error:', err);
          sendResponse({ code: 500, error: 'Server error' }, reqId);
          return;
        }
      }

      // ===== SEARCH =====
      if (msg.command === 'SEARCH') {
        const { query, folder = 'inbox' } = msg;
        
        if (!query || typeof query !== 'string') {
          sendResponse({ code: 400, error: 'Invalid query' }, reqId);
          return;
        }
        
        if (!['inbox', 'sent', 'all'].includes(folder)) {
          sendResponse({ code: 400, error: 'Invalid folder' }, reqId);
          return;
        }
        
        const offset = Math.max(0, parseInt(msg.offset) || 0);
        const limit = Math.min(Math.max(1, parseInt(msg.limit) || 20), 100);
        const sortBy = msg.sort_by === 'subject' ? 'subject' : 'ts';
        const sortOrder = msg.sort_desc === false ? 'ASC' : 'DESC';
        const ftsQuery = `"${query.replace(/"/g, '""')}"`;
        
        try {
          let rows;
          
          if (folder === 'inbox') {
            rows = await db.allAsync(
              `SELECT DISTINCT m.id, m.sender AS sender_name, m.subject, m.ts, r.is_read
               FROM messages_fts fts JOIN messages m ON m.id = fts.rowid
               JOIN message_recipients r ON r.message_id = m.id
               WHERE fts MATCH ? AND r.recipient = ? AND r.is_deleted = 0 AND m.is_draft = 0
               ORDER BY m.${sortBy} ${sortOrder} LIMIT ? OFFSET ?`,
              [ftsQuery, sender, limit, offset]
            );
          } else if (folder === 'sent') {
            rows = await db.allAsync(
              `SELECT m.id, m.sender AS sender_name, m.subject, m.ts, 0 AS is_read
               FROM messages_fts fts JOIN messages m ON m.id = fts.rowid
               WHERE fts MATCH ? AND m.sender = ? AND m.is_deleted = 0 AND m.is_draft = 0
               ORDER BY m.${sortBy} ${sortOrder} LIMIT ? OFFSET ?`,
              [ftsQuery, sender, limit, offset]
            );
          } else {
            rows = await db.allAsync(
              `SELECT DISTINCT m.id, m.sender AS sender_name, m.subject, m.ts, COALESCE(r.is_read, 0) AS is_read
               FROM messages_fts fts JOIN messages m ON m.id = fts.rowid
               LEFT JOIN message_recipients r ON r.message_id = m.id AND r.recipient = ?
               WHERE fts MATCH ? AND (m.sender = ? OR r.recipient = ?) AND (m.is_deleted = 0 OR r.is_deleted = 0) AND m.is_draft = 0
               ORDER BY m.${sortBy} ${sortOrder} LIMIT ? OFFSET ?`,
              [sender, ftsQuery, sender, sender, limit, offset]
            );
          }
          
          sendResponse({ code: 200, results: rows }, reqId);
          return;
        } catch (err) {
          logger.error('SEARCH error:', err);
          sendResponse({ code: 500, error: 'Search failed' }, reqId);
          return;
        }
      }

      // ===== LIST_THREADS =====
      if (msg.command === 'LIST_THREADS') {
        const offset = Math.max(0, parseInt(msg.offset) || 0);
        const limit = Math.min(Math.max(1, parseInt(msg.limit) || 20), 100);
        
        try {
          const rows = await db.allAsync(
  `SELECT m.thread_id,
   (SELECT subject FROM messages WHERE id = m.thread_id) AS subject,
   COUNT(DISTINCT m.id) AS message_count,
   MAX(m.ts) AS last_ts,
   (
     SELECT CASE 
       WHEN EXISTS (SELECT 1 FROM messages WHERE thread_id = m.thread_id AND sender != ?) 
       THEN (SELECT DISTINCT sender FROM messages WHERE thread_id = m.thread_id AND sender != ? LIMIT 1)
       ELSE (SELECT GROUP_CONCAT(DISTINCT recipient) FROM message_recipients WHERE message_id IN (SELECT id FROM messages WHERE thread_id = m.thread_id AND sender = ?) LIMIT 1)
     END
   ) AS other_party
   FROM messages m 
   LEFT JOIN message_recipients r ON r.message_id = m.id
   WHERE (r.recipient = ? OR m.sender = ?) 
   AND (r.is_deleted = 0 OR r.is_deleted IS NULL)
   AND m.is_draft = 0
   GROUP BY m.thread_id ORDER BY last_ts DESC LIMIT ? OFFSET ?`,
  [sender, sender, sender, sender, sender, limit, offset]
);
          
          // 🔥 Fix timestamp for client (ms conversion)
          const formattedThreads = rows.map(row => ({
            ...row,
            last_ts: row.last_ts ? Number(row.last_ts) * 1000 : Date.now()
          }));
          
          sendResponse({ code: 200, threads: formattedThreads }, reqId);
          return;
        } catch (err) {
          logger.error('LIST_THREADS error:', err);
          sendResponse({ code: 500, error: 'Server error' }, reqId);
          return;
        }
      }

      // ===== LIST_THREAD =====
if (msg.command === 'LIST_THREAD') {
  const { thread_id } = msg;
  
  if (typeof thread_id !== 'number') {
    sendResponse({ code: 400, error: 'Invalid thread_id' }, reqId);
    return;
  }
  
  try {
    const rows = await db.allAsync(
      `SELECT m.id, m.in_reply_to, m.sender AS sender_name,
       (SELECT GROUP_CONCAT(recipient, ',') FROM message_recipients WHERE message_id = m.id) AS to_addrs,
       m.subject, m.body, m.ts, 
       COALESCE((SELECT is_read FROM message_recipients WHERE message_id = m.id AND recipient = ?), 1) AS is_read
       FROM messages m
       WHERE m.thread_id = ? AND m.is_draft = 0
       ORDER BY m.ts ASC`,
      [sender, thread_id]
    );
    
    if (rows.length === 0) {
      sendResponse({ code: 404, error: 'Thread not found' }, reqId);
      return;
    }
    
    // Fix timestamp for client
    const formattedMessages = rows.map(row => ({
      ...row,
      ts: row.ts ? Number(row.ts) * 1000 : Date.now()
    }));
    
    sendResponse({ code: 200, messages: formattedMessages }, reqId);
    return;
  } catch (err) {
    logger.error('LIST_THREAD error:', err);
    sendResponse({ code: 500, error: 'Server error' }, reqId);
    return;
  }
}

      // ===== CREATE_LABEL =====
      if (msg.command === 'CREATE_LABEL') {
        const { name, color = '#3b82f6' } = msg;
        
        if (!name || typeof name !== 'string') {
          sendResponse({ code: 400, error: 'Invalid label name' }, reqId);
          return;
        }
        
        try {
          const result = await db.runAsync(
            `INSERT INTO labels (user_email, name, color) VALUES (?, ?, ?)`,
            [sender, sanitizeInput(name, 50), color]
          );
          
          sendResponse({ code: 200, result: 'Created', labelId: result.lastID }, reqId);
          return;
        } catch (err) {
          if (/UNIQUE constraint/.test(err.message)) {
            sendResponse({ code: 409, error: 'Label already exists' }, reqId);
          } else {
            logger.error('CREATE_LABEL error:', err);
            sendResponse({ code: 500, error: 'Server error' }, reqId);
          }
          return;
        }
      }

      // ===== LIST_LABELS =====
      if (msg.command === 'LIST_LABELS') {
        try {
          const labels = await db.allAsync(
            `SELECT id, name, color FROM labels WHERE user_email = ? ORDER BY name ASC`,
            [sender]
          );
          
          sendResponse({ code: 200, labels }, reqId);
          return;
        } catch (err) {
          logger.error('LIST_LABELS error:', err);
          sendResponse({ code: 500, error: 'Server error' }, reqId);
          return;
        }
      }
      
   if (msg.command === 'SEND') {
  const { to, cc = [], bcc = [], subject, body, hashcash } = msg;
  
  if (!Array.isArray(to) || to.length === 0 || !validateSubject(subject) || !validateBody(body)) {
    sendResponse({ code: 400, error: 'Invalid parameters' }, reqId);
    return;
  }
  if (!hashcash || !verifyHashcash(hashcash, sender)) {
    sendResponse({ code: 429, error: 'Invalid Hashcash' }, reqId);
    return;
  }

  const now = Math.floor(Date.now() / 1000);
  const sanitizedSubject = sanitizeInput(subject);
  const sanitizedBody = sanitizeInput(body, MAX_BODY_LENGTH);

  try {
    await db.runAsync('BEGIN IMMEDIATE');
    let messageInternalId;

    try {
      // Insert message WITHOUT thread_id first
      const result = await db.runAsync(
        `INSERT INTO messages (sender, subject, body, ts) VALUES (?, ?, ?, ?)`,
        [sender, sanitizedSubject, sanitizedBody, now]
      );
      
      messageInternalId = result.lastID;

      // ✅ Set thread_id to its own id (this starts a new thread)
      await db.runAsync(
        `UPDATE messages SET thread_id = ? WHERE id = ?`,
        [messageInternalId, messageInternalId]
      );

      for (const rcpt of to) {
        await db.runAsync(`INSERT INTO message_recipients (message_id, recipient, type) VALUES (?, ?, 'to')`, [messageInternalId, rcpt]);
      }
      for (const rcpt of cc) {
        await db.runAsync(`INSERT INTO message_recipients (message_id, recipient, type) VALUES (?, ?, 'cc')`, [messageInternalId, rcpt]);
      }

      await db.runAsync('COMMIT');
    } catch (innerErr) {
      await db.runAsync('ROLLBACK');
      throw innerErr;
    }

    // FTS manual update
    try {
      await db.runAsync(
        `INSERT INTO messages_fts(rowid, subject, body) VALUES (?, ?, ?)`,
        [messageInternalId, sanitizedSubject, sanitizedBody]
      );
    } catch (ftsErr) {
      logger.warn('FTS index failed:', ftsErr.message);
    }

    sendResponse({ code: 200, result: 'Sent', messageId: messageInternalId }, reqId);
    return; // ✅ Make sure this return is here!
  } catch (err) {
    logger.error('SEND error:', err);
    sendResponse({ code: 500, error: 'Server error' }, reqId);
    return; // ✅ And here!
  }
}

      // ===== APPLY_LABEL =====
      if (msg.command === 'APPLY_LABEL') {
        const { message_id, label_id } = msg;
        
        try {
          await db.runAsync(
            `INSERT OR IGNORE INTO message_labels (message_id, label_id) VALUES (?, ?)`,
            [message_id, label_id]
          );
          
          sendResponse({ code: 200, result: 'Applied' }, reqId);
          return;
        } catch (err) {
          logger.error('APPLY_LABEL error:', err);
          sendResponse({ code: 500, error: 'Server error' }, reqId);
          return;
        }
      }

      // ===== REMOVE_LABEL =====
      if (msg.command === 'REMOVE_LABEL') {
        const { message_id, label_id } = msg;
        
        try {
          await db.runAsync(
            `DELETE FROM message_labels WHERE message_id = ? AND label_id = ?`,
            [message_id, label_id]
          );
          
          sendResponse({ code: 200, result: 'Removed' }, reqId);
          return;
        } catch (err) {
          logger.error('REMOVE_LABEL error:', err);
          sendResponse({ code: 500, error: 'Server error' }, reqId);
          return;
        }
      }

      // ===== CREATE_FILTER =====
      if (msg.command === 'CREATE_FILTER') {
        const { name, condition_type, condition_value, action_type, action_value, priority = 0 } = msg;
        
        if (!name || !condition_type || !condition_value || !action_type) {
          sendResponse({ code: 400, error: 'Invalid filter parameters' }, reqId);
          return;
        }
        
        try {
          const result = await db.runAsync(
            `INSERT INTO filters (user_email, name, condition_type, condition_value, action_type, action_value, priority)
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [sender, sanitizeInput(name, 100), condition_type, condition_value, action_type, action_value, priority]
          );
          
          sendResponse({ code: 200, result: 'Created', filterId: result.lastID }, reqId);
          return;
        } catch (err) {
          logger.error('CREATE_FILTER error:', err);
          sendResponse({ code: 500, error: 'Server error' }, reqId);
          return;
        }
      }

      // ===== LIST_FILTERS =====
      if (msg.command === 'LIST_FILTERS') {
        try {
          const filters = await db.allAsync(
            `SELECT * FROM filters WHERE user_email = ? ORDER BY priority ASC`,
            [sender]
          );
          
          sendResponse({ code: 200, filters }, reqId);
          return;
        } catch (err) {
          logger.error('LIST_FILTERS error:', err);
          sendResponse({ code: 500, error: 'Server error' }, reqId);
          return;
        }
      }

      // ===== DELETE_FILTER =====
      if (msg.command === 'DELETE_FILTER') {
        const { filter_id } = msg;
        
        try {
          await db.runAsync(
            `DELETE FROM filters WHERE id = ? AND user_email = ?`,
            [filter_id, sender]
          );
          
          sendResponse({ code: 200, result: 'Deleted' }, reqId);
          return;
        } catch (err) {
          logger.error('DELETE_FILTER error:', err);
          sendResponse({ code: 500, error: 'Server error' }, reqId);
          return;
        }
      }

      // ===== CREATE_TEMPLATE =====
      if (msg.command === 'CREATE_TEMPLATE') {
        const { name, subject = '', body } = msg;
        
        if (!name || !body) {
          sendResponse({ code: 400, error: 'Invalid template parameters' }, reqId);
          return;
        }
        
        try {
          const result = await db.runAsync(
            `INSERT INTO templates (user_email, name, subject, body) VALUES (?, ?, ?, ?)`,
            [sender, sanitizeInput(name, 100), sanitizeInput(subject), sanitizeInput(body, MAX_BODY_LENGTH)]
          );
          
          sendResponse({ code: 200, result: 'Created', templateId: result.lastID }, reqId);
          return;
        } catch (err) {
          logger.error('CREATE_TEMPLATE error:', err);
          sendResponse({ code: 500, error: 'Server error' }, reqId);
          return;
        }
      }

      // ===== LIST_TEMPLATES =====
      if (msg.command === 'LIST_TEMPLATES') {
        try {
          const templates = await db.allAsync(
            `SELECT * FROM templates WHERE user_email = ? ORDER BY name ASC`,
            [sender]
          );
          
          sendResponse({ code: 200, templates }, reqId);
          return;
        } catch (err) {
          logger.error('LIST_TEMPLATES error:', err);
          sendResponse({ code: 500, error: 'Server error' }, reqId);
          return;
        }
      }

      // ===== ADD_CONTACT =====
      if (msg.command === 'ADD_CONTACT') {
        const { contact_email, display_name, notes = '' } = msg;
        
        if (!validateEmail(contact_email)) {
          sendResponse({ code: 400, error: 'Invalid email' }, reqId);
          return;
        }
        
        try {
          const now = Math.floor(Date.now() / 1000);
          const result = await db.runAsync(
            `INSERT INTO contacts (user_email, contact_email, display_name, notes, added_at)
             VALUES (?, ?, ?, ?, ?)`,
            [sender, contact_email, sanitizeInput(display_name, 100), sanitizeInput(notes), now]
          );
          
          sendResponse({ code: 200, result: 'Added', contactId: result.lastID }, reqId);
          return;
        } catch (err) {
          logger.error('ADD_CONTACT error:', err);
          sendResponse({ code: 500, error: 'Server error' }, reqId);
          return;
        }
      }

      // ===== LIST_CONTACTS =====
      if (msg.command === 'LIST_CONTACTS') {
        try {
          const contacts = await db.allAsync(
            `SELECT * FROM contacts WHERE user_email = ? ORDER BY display_name ASC`,
            [sender]
          );
          
          sendResponse({ code: 200, contacts }, reqId);
          return;
        } catch (err) {
          logger.error('LIST_CONTACTS error:', err);
          sendResponse({ code: 500, error: 'Server error' }, reqId);
          return;
        }
      }

      // ===== BLOCK_SENDER =====
      if (msg.command === 'BLOCK_SENDER') {
        const { email } = msg;
        
        if (!validateEmail(email)) {
          sendResponse({ code: 400, error: 'Invalid email' }, reqId);
          return;
        }
        
        try {
          const now = Math.floor(Date.now() / 1000);
          await db.runAsync(
            `INSERT OR IGNORE INTO blocked_senders (user_email, blocked_email, blocked_at) VALUES (?, ?, ?)`,
            [sender, email, now]
          );
          
          sendResponse({ code: 200, result: 'Blocked' }, reqId);
          return;
        } catch (err) {
          logger.error('BLOCK_SENDER error:', err);
          sendResponse({ code: 500, error: 'Server error' }, reqId);
          return;
        }
      }

      // ===== UNBLOCK_SENDER =====
      if (msg.command === 'UNBLOCK_SENDER') {
        const { email } = msg;
        
        try {
          await db.runAsync(
            `DELETE FROM blocked_senders WHERE user_email = ? AND blocked_email = ?`,
            [sender, email]
          );
          
          sendResponse({ code: 200, result: 'Unblocked' }, reqId);
          return;
        } catch (err) {
          logger.error('UNBLOCK_SENDER error:', err);
          sendResponse({ code: 500, error: 'Server error' }, reqId);
          return;
        }
      }

      // ===== UPDATE_PREFERENCES =====
      if (msg.command === 'UPDATE_PREFERENCES') {
        const { signature, preferences } = msg;
        
        try {
          if (signature !== undefined) {
            await db.runAsync(
              `UPDATE users SET signature = ? WHERE email = ?`,
              [sanitizeInput(signature, 1000), sender]
            );
          }
          
          if (preferences !== undefined) {
            await db.runAsync(
              `UPDATE users SET preferences = ? WHERE email = ?`,
              [JSON.stringify(preferences), sender]
            );
          }
          
          sendResponse({ code: 200, result: 'Updated' }, reqId);
          return;
        } catch (err) {
          logger.error('UPDATE_PREFERENCES error:', err);
          sendResponse({ code: 500, error: 'Server error' }, reqId);
          return;
        }
      }

      // ===== GET_PREFERENCES =====
      if (msg.command === 'GET_PREFERENCES') {
        try {
          const prefs = await db.getAsync(
            `SELECT signature, preferences FROM users WHERE email = ?`,
            [sender]
          );
          
          const preferences = prefs.preferences ? JSON.parse(prefs.preferences) : {};
          
          sendResponse({ 
            code: 200, 
            signature: prefs.signature || '', 
            preferences 
          }, reqId);
          return;
        } catch (err) {
          logger.error('GET_PREFERENCES error:', err);
          sendResponse({ code: 500, error: 'Server error' }, reqId);
          return;
        }
      }

      // ===== Unknown command =====
      sendResponse({ code: 400, error: 'Unknown command' }, reqId);
      return;

    } catch (err) {
      logger.error('Command error:', err);
      sendResponse({ code: 500, error: 'Internal server error' }, msg.requestId);
      return;
    }
  });

  framer.on('error', err => {
    logger.error('❌ Framer error:', err);
    socket.end();
  });

  socket.on('error', err => {
    logger.error('❌ Socket error:', err);
  });

  socket.on('end', () => {
    logger.info('↙ Client disconnected');
  });
}

// ============================================================================
// MAIN STARTUP
// ============================================================================

async function startServer() {
  try {
    // 1. Database initialization FIRST
    await setupDatabase();
    
    logger.info('🚀 Starting network services...');
    
    // 2. Load TLS certificates
    const tlsOpts = {
      key: fs.readFileSync(config.tls.keyFile),
      cert: fs.readFileSync(config.tls.certFile)
    };
    
    const publicKey = fs.readFileSync(config.jwt.publicKeyFile);
    const privateKey = fs.readFileSync(config.jwt.privateKeyFile);
    
    // Make these available globally
    global.publicKey = publicKey;
    global.privateKey = privateKey;
    
    // 3. Plaintext server (STARTTLS)
    const server = net.createServer((plainSocket) => {
      logger.info('↗ Client connected:', plainSocket.remoteAddress);
      plainSocket.write('220 yolo.com OurMail v2.0 ready\r\n');
      let upgraded = false;
      
      plainSocket.on('data', chunk => {
        const line = chunk.toString().trim();
        if (!upgraded && line === 'STARTTLS') {
          plainSocket.write('220 Ready to start TLS\r\n');
          plainSocket.pause();
          const secureSocket = new tls.TLSSocket(plainSocket, {
            isServer: true, key: tlsOpts.key, cert: tlsOpts.cert
          });
          secureSocket.once('secure', () => {
            upgraded = true;
            logger.info('🔒 TLS handshake complete');
            initSecureConnection(secureSocket);
          });
          secureSocket.on('error', err => logger.error('❌ TLS error:', err));
          secureSocket.resume();
          plainSocket.removeAllListeners('data');
        } else if (!upgraded) {
          plainSocket.write('530 Must issue STARTTLS first\r\n');
        }
      });
      
      plainSocket.on('error', err => logger.error('Socket error:', err));
      plainSocket.on('end', () => logger.info('↙ Client disconnected'));
    });
    
    server.listen(config.plaintext.port, () => {
      logger.info(`✨ Ymail plaintext server on port ${config.plaintext.port}`);
    });
    
    // 4. Direct TLS server
    const tlsServer = tls.createServer(tlsOpts, socket => {
      logger.info('🔒 Direct-TLS client connected:', socket.remoteAddress);
      initSecureConnection(socket);
    });
    
    tlsServer.listen(config.tls.port, () => {
      logger.info(`✨ Ymail TLS server on port ${config.tls.port}`);
    });
    
    // 5. WebSocket server
    const wss = new WebSocket.Server({ port: config.websocket.port });
    
    wss.on('connection', ws => {
      logger.info('🕸️ WS client connected');
      const fakeSocket = new EventEmitter();
      fakeSocket.remoteAddress = ws._socket ? ws._socket.remoteAddress : 'websocket';
      fakeSocket.write = buf => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(buf);
          return true;
        }
        return false;
      };
      fakeSocket.end = () => {
        if (ws.readyState === WebSocket.OPEN) ws.close();
      };
      ws.on('message', data => {
        const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
        fakeSocket.emit('data', buf);
      });
      ws.on('close', () => fakeSocket.emit('end'));
      ws.on('error', err => logger.error('🕸️ WS error:', err));
      initSecureConnection(fakeSocket);
    });
    
    logger.info(`✨ Ymail WebSocket server on port ${config.websocket.port}`);
    
    // 6. HTTP API
    const api = express();
    api.use(cors());
    api.use(express.json());
    
    const apiLimiter = rateLimit({
      windowMs: 15 * 60 * 1000,
      max: 100
    });
    
    api.use(apiLimiter);
    
    api.get('/mint', async (req, res) => {
      const resource = String(req.query.resource || '');
      const bits = Math.min(Math.max(parseInt(req.query.bits) || 16, 16), 32);
      
      if (!resource || !validateEmail(resource)) {
        return res.status(400).json({ error: 'Invalid resource' });
      }
      
      try {
        const { mint } = require('./mint');
        const stamp = await mint(resource, bits);
        res.json({ stamp });
      } catch (err) {
        logger.error('Mint error:', err);
        res.status(500).json({ error: 'Mint failed' });
      }
    });
    
    api.get('/health', (req, res) => {
      res.json({
        status: 'ok',
        dbReady,
        timestamp: Date.now(),
        uptime: process.uptime(),
        emailBridge: config.emailBridge.enabled
      });
    });
    
    api.listen(3001, () => {
      logger.info('⚡ HTTP API on port 3001');
    });
    
    logger.info('🎉 ALL SERVICES STARTED SUCCESSFULLY');
    logger.info('🚀 Ymail Server v2.0 ready to accept connections');
    
  } catch (error) {
    logger.error('❌ SERVER STARTUP FAILED:', error);
    process.exit(1);
  }
}

// ============================================================================
// GRACEFUL SHUTDOWN
// ============================================================================

process.on('SIGINT', () => {
  logger.info('\n🛑 Shutting down gracefully...');
  if (db) {
    db.close((err) => {
      if (err) logger.error('Error closing database:', err);
      else logger.info('✅ Database closed');
      process.exit(0);
    });
  } else {
    process.exit(0);
  }
});

process.on('SIGTERM', () => {
  logger.info('\n🛑 SIGTERM received, shutting down...');
  if (db) {
    db.close((err) => {
      if (err) logger.error('Error closing database:', err);
      else logger.info('✅ Database closed');
      process.exit(0);
    });
  } else {
    process.exit(0);
  }
});

process.on('uncaughtException', (err) => {
  logger.error('💥 Uncaught Exception:', err);
  if (db) {
    db.close(() => {
      process.exit(1);
    });
  } else {
    process.exit(1);
  }
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
});

// ============================================================================
// START THE SERVER
// ============================================================================


startServer();




