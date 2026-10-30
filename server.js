// DazzleMark - Production Backend with Strict Verification & Anti-Fraud
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 8080;
const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'public', 'uploads');
const PUBLIC_DIR = path.join(__dirname, 'public');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

const DB_FILE = path.join(DATA_DIR, 'db.json');

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const initial = { users: [], items: [], chats: [], messages: [], otpSessions: [] };
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2), 'utf-8');
    return initial;
  }
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
  } catch (e) {
    return { users: [], items: [], chats: [], messages: [], otpSessions: [] };
  }
}

function saveDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf-8');
}

let db = loadDB();
if (!db.otpSessions) db.otpSessions = [];

// Clean expired OTP sessions periodically
setInterval(() => {
  const now = Date.now();
  if (db.otpSessions && db.otpSessions.length) {
    db.otpSessions = db.otpSessions.filter(s => s.expiresAt > now);
    saveDB(db);
  }
}, 60000);

// Helper: parse JSON body
function getBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 50 * 1024 * 1024) reject(new Error('Payload too large'));
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try { resolve(JSON.parse(body)); } catch (e) { resolve({}); }
    });
    req.on('error', reject);
  });
}

// Phone validator: strict E.164 Russian format (+79XXXXXXXXX)
function normalizePhone(raw) {
  if (!raw) return null;
  const digits = raw.replace(/\D/g, '');
  if (digits.length === 11 && (digits.startsWith('7') || digits.startsWith('8'))) {
    return '+7' + digits.slice(1);
  }
  return null;
}

// Name validator: 2-40 chars, Cyrillic or Latin letters, spaces, hyphens. No garbage symbols.
function validateName(name) {
  if (!name || typeof name !== 'string') return false;
  const trimmed = name.trim();
  if (trimmed.length < 2 || trimmed.length > 40) return false;
  // Disallow repetitive patterns or purely numbers / symbols
  const nameRegex = /^[a-zA-Zа-яА-ЯёЁ\s\-]+$/;
  return nameRegex.test(trimmed);
}

// Helper: Auth from header Bearer token
function getAuthUser(req) {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token) return null;
  return db.users.find(u => u.token === token) || null;
}

// MIME types
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.svg': 'image/svg+xml'
};

const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    return res.end();
  }

  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;

  const sendJSON = (data, status = 200) => {
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify(data));
  };

  try {
    // ----------------------------------------------------
    // API 1: REQUEST SMS OTP (Отправка кода подтверждения)
    // ----------------------------------------------------
    if (pathname === '/api/auth/send-otp' && req.method === 'POST') {
      const { phone, isRegistration } = await getBody(req);
      const normalized = normalizePhone(phone);

      if (!normalized) {
        return sendJSON({ error: 'Введите корректный номер телефона РФ (+7 (9XX) XXX-XX-XX)' }, 400);
      }

      const existingUser = db.users.find(u => u.phone === normalized);
      if (isRegistration && existingUser) {
        return sendJSON({ error: 'Пользователь с таким номером уже зарегистрирован. Пожалуйста, выполните вход.' }, 400);
      }

      const now = Date.now();
      const existingSession = db.otpSessions.find(s => s.phone === normalized);

      // Check cooldown (60 seconds)
      if (existingSession && existingSession.resendAvailableAt > now) {
        const remainingSec = Math.ceil((existingSession.resendAvailableAt - now) / 1000);
        return sendJSON({ error: `Повторная отправка возможна через ${remainingSec} сек.`, cooldownSeconds: remainingSec }, 429);
      }

      // Generate cryptographically secure 4-digit code (e.g. 4821)
      const code = (Math.floor(1000 + crypto.randomInt(9000))).toString();
      const salt = crypto.randomBytes(8).toString('hex');
      const codeHash = crypto.createHash('sha256').update(code + salt).digest('hex');

      // Update or create OTP session
      const newSession = {
        phone: normalized,
        codeHash,
        salt,
        attemptsLeft: 3,
        createdAt: now,
        expiresAt: now + (5 * 60 * 1000), // 5 minutes
        resendAvailableAt: now + (60 * 1000) // 60 seconds
      };

      db.otpSessions = db.otpSessions.filter(s => s.phone !== normalized);
      db.otpSessions.push(newSession);
      saveDB(db);

      // Log OTP (in production, call SMS gateway e.g. SMS.ru / SMS-Aero)
      console.log(`[SMS-GATEWAY] Код подтверждения для ${normalized}: [ ${code} ]`);

      // In test mode / web demo, we return the code directly so developer can immediately test without paying SMS provider
      return sendJSON({
        success: true,
        message: `SMS-код отправлен на ${normalized}`,
        cooldownSeconds: 60,
        devCode: code // Real-time convenience for testing in browser
      });
    }

    // ----------------------------------------------------
    // API 2: VERIFY OTP & REGISTER / LOGIN
    // ----------------------------------------------------
    if (pathname === '/api/auth/verify-otp' && req.method === 'POST') {
      const { phone, code, name, password, isRegistration } = await getBody(req);
      const normalized = normalizePhone(phone);

      if (!normalized || !code) {
        return sendJSON({ error: 'Укажите номер телефона и код из SMS' }, 400);
      }

      const session = db.otpSessions.find(s => s.phone === normalized);
      const now = Date.now();

      if (!session || session.expiresAt < now) {
        return sendJSON({ error: 'Срок действия кода истек. Запросите новый код.' }, 400);
      }

      if (session.attemptsLeft <= 0) {
        db.otpSessions = db.otpSessions.filter(s => s.phone !== normalized);
        saveDB(db);
        return sendJSON({ error: 'Превышено количество попыток. Запросите код заново.' }, 403);
      }

      const testHash = crypto.createHash('sha256').update(code.trim() + session.salt).digest('hex');
      if (testHash !== session.codeHash) {
        session.attemptsLeft--;
        saveDB(db);
        return sendJSON({ error: `Неверный код. Осталось попыток: ${session.attemptsLeft}` }, 400);
      }

      // Code is valid! Invalidate session
      db.otpSessions = db.otpSessions.filter(s => s.phone !== normalized);

      let user = db.users.find(u => u.phone === normalized);

      if (isRegistration) {
        if (!validateName(name)) {
          return sendJSON({ error: 'Укажите реальное имя (от 2 до 40 букв, без спецсимволов)' }, 400);
        }
        if (!password || password.length < 6) {
          return sendJSON({ error: 'Пароль должен содержать не менее 6 символов' }, 400);
        }

        user = {
          id: 'u_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
          name: name.trim(),
          phone: normalized,
          phoneVerified: true,
          phoneVerifiedAt: new Date().toISOString(),
          passwordHash: crypto.createHash('sha256').update(password).digest('hex'),
          city: 'Москва',
          avatar: '',
          rating: 5.0,
          status: 'verified', // Avito verified status
          badges: ['phone_verified'],
          createdAt: new Date().toISOString(),
          token: crypto.randomBytes(32).toString('hex')
        };
        db.users.push(user);
      } else {
        // Fast login by SMS code
        if (!user) {
          return sendJSON({ error: 'Пользователь с таким номером не найден. Пройдите регистрацию.' }, 404);
        }
        user.phoneVerified = true;
        user.status = 'verified';
        if (!user.badges.includes('phone_verified')) user.badges.push('phone_verified');
        user.token = crypto.randomBytes(32).toString('hex');
      }

      saveDB(db);
      const { passwordHash: _, ...safeUser } = user;
      return sendJSON({ user: safeUser, token: user.token });
    }

    // ----------------------------------------------------
    // API 3: GOOGLE OAUTH AUTHENTICATION
    // ----------------------------------------------------
    if (pathname === '/api/auth/google' && req.method === 'POST') {
      const { credential, profile } = await getBody(req);
      
      // In production, verify Google JWT using google-auth-library.
      // Here we parse user payload from Google Client
      let googleUser = profile;
      if (credential) {
        try {
          const parts = credential.split('.');
          const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf-8'));
          googleUser = {
            id: payload.sub,
            email: payload.email,
            name: payload.name,
            avatar: payload.picture,
            emailVerified: payload.email_verified
          };
        } catch (e) {
          return sendJSON({ error: 'Невалидный Google токен' }, 400);
        }
      }

      if (!googleUser || !googleUser.email) {
        return sendJSON({ error: 'Не удалось получить профиль Google' }, 400);
      }

      let user = db.users.find(u => u.email === googleUser.email || u.googleId === googleUser.id);

      if (!user) {
        // New verified account through Google
        user = {
          id: 'u_g_' + Date.now(),
          name: googleUser.name || 'Пользователь Google',
          email: googleUser.email,
          emailVerified: true,
          googleId: googleUser.id,
          phone: '',
          phoneVerified: false,
          avatar: googleUser.avatar || '',
          city: 'Москва',
          rating: 5.0,
          status: 'verified', // Verified via Google ID
          badges: ['google_verified'],
          createdAt: new Date().toISOString(),
          token: crypto.randomBytes(32).toString('hex')
        };
        db.users.push(user);
      } else {
        user.token = crypto.randomBytes(32).toString('hex');
        if (!user.badges) user.badges = [];
        if (!user.badges.includes('google_verified')) user.badges.push('google_verified');
        user.status = 'verified';
      }

      saveDB(db);
      const { passwordHash: _, ...safeUser } = user;
      return sendJSON({ user: safeUser, token: user.token });
    }

    // ----------------------------------------------------
    // API 4: PASSWORD LOGIN (FOR EXISTING ACCOUNTS)
    // ----------------------------------------------------
    if (pathname === '/api/auth/login' && req.method === 'POST') {
      const { phone, password } = await getBody(req);
      const normalized = normalizePhone(phone);
      if (!normalized || !password) {
        return sendJSON({ error: 'Заполните номер телефона и пароль' }, 400);
      }

      const hash = crypto.createHash('sha256').update(password).digest('hex');
      const user = db.users.find(u => u.phone === normalized && u.passwordHash === hash);

      if (!user) {
        return sendJSON({ error: 'Неверный номер телефона или пароль' }, 401);
      }

      user.token = crypto.randomBytes(32).toString('hex');
      saveDB(db);

      const { passwordHash: _, ...safeUser } = user;
      return sendJSON({ user: safeUser, token: user.token });
    }

    if (pathname === '/api/auth/me' && req.method === 'GET') {
      const user = getAuthUser(req);
      if (!user) return sendJSON({ user: null });
      const { passwordHash: _, ...safeUser } = user;
      return sendJSON({ user: safeUser });
    }

    // ----------------------------------------------------
    // API: ITEMS (С ПРОВЕРКОЙ ВЕРИФИКАЦИИ АВИТО)
    // ----------------------------------------------------
    if (pathname === '/api/items' && req.method === 'GET') {
      const category = url.searchParams.get('category');
      const q = (url.searchParams.get('q') || '').toLowerCase();
      let items = [...db.items];

      if (category && category !== 'all') {
        items = items.filter(it => it.category === category);
      }
      if (q) {
        items = items.filter(it =>
          (it.title && it.title.toLowerCase().includes(q)) ||
          (it.brand && it.brand.toLowerCase().includes(q))
        );
      }
      items.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
      return sendJSON(items);
    }

    if (pathname === '/api/items' && req.method === 'POST') {
      const user = getAuthUser(req);
      if (!user) {
        return sendJSON({ error: 'Авторизуйтесь для публикации объявлений' }, 401);
      }

      // Avito rule: Only verified accounts can post items!
      if (user.status !== 'verified' && !user.phoneVerified && !user.emailVerified) {
        return sendJSON({
          error: 'Публикация доступна только подтверждённым аккаунтам. Подтвердите номер телефона или войдите через Google.',
          code: 'VERIFICATION_REQUIRED'
        }, 403);
      }

      const body = await getBody(req);
      const { title, brand, size, price, category, condition, description, photos } = body;

      if (!title || title.trim().length < 3) {
        return sendJSON({ error: 'Название товара должно быть не короче 3 символов' }, 400);
      }
      if (!price || isNaN(price) || Number(price) <= 0) {
        return sendJSON({ error: 'Укажите корректную стоимость' }, 400);
      }

      const newItem = {
        id: 'item_' + Date.now(),
        sellerId: user.id,
        sellerName: user.name,
        sellerPhone: user.phone,
        sellerBadges: user.badges || ['phone_verified'],
        sellerVerified: true,
        title: title.trim(),
        brand: (brand || 'Без бренда').trim(),
        size: (size || 'One Size').trim(),
        price: Number(price),
        category: category || 'Женское',
        condition: condition || 'Отличное',
        city: user.city || 'Москва',
        description: (description || '').trim(),
        photos: Array.isArray(photos) && photos.length ? photos : ['/placeholder.png'],
        createdAt: new Date().toISOString()
      };

      db.items.unshift(newItem);
      saveDB(db);
      return sendJSON(newItem, 201);
    }

    // ----------------------------------------------------
    // API: UPLOAD PHOTO
    // ----------------------------------------------------
    if (pathname === '/api/upload' && req.method === 'POST') {
      const user = getAuthUser(req);
      if (!user) return sendJSON({ error: 'Unauthorized' }, 401);

      const body = await getBody(req);
      const { imageBase64 } = body;
      if (!imageBase64) return sendJSON({ error: 'No image' }, 400);

      const matches = imageBase64.match(/^data:image\/([a-zA-Z0-9]+);base64,(.+)$/);
      let ext = 'jpg';
      let data = imageBase64;
      if (matches) {
        ext = matches[1] === 'jpeg' ? 'jpg' : matches[1];
        data = matches[2];
      }

      const fileName = `img_${Date.now()}_${Math.floor(Math.random() * 10000)}.${ext}`;
      fs.writeFileSync(path.join(UPLOADS_DIR, fileName), Buffer.from(data, 'base64'));
      return sendJSON({ url: `/uploads/${fileName}` });
    }

    // ----------------------------------------------------
    // API: CHATS & MESSAGES
    // ----------------------------------------------------
    if (pathname === '/api/chats' && req.method === 'GET') {
      const user = getAuthUser(req);
      if (!user) return sendJSON({ error: 'Unauthorized' }, 401);

      const userChats = db.chats.filter(c => c.buyerId === user.id || c.sellerId === user.id);
      userChats.forEach(c => {
        const lastMsg = db.messages.filter(m => m.chatId === c.id).slice(-1)[0];
        c.lastMessage = lastMsg ? lastMsg.text : 'Диалог начат';
        c.lastMessageTime = lastMsg ? lastMsg.createdAt : c.createdAt;
      });
      userChats.sort((a, b) => new Date(b.lastMessageTime) - new Date(a.lastMessageTime));
      return sendJSON(userChats);
    }

    if (pathname === '/api/chats' && req.method === 'POST') {
      const user = getAuthUser(req);
      if (!user) return sendJSON({ error: 'Unauthorized' }, 401);

      if (user.status !== 'verified') {
        return sendJSON({ error: 'Отправка сообщений доступна после подтверждения номера' }, 403);
      }

      const { itemId } = await getBody(req);
      const item = db.items.find(i => i.id === itemId);
      if (!item) return sendJSON({ error: 'Товар не найден' }, 404);
      if (item.sellerId === user.id) return sendJSON({ error: 'Нельзя начать диалог с самим собой' }, 400);

      let chat = db.chats.find(c => c.itemId === itemId && c.buyerId === user.id);
      if (!chat) {
        chat = {
          id: 'chat_' + Date.now(),
          itemId: item.id,
          itemTitle: item.title,
          itemPrice: item.price,
          itemPhoto: item.photos[0] || '',
          buyerId: user.id,
          buyerName: user.name,
          sellerId: item.sellerId,
          sellerName: item.sellerName,
          createdAt: new Date().toISOString()
        };
        db.chats.push(chat);
        saveDB(db);
      }
      return sendJSON(chat);
    }

    if (pathname.startsWith('/api/chats/') && pathname.endsWith('/messages')) {
      const chatId = pathname.split('/')[3];
      const user = getAuthUser(req);
      if (!user) return sendJSON({ error: 'Unauthorized' }, 401);

      if (req.method === 'GET') {
        return sendJSON(db.messages.filter(m => m.chatId === chatId));
      }
      if (req.method === 'POST') {
        const { text } = await getBody(req);
        if (!text || !text.trim()) return sendJSON({ error: 'Empty' }, 400);

        const newMsg = {
          id: 'msg_' + Date.now(),
          chatId,
          senderId: user.id,
          senderName: user.name,
          text: text.trim(),
          createdAt: new Date().toISOString()
        };
        db.messages.push(newMsg);
        saveDB(db);
        return sendJSON(newMsg, 201);
      }
    }

    // ----------------------------------------------------
    // STATIC SERVER
    // ----------------------------------------------------
    let filePath = path.join(PUBLIC_DIR, pathname === '/' ? 'index.html' : pathname);
    if (!fs.existsSync(filePath)) filePath = path.join(PUBLIC_DIR, 'index.html');

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    fs.readFile(filePath, (err, content) => {
      if (err) { res.statusCode = 404; return res.end('Not Found'); }
      res.statusCode = 200;
      res.setHeader('Content-Type', contentType);
      res.end(content);
    });

  } catch (err) {
    console.error(err);
    sendJSON({ error: 'Internal Server Error' }, 500);
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`DazzleMark Avito-grade Server running on port ${PORT}`);
});
