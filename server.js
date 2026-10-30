// DazzleMark - Real C2C Fashion Marketplace Server
// Zero external dependencies (uses native Node.js: http, fs, crypto, path)

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

// --- Simple JSON Database ---
const DB_FILE = path.join(DATA_DIR, 'db.json');

function loadDB() {
  if (!fs.existsSync(DB_FILE)) {
    const initial = {
      users: [],
      items: [],
      chats: [],
      messages: []
    };
    fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2), 'utf-8');
    return initial;
  }
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf-8'));
  } catch (e) {
    return { users: [], items: [], chats: [], messages: [] };
  }
}

function saveDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), 'utf-8');
}

let db = loadDB();

// Helper: parse JSON body
function getBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 50 * 1024 * 1024) { // 50MB max for multiple photos
        reject(new Error('Payload too large'));
      }
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch (err) {
        resolve({});
      }
    });
    req.on('error', reject);
  });
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

// --- HTTP SERVER ---
const server = http.createServer(async (req, res) => {
  // Enable CORS
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
    // API: AUTH
    // ----------------------------------------------------
    if (pathname === '/api/auth/register' && req.method === 'POST') {
      const { name, phone, password, city } = await getBody(req);
      if (!name || !phone || !password) {
        return sendJSON({ error: 'Заполните имя, телефон и пароль' }, 400);
      }

      const existing = db.users.find(u => u.phone === phone);
      if (existing) {
        return sendJSON({ error: 'Пользователь с таким телефоном уже существует' }, 400);
      }

      const token = crypto.randomBytes(24).toString('hex');
      const newUser = {
        id: 'u_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
        name: name.trim(),
        phone: phone.trim(),
        password: crypto.createHash('sha256').update(password).digest('hex'),
        city: city ? city.trim() : 'Москва',
        avatar: '',
        rating: 5.0,
        dealsCount: 0,
        createdAt: new Date().toISOString(),
        token
      };

      db.users.push(newUser);
      saveDB(db);

      const { password: _, ...safeUser } = newUser;
      return sendJSON({ user: safeUser, token });
    }

    if (pathname === '/api/auth/login' && req.method === 'POST') {
      const { phone, password } = await getBody(req);
      const hash = crypto.createHash('sha256').update(password || '').digest('hex');
      const user = db.users.find(u => u.phone === phone && u.password === hash);

      if (!user) {
        return sendJSON({ error: 'Неверный телефон или пароль' }, 401);
      }

      user.token = crypto.randomBytes(24).toString('hex');
      saveDB(db);

      const { password: _, ...safeUser } = user;
      return sendJSON({ user: safeUser, token: user.token });
    }

    if (pathname === '/api/auth/me' && req.method === 'GET') {
      const user = getAuthUser(req);
      if (!user) return sendJSON({ user: null });
      const { password: _, ...safeUser } = user;
      return sendJSON({ user: safeUser });
    }

    // ----------------------------------------------------
    // API: ITEMS (ОБЪЯВЛЕНИЯ)
    // ----------------------------------------------------
    if (pathname === '/api/items' && req.method === 'GET') {
      const category = url.searchParams.get('category');
      const q = (url.searchParams.get('q') || '').toLowerCase();
      const sort = url.searchParams.get('sort') || 'new';

      let items = [...db.items];

      if (category && category !== 'all') {
        items = items.filter(it => it.category === category);
      }

      if (q) {
        items = items.filter(it =>
          (it.title && it.title.toLowerCase().includes(q)) ||
          (it.brand && it.brand.toLowerCase().includes(q)) ||
          (it.description && it.description.toLowerCase().includes(q))
        );
      }

      if (sort === 'cheap') items.sort((a, b) => a.price - b.price);
      else if (sort === 'expensive') items.sort((a, b) => b.price - a.price);
      else items.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

      return sendJSON(items);
    }

    if (pathname === '/api/items' && req.method === 'POST') {
      const user = getAuthUser(req);
      if (!user) {
        return sendJSON({ error: 'Авторизуйтесь, чтобы выставить вещь на продажу' }, 401);
      }

      const body = await getBody(req);
      const { title, brand, size, price, category, condition, description, photos } = body;

      if (!title || !price) {
        return sendJSON({ error: 'Укажите название и цену вещи' }, 400);
      }

      const newItem = {
        id: 'item_' + Date.now(),
        sellerId: user.id,
        sellerName: user.name,
        sellerPhone: user.phone,
        sellerRating: user.rating,
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
    // API: UPLOAD PHOTO (Base64 handler to file)
    // ----------------------------------------------------
    if (pathname === '/api/upload' && req.method === 'POST') {
      const user = getAuthUser(req);
      if (!user) return sendJSON({ error: 'Unauthorized' }, 401);

      const body = await getBody(req);
      const { imageBase64 } = body;
      if (!imageBase64) return sendJSON({ error: 'No image provided' }, 400);

      const matches = imageBase64.match(/^data:image\/([a-zA-Z0-9]+);base64,(.+)$/);
      let ext = 'jpg';
      let data = imageBase64;
      if (matches) {
        ext = matches[1] === 'jpeg' ? 'jpg' : matches[1];
        data = matches[2];
      }

      const fileName = `img_${Date.now()}_${Math.floor(Math.random() * 10000)}.${ext}`;
      const filePath = path.join(UPLOADS_DIR, fileName);
      fs.writeFileSync(filePath, Buffer.from(data, 'base64'));

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

      const { itemId } = await getBody(req);
      const item = db.items.find(i => i.id === itemId);
      if (!item) return sendJSON({ error: 'Товар не найден' }, 404);

      if (item.sellerId === user.id) {
        return sendJSON({ error: 'Нельзя написать самому себе' }, 400);
      }

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
        const msgs = db.messages.filter(m => m.chatId === chatId);
        return sendJSON(msgs);
      }

      if (req.method === 'POST') {
        const { text } = await getBody(req);
        if (!text || !text.trim()) return sendJSON({ error: 'Empty message' }, 400);

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
    // STATIC FILE SERVER
    // ----------------------------------------------------
    let filePath = path.join(PUBLIC_DIR, pathname === '/' ? 'index.html' : pathname);
    if (!fs.existsSync(filePath)) {
      filePath = path.join(PUBLIC_DIR, 'index.html');
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    fs.readFile(filePath, (err, content) => {
      if (err) {
        res.statusCode = 404;
        return res.end('Not Found');
      }
      res.statusCode = 200;
      res.setHeader('Content-Type', contentType);
      res.end(content);
    });

  } catch (err) {
    console.error('Server error:', err);
    sendJSON({ error: 'Internal Server Error' }, 500);
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`===============================================`);
  console.log(` DazzleMark Live Platform is RUNNING!`);
  console.log(` Port: ${PORT}`);
  console.log(` Local: http://localhost:${PORT}`);
  console.log(`===============================================`);
});
