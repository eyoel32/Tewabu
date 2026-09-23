require('dotenv').config();
const db = require('./db');
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const { fromBuffer: fileTypeFromBuffer } = require('file-type');
const { doubleCsrf } = require('csrf-csrf');
// Adjust this path to wherever LoginLimiter.js actually lives in your project
// (looked like Views/Middleware/LoginLimiter.js in your VS Code screenshot)
const { recordFailure, isLocked, clearAttempts } = require('./views/middleware/loginlimiter');

const app = express();
const SHOP_NAME = 'Tewabu Shifon';
const WHATSAPP_NUMBER = '251932174589';
const TELEGRAM_USERNAME = 'we4543';

// ---------- secrets: pull from environment, never hardcode ----------
const OWNER_USERNAME = process.env.OWNER_USERNAME;
const OWNER_PASSWORD = process.env.OWNER_PASSWORD; // only used for first-run seed
const SESSION_SECRET = process.env.SESSION_SECRET;
const CSRF_SECRET = process.env.CSRF_SECRET;

if (!SESSION_SECRET || !CSRF_SECRET) {
  throw new Error('SESSION_SECRET and CSRF_SECRET must be set in your .env file');
}

// Cloth code shown to customers, for example TS-0007
const CODE_PREFIX = 'TS';
app.locals.codeOf = (id) => CODE_PREFIX + '-' + String(id).padStart(4, '0');

// First start only: create the owner in the database
if (!db.prepare('SELECT 1 FROM owner WHERE id = 1').get()) {
  if (!OWNER_USERNAME || !OWNER_PASSWORD) {
    throw new Error('Set OWNER_USERNAME and OWNER_PASSWORD in .env for first-time setup');
  }
  db.prepare('INSERT INTO owner (id, username, password_hash) VALUES (1, ?, ?)')
    .run(OWNER_USERNAME, bcrypt.hashSync(OWNER_PASSWORD, 12));
}

// ---------- uploads: accept into memory first, verify real content, then write to disk ----------
const ALLOWED_TYPES = {
  'image/jpeg': '.jpg',
  'image/png': '.png',
  'image/webp': '.webp',
};
const DATA_DIR = process.env.DATA_DIR || '.';
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const upload = multer({
  storage: multer.memoryStorage(),
  fileFilter: (req, file, cb) => cb(null, !!ALLOWED_TYPES[file.mimetype]),
  limits: { fileSize: 5 * 1024 * 1024 },
});
async function validateAndSaveImages(files) {
  const saved = [];
  try {
    for (const file of files) {
      const type = await fileTypeFromBuffer(file.buffer);
      if (!type || !ALLOWED_TYPES[type.mime]) {
        throw new Error('One of the files is not a valid image.');
      }
      const filename = crypto.randomBytes(8).toString('hex') + ALLOWED_TYPES[type.mime];
      fs.writeFileSync(path.join(UPLOAD_DIR, filename), file.buffer);
      saved.push(filename);
    }
    return saved;
  } catch (err) {
    // Roll back anything already written before the failure
    removeFiles(saved);
    throw err;
  }
}

app.set('view engine', 'ejs');
app.locals.shopName = SHOP_NAME;
app.locals.whatsappNumber = WHATSAPP_NUMBER;
app.locals.telegramUsername = TELEGRAM_USERNAME;
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use('/uploads', express.static(UPLOAD_DIR));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 8 * 60 * 60 * 1000 },
}));

// ---------- CSRF protection ----------
const { generateToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => CSRF_SECRET,
  cookieName: process.env.NODE_ENV === 'production' ? '__Host-csrf' : 'csrf',
  cookieOptions: {
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
  },
  getTokenFromRequest: (req) => req.body && req.body._csrf,
});

app.use('/admin', (req, res, next) => {
  try {
    res.locals.csrfToken = generateToken(req, res);
  } catch (err) {
    res.locals.csrfToken = generateToken(req, res, true);
  }
  next();
});

function requireOwner(req, res, next) {
  if (req.session.owner) return next();
  res.redirect('/admin/login');
}

// Deletes picture files from the uploads folder
function removeFiles(names) {
  names.forEach((n) => fs.unlink(path.join(UPLOAD_DIR, n), () => {}));
}

// Every cloth's pictures, with its first picture as the "cover"
const COVER_SQL = `
  SELECT p.*,
    (SELECT filename FROM product_images WHERE product_id = p.id ORDER BY position, id LIMIT 1) AS image
  FROM products p`;

// ---------- customers: no login needed ----------
app.get('/', (req, res) => {
  const products = db.prepare(COVER_SQL + ' ORDER BY p.id DESC').all();
  res.render('home', { products, shopName: SHOP_NAME });
});

app.get('/product/:id', (req, res) => {
  const item = db.prepare(COVER_SQL + ' WHERE p.id = ?').get(Number(req.params.id));
  if (!item) return res.status(404).send('Cloth not found');

  const images = db.prepare('SELECT filename FROM product_images WHERE product_id = ? ORDER BY position, id').all(item.id);

  const code = app.locals.codeOf(item.id);
  const link = req.protocol + '://' + req.get('host') + '/product/' + item.id;
  const message = 'Hello, I would like to order: ' + item.name +
    ' (Code: ' + code + ', ' + item.price + ' ETB). ' + link;

  res.render('product', {
    item,
    images,
    shopName: SHOP_NAME,
    whatsappLink: 'https://wa.me/' + WHATSAPP_NUMBER + '?text=' + encodeURIComponent(message),
    telegramLink: 'https://t.me/' + TELEGRAM_USERNAME,
  });
});

// ---------- login and logout ----------
app.get('/admin/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/admin/login', async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const key = `${req.ip}:${username}`;

  if (isLocked(key)) {
    return res.status(429).render('login', {
      error: 'Too many attempts. Try again in a few minutes.',
    });
  }

  const owner = db.prepare('SELECT * FROM owner WHERE id = 1').get();
  const ok = owner
    && username === String(owner.username).toLowerCase()
    && await bcrypt.compare(password, owner.password_hash);

  if (!ok) {
    recordFailure(key);
    return res.status(401).render('login', { error: 'Wrong username or password.' });
  }

  clearAttempts(key);

  req.session.regenerate((err) => {
    if (err) return res.status(500).render('login', { error: 'Something went wrong, try again.' });
    req.session.owner = true;
    res.redirect('/admin');
  });
});

app.post('/admin/logout', requireOwner, doubleCsrfProtection, (req, res) => {
  req.session.destroy(() => res.redirect('/admin/login'));
});

// ---------- owner: list ----------
app.get('/admin', requireOwner, (req, res) => {
  const products = db.prepare(COVER_SQL + ' ORDER BY p.id DESC').all();
  res.render('admin', { products, deletedName: req.query.deleted || null });
});

// ---------- owner: add cloth ----------
app.get('/admin/new', requireOwner, (req, res) => {
  res.render('form', {
    heading: 'Add cloth',
    action: '/admin/new',
    error: null,
    item: { name: '', price: '', description: '' },
    images: [],
  });
});

// multer must run before doubleCsrfProtection here: this form is
// multipart/form-data (because of the file input), and express.urlencoded()
// does not parse multipart bodies — only multer does. If CSRF ran first,
// req.body would still be undefined and the _csrf check would crash.
app.post('/admin/new', requireOwner, upload.array('images', 8), doubleCsrfProtection, async (req, res) => {
  const files = req.files || [];
  const name = String(req.body.name || '').trim();
  const description = String(req.body.description || '').trim();
  const price = Number(req.body.price);

  if (!name || !(price > 0)) {
    return res.status(400).render('form', {
      heading: 'Add cloth',
      action: '/admin/new',
      error: 'Enter a name and a price greater than 0. Please choose the pictures again.',
      item: { name, price: req.body.price, description },
      images: [],
    });
  }

  let filenames;
  try {
    filenames = await validateAndSaveImages(files);
  } catch (err) {
    return res.status(400).render('form', {
      heading: 'Add cloth',
      action: '/admin/new',
      error: 'One of the files was not a valid image. Please choose the pictures again.',
      item: { name, price: req.body.price, description },
      images: [],
    });
  }

  const result = db.prepare('INSERT INTO products (name, description, price) VALUES (?, ?, ?)')
    .run(name, description, price);
  const id = Number(result.lastInsertRowid);

  filenames.forEach((filename, i) => {
    db.prepare('INSERT INTO product_images (product_id, filename, position) VALUES (?, ?, ?)')
      .run(id, filename, i);
  });

  res.redirect('/admin');
});

// ---------- owner: edit cloth ----------
app.get('/admin/edit/:id', requireOwner, (req, res) => {
  const id = Number(req.params.id);
  const item = db.prepare('SELECT * FROM products WHERE id = ?').get(id);
  if (!item) return res.redirect('/admin');

  const images = db.prepare('SELECT * FROM product_images WHERE product_id = ? ORDER BY position, id').all(id);
  res.render('form', { heading: 'Edit cloth', action: '/admin/edit/' + id, error: null, item, images });
});

app.post('/admin/edit/:id', requireOwner, upload.array('images', 8), doubleCsrfProtection, async (req, res) => {
  const id = Number(req.params.id);
  const files = req.files || [];
  const old = db.prepare('SELECT * FROM products WHERE id = ?').get(id);
  if (!old) {
    return res.redirect('/admin');
  }

  const images = db.prepare('SELECT * FROM product_images WHERE product_id = ? ORDER BY position, id').all(id);
  const name = String(req.body.name || '').trim();
  const description = String(req.body.description || '').trim();
  const price = Number(req.body.price);
  const remove = [].concat(req.body.remove || []).map(Number);
  const keepCount = images.filter((im) => !remove.includes(im.id)).length;

  let error = null;
  if (!name || !(price > 0)) error = 'Enter a name and a price greater than 0.';
  else if (keepCount + files.length > 8) error = 'A cloth can have at most 8 pictures.';

  if (error) {
    return res.status(400).render('form', {
      heading: 'Edit cloth',
      action: '/admin/edit/' + id,
      error,
      item: { id, name, price: req.body.price, description },
      images,
    });
  }

  let filenames;
  try {
    filenames = await validateAndSaveImages(files);
  } catch (err) {
    return res.status(400).render('form', {
      heading: 'Edit cloth',
      action: '/admin/edit/' + id,
      error: 'One of the files was not a valid image. Please choose the pictures again.',
      item: { id, name, price: req.body.price, description },
      images,
    });
  }

  db.prepare('UPDATE products SET name = ?, description = ?, price = ? WHERE id = ?')
    .run(name, description, price, id);

  const removed = images.filter((im) => remove.includes(im.id));
  removed.forEach((im) => db.prepare('DELETE FROM product_images WHERE id = ?').run(im.id));
  removeFiles(removed.map((im) => im.filename));

  let position = images.length ? Math.max(...images.map((im) => im.position)) + 1 : 0;
  filenames.forEach((filename) => {
    db.prepare('INSERT INTO product_images (product_id, filename, position) VALUES (?, ?, ?)')
      .run(id, filename, position);
    position++;
  });

  res.redirect('/admin');
});

// ---------- owner: delete cloth ----------
app.post('/admin/delete/:id', requireOwner, doubleCsrfProtection, (req, res) => {
  const id = Number(req.params.id);
  const product = db.prepare('SELECT name FROM products WHERE id = ?').get(id);
  const images = db.prepare('SELECT filename FROM product_images WHERE product_id = ?').all(id);
  db.prepare('DELETE FROM product_images WHERE product_id = ?').run(id);
  db.prepare('DELETE FROM products WHERE id = ?').run(id);
  removeFiles(images.map((im) => im.filename));
  res.redirect('/admin?deleted=' + encodeURIComponent(product ? product.name : 'Item'));
});

// ---------- owner: change username / password ----------
app.get('/admin/account', requireOwner, (req, res) => {
  const owner = db.prepare('SELECT username FROM owner WHERE id = 1').get();
  res.render('account', { error: null, message: null, username: owner.username });
});

app.post('/admin/account', requireOwner, doubleCsrfProtection, async (req, res) => {
  const owner = db.prepare('SELECT * FROM owner WHERE id = 1').get();
  const current = String(req.body.current || '');
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const again = String(req.body.again || '');

  const fail = (error) => res.status(400).render('account', { error, message: null, username });

  if (!(await bcrypt.compare(current, owner.password_hash))) return fail('Your current password is wrong.');
  if (!username) return fail('Enter a username.');

  let hash = owner.password_hash;
  if (password) {
    if (password.length < 8) return fail('The new password must be at least 8 characters.');
    if (password !== again) return fail('The new passwords do not match.');
    hash = bcrypt.hashSync(password, 12);
  }

  db.prepare('UPDATE owner SET username = ?, password_hash = ? WHERE id = 1').run(username, hash);
  res.render('account', { error: null, message: 'Saved. Use your new details the next time you log in.', username });
});

// ---------- error handler: must be registered last, before listen() ----------
// Catches CSRF failures (and anything else passed to next(err)) so visitors
// see a normal page instead of a raw stack trace, and so a bad request can
// never crash the whole server process.
app.use((err, req, res, next) => {
  if (err && err.code === 'EBADCSRFTOKEN') {
    console.warn('CSRF check failed for', req.method, req.originalUrl);
    return res.status(403).send(
      'Your session expired or the form was out of date. Please go back, refresh the page, and try again.'
    );
  }
  console.error(err);
  res.status(500).send('Something went wrong. Please try again.');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Running on port ' + PORT));