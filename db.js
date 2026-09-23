const { DatabaseSync } = require('node:sqlite');
const fs = require('fs');
const path = require('path');

// On Render, this will be set to your permanent disk folder.
// On your computer, it's empty, so it just uses the current folder.
const DATA_DIR = process.env.DATA_DIR || '.';
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new DatabaseSync(path.join(DATA_DIR, 'shop.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    price REAL NOT NULL,
    image TEXT NOT NULL DEFAULT ''
  )
`);
db.exec(`
  CREATE TABLE IF NOT EXISTS owner (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL
  )
`);
db.exec(`
  CREATE TABLE IF NOT EXISTS product_images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    position INTEGER NOT NULL DEFAULT 0
  )
`);

db.exec(`
  INSERT INTO product_images (product_id, filename, position)
  SELECT id, image, 0 FROM products WHERE image != ''
`);
db.exec(`UPDATE products SET image = '' WHERE image != ''`);

module.exports = db;