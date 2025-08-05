const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Arquivo onde as keys e dados serão salvos
const dbPath = path.join(__dirname, 'db.json');

// Inicializa o arquivo db.json se não existir
if (!fs.existsSync(dbPath)) {
  fs.writeFileSync(dbPath, JSON.stringify({ keys: {} }, null, 2));
}

// Função para ler dados do arquivo
function readDB() {
  const data = fs.readFileSync(dbPath, 'utf8');
  return JSON.parse(data);
}

// Função para salvar dados no arquivo
function saveDB(data) {
  fs.writeFileSync(dbPath, JSON.stringify(data, null, 2));
}

// Gera uma API Key começando com 4K1R4 + 10 chars aleatórios (A-Z0-9)
function generateApiKey() {
  const prefix = '4K1R4';
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let key = prefix;
  for (let i = 0; i < 10; i++) {
    key += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return key;
}

// Middleware para validar API Key e controlar limite de requests
function apiKeyMiddleware(req, res, next) {
  const key = req.query.key || req.headers['x-api-key'];
  if (!key) {
    return res.status(401).json({ error: 'API Key é obrigatória.' });
  }

  const db = readDB();
  const user = db.keys[key];
  if (!user) {
    return res.status(403).json({ error: 'API Key inválida.' });
  }

  if (user.requestsLeft <= 0) {
    return res.status(429).json({ error: 'Limite de requests atingido para esta API Key.' });
  }

  // Decrementa o contador de requests
  user.requestsLeft -= 1;
  saveDB(db);

  // Anexa info do usuário na requisição
  req.apiUser = user;
  next();
}

// Rota para gerar nova API Key
app.post('/generate-key', (req, res) => {
  const db = readDB();

  // Gera nova key que não exista no db
  let newKey;
  do {
    newKey = generateApiKey();
  } while (db.keys[newKey]);

  // Cria o usuário com requests iniciais (ex: 100 por dia)
  db.keys[newKey] = {
    createdAt: new Date().toISOString(),
    requestsLeft: 100,
  };

  saveDB(db);

  res.json({ apiKey: newKey, requestsLeft: 100 });
});

// Rota para resetar a key (trocar por nova)
app.post('/reset-key', (req, res) => {
  const oldKey = req.body.oldKey;
  if (!oldKey) {
    return res.status(400).json({ error: 'Informe a chave antiga no corpo da requisição (JSON).' });
  }
  const db = readDB();

  if (!db.keys[oldKey]) {
    return res.status(404).json({ error: 'API Key antiga não encontrada.' });
  }

  // Apaga a key antiga
  delete db.keys[oldKey];

  // Gera nova key
  let newKey;
  do {
    newKey = generateApiKey();
  } while (db.keys[newKey]);

  db.keys[newKey] = {
    createdAt: new Date().toISOString(),
    requestsLeft: 100,
  };

  saveDB(db);

  res.json({ apiKey: newKey, requestsLeft: 100 });
});

// Rota para verificar requests restantes (via query key ou header)
app.get('/requests-left', (req, res) => {
  const key = req.query.key || req.headers['x-api-key'];
  if (!key) return res.status(400).json({ error: 'API Key é obrigatória.' });

  const db = readDB();
  const user = db.keys[key];
  if (!user) return res.status(404).json({ error: 'API Key inválida.' });

  res.json({ requestsLeft: user.requestsLeft });
});

// Rota protegida que retorna dados (exemplo)
app.get('/data', apiKeyMiddleware, (req, res) => {
  // Retorna dados para o usuário autenticado
  res.json({
    message: 'Aqui estão os dados da API protegida!',
    requestsLeft: req.apiUser.requestsLeft,
    apiKeyCreatedAt: req.apiUser.createdAt,
  });
});

// Servir frontend estático (pasta public)
app.use(express.static(path.join(__dirname, 'public')));

app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});