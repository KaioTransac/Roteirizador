const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const xlsx = require('xlsx');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

const SECRET_KEY = 'sua_chave_secreta_aqui';
const db = new sqlite3.Database('./database.db');

// Criar tabelas
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      isAdmin BOOLEAN DEFAULT FALSE
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS caminhoes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      placa TEXT UNIQUE NOT NULL,
      capacidade REAL NOT NULL,
      tem_bomba BOOLEAN DEFAULT FALSE,
      proxima_manutencao TEXT,
      observacoes TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS clientes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome TEXT NOT NULL,
      restricao_tamanho TEXT,
      grade_horaria TEXT,
      cidade TEXT NOT NULL,
      longitude REAL,
      latitude REAL,
      necessita_bomba BOOLEAN DEFAULT FALSE,
      contato TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS pedidos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      cliente_id INTEGER NOT NULL,
      combustivel TEXT NOT NULL,
      quantidade REAL NOT NULL,
      status TEXT DEFAULT 'pendente',
      FOREIGN KEY (cliente_id) REFERENCES clientes (id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS rotas (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      caminhao_id INTEGER NOT NULL,
      pedidos_ids TEXT NOT NULL, -- JSON array de IDs de pedidos
      data_entrega TEXT NOT NULL,
      status TEXT DEFAULT 'sugerido',
      FOREIGN KEY (caminhao_id) REFERENCES caminhoes (id)
    )
  `);
});

// Middleware de autenticação
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

function isAdmin(req, res, next) {
  if (!req.user.isAdmin) return res.sendStatus(403);
  next();
}

// Rotas de autenticação
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!user) return res.status(401).json({ error: 'Usuário não encontrado' });
    
    bcrypt.compare(password, user.password, (err, result) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!result) return res.status(401).json({ error: 'Senha incorreta' });
      
      const token = jwt.sign(
        { id: user.id, username: user.username, isAdmin: user.isAdmin },
        SECRET_KEY,
        { expiresIn: '24h' }
      );
      
      res.json({ token, isAdmin: user.isAdmin });
    });
  });
});

// Rotas de administração
app.post('/api/users', authenticateToken, isAdmin, (req, res) => {
  const { username, password, isAdmin } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);
  
  db.run(
    'INSERT INTO users (username, password, isAdmin) VALUES (?, ?, ?)',
    [username, hashedPassword, isAdmin],
    function(err) {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ id: this.lastID });
    }
  );
});

app.get('/api/users', authenticateToken, isAdmin, (req, res) => {
  db.all('SELECT id, username, isAdmin FROM users', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Rotas para caminhões
app.post('/api/caminhoes', authenticateToken, (req, res) => {
  const { placa, capacidade, tem_bomba, proxima_manutencao, observacoes } = req.body;
  
  db.run(
    'INSERT INTO caminhoes (placa, capacidade, tem_bomba, proxima_manutencao, observacoes) VALUES (?, ?, ?, ?, ?)',
    [placa, capacidade, tem_bomba, proxima_manutencao, observacoes],
    function(err) {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ id: this.lastID });
    }
  );
});

app.get('/api/caminhoes', authenticateToken, (req, res) => {
  db.all('SELECT * FROM caminhoes', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Rotas para clientes
const upload = multer({ dest: 'uploads/' });
app.post('/api/clientes', authenticateToken, (req, res) => {
  const { nome, restricao_tamanho, grade_horaria, cidade, longitude, latitude, necessita_bomba, contato } = req.body;
  
  db.run(
    'INSERT INTO clientes (nome, restricao_tamanho, grade_horaria, cidade, longitude, latitude, necessita_bomba, contato) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [nome, restricao_tamanho, grade_horaria, cidade, longitude, latitude, necessita_bomba, contato],
    function(err) {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ id: this.lastID });
    }
  );
});

app.post('/api/clientes/upload', authenticateToken, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Nenhum arquivo enviado' });
  
  try {
    const workbook = xlsx.readFile(req.file.path);
    const sheet = workbook.Sheets[workbook.SheetNames[0]];
    const data = xlsx.utils.sheet_to_json(sheet);
    
    const stmt = db.prepare(
      'INSERT INTO clientes (nome, restricao_tamanho, grade_horaria, cidade, longitude, latitude, necessita_bomba, contato) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    );
    
    data.forEach(row => {
      stmt.run(
        row.nome,
        row.restricao_tamanho,
        row.grade_horaria,
        row.cidade,
        row.longitude,
        row.latitude,
        row.necessita_bomba || false,
        row.contato
      );
    });
    
    stmt.finalize();
    res.json({ message: `${data.length} clientes importados com sucesso` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/clientes', authenticateToken, (req, res) => {
  db.all('SELECT * FROM clientes', [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Rotas para pedidos
app.post('/api/pedidos', authenticateToken, (req, res) => {
  const { cliente_id, combustivel, quantidade } = req.body;
  
  db.run(
    'INSERT INTO pedidos (cliente_id, combustivel, quantidade, status) VALUES (?, ?, ?, ?)',
    [cliente_id, combustivel, quantidade, 'pendente'],
    function(err) {
      if (err) return res.status(400).json({ error: err.message });
      res.json({ id: this.lastID });
    }
  );
});

app.get('/api/pedidos', authenticateToken, (req, res) => {
  const { status } = req.query;
  let query = 'SELECT p.*, c.nome as cliente_nome FROM pedidos p JOIN clientes c ON p.cliente_id = c.id';
  
  if (status) {
    query += ` WHERE p.status = '${status}'`;
  }
  
  db.all(query, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// Rotas para roteirização
app.post('/api/rotas/sugerir', authenticateToken, (req, res) => {
  // Algoritmo simplificado de roteirização
  // Na prática, você pode querer usar uma biblioteca como VRP (Vehicle Routing Problem)
  
  db.serialize(() => {
    db.all('SELECT * FROM pedidos WHERE status = "pendente"', [], (err, pedidos) => {
      if (err) return res.status(500).json({ error: err.message });
      
      db.all('SELECT * FROM caminhoes', [], (err, caminhoes) => {
        if (err) return res.status(500).json({ error: err.message });
        
        db.all('SELECT * FROM clientes', [], (err, clientes) => {
          if (err) return res.status(500).json({ error: err.message });
          
          // Mapear pedidos para incluir informações do cliente
          const pedidosCompleto = pedidos.map(pedido => {
            const cliente = clientes.find(c => c.id === pedido.cliente_id);
            return { ...pedido, cliente };
          });
          
          // Agrupar pedidos por cidade
          const pedidosPorCidade = {};
          pedidosCompleto.forEach(pedido => {
            if (!pedidosPorCidade[pedido.cliente.cidade]) {
              pedidosPorCidade[pedido.cliente.cidade] = [];
            }
            pedidosPorCidade[pedido.cliente.cidade].push(pedido);
          });
          
          // Alocar caminhões
          const rotasSugeridas = [];
          const hoje = new Date().toISOString().split('T')[0];
          
          caminhoes.forEach(caminhao => {
            const capacidadeRestante = caminhao.capacidade;
            const pedidosAlocados = [];
            let capacidadeUsada = 0;
            
            // Verificar pedidos que precisam de bomba, se o caminhão tiver
            if (caminhao.tem_bomba) {
              for (const cidade in pedidosPorCidade) {
                const pedidosCidade = pedidosPorCidade[cidade];
                for (const pedido of pedidosCidade) {
                  if (pedido.cliente.necessita_bomba && 
                      capacidadeUsada + pedido.quantidade <= caminhao.capacidade) {
                    pedidosAlocados.push(pedido.id);
                    capacidadeUsada += pedido.quantidade;
                  }
                }
              }
            }
            
            // Alocar outros pedidos
            for (const cidade in pedidosPorCidade) {
              const pedidosCidade = pedidosPorCidade[cidade];
              for (const pedido of pedidosCidade) {
                if (!pedidosAlocados.includes(pedido.id) && 
                    capacidadeUsada + pedido.quantidade <= caminhao.capacidade) {
                  pedidosAlocados.push(pedido.id);
                  capacidadeUsada += pedido.quantidade;
                }
              }
            }
            
            if (pedidosAlocados.length > 0) {
              rotasSugeridas.push({
                caminhao_id: caminhao.id,
                pedidos_ids: JSON.stringify(pedidosAlocados),
                data_entrega: hoje,
                status: 'sugerido'
              });
            }
          });
          
          // Salvar rotas sugeridas no banco de dados
          const stmt = db.prepare(
            'INSERT INTO rotas (caminhao_id, pedidos_ids, data_entrega, status) VALUES (?, ?, ?, ?)'
          );
          
          rotasSugeridas.forEach(rota => {
            stmt.run(
              rota.caminhao_id,
              rota.pedidos_ids,
              rota.data_entrega,
              rota.status
            );
            
            // Atualizar status dos pedidos
            const pedidosIds = JSON.parse(rota.pedidos_ids);
            pedidosIds.forEach(pedidoId => {
              db.run(
                'UPDATE pedidos SET status = "alocado" WHERE id = ?',
                [pedidoId]
              );
            });
          });
          
          stmt.finalize();
          res.json({ message: `${rotasSugeridas.length} rotas sugeridas criadas` });
        });
      });
    });
  });
});

app.get('/api/rotas', authenticateToken, (req, res) => {
  const { status } = req.query;
  let query = 'SELECT r.*, c.placa FROM rotas r JOIN caminhoes c ON r.caminhao_id = c.id';
  
  if (status) {
    query += ` WHERE r.status = '${status}'`;
  }
  
  db.all(query, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    
    // Para cada rota, obter detalhes dos pedidos
    const rotasComPedidos = rows.map(rota => {
      const pedidosIds = JSON.parse(rota.pedidos_ids);
      return new Promise((resolve, reject) => {
        db.all(
          'SELECT p.*, cli.nome as cliente_nome FROM pedidos p JOIN clientes cli ON p.cliente_id = cli.id WHERE p.id IN (' + pedidosIds.map(() => '?').join(',') + ')',
          pedidosIds,
          (err, pedidos) => {
            if (err) return reject(err);
            resolve({ ...rota, pedidos });
          }
        );
      });
    });
    
    Promise.all(rotasComPedidos)
      .then(rotas => res.json(rotas))
      .catch(err => res.status(500).json({ error: err.message }));
  });
});

app.put('/api/rotas/:id/confirmar', authenticateToken, (req, res) => {
  const { id } = req.params;
  
  db.run(
    'UPDATE rotas SET status = "confirmado" WHERE id = ?',
    [id],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: 'Rota confirmada' });
    }
  );
});

app.put('/api/rotas/:id/rejeitar', authenticateToken, (req, res) => {
  const { id } = req.params;
  
  db.get('SELECT pedidos_ids FROM rotas WHERE id = ?', [id], (err, rota) => {
    if (err) return res.status(500).json({ error: err.message });
    
    const pedidosIds = JSON.parse(rota.pedidos_ids);
    const stmt = db.prepare('UPDATE pedidos SET status = "pendente" WHERE id = ?');
    
    pedidosIds.forEach(pedidoId => {
      stmt.run(pedidoId);
    });
    
    stmt.finalize();
    
    db.run('DELETE FROM rotas WHERE id = ?', [id], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: 'Rota rejeitada e pedidos retornados para pendentes' });
    });
  });
});

// Inicializar com um admin padrão (apenas na primeira execução)
db.get('SELECT COUNT(*) as count FROM users', [], (err, row) => {
  if (err) return console.error(err.message);
  if (row.count === 0) {
    const hashedPassword = bcrypt.hashSync('admin123', 10);
    db.run(
      'INSERT INTO users (username, password, isAdmin) VALUES (?, ?, ?)',
      ['admin', hashedPassword, true]
    );
    console.log('Usuário admin criado: admin / admin123');
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});