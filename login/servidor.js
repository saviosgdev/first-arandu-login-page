require('dotenv').config();

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const EM_PRODUCAO = process.env.NODE_ENV === 'production';
const SENHA_MINIMA = 8;

if (!process.env.SESSION_SECRET) {
  console.error('Defina SESSION_SECRET no arquivo .env antes de iniciar.');
  process.exit(1);
}

const app = express();

if (EM_PRODUCAO) app.set('trust proxy', 1);

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: EM_PRODUCAO,
    maxAge: 1000 * 60 * 60 * 24,
  },
}));

function exigirLogin(req, res, next) {
  if (!req.session.usuario) {
    return res.redirect('/login.html');
  }
  next();
}

function gerarHashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}


app.get('/', (req, res) => {
  res.redirect('/login.html');
});


app.post('/cadastro', async (req, res) => {
  const { nome, email, senha, confirmar } = req.body;

  if (!nome || !email || !senha) {
    return res.status(400).send('Preencha todos os campos.');
  }
  if (senha !== confirmar) {
    return res.status(400).send('As senhas não são iguais.');
  }
  if (senha.length < SENHA_MINIMA) {
    return res.status(400).send(`A senha precisa ter pelo menos ${SENHA_MINIMA} caracteres.`);
  }

  try {
    const senhaHash = await bcrypt.hash(senha, 10);

    await pool.query(
      'INSERT INTO usuarios (nome, email, senha_hash) VALUES ($1, $2, $3)',
      [nome, email, senhaHash]
    );

    res.redirect('/login.html');
  } catch (erro) {
    if (erro.code === '23505') {
      return res.status(400).send('Este e-mail já está cadastrado.');
    }
    console.error(erro);
    res.status(500).send('Erro ao criar a conta.');
  }
});

app.post('/login', async (req, res) => {
  const { email, senha } = req.body;

  if (!email || !senha) {
    return res.status(400).send('Informe e-mail e senha.');
  }

  try {
    const resultado = await pool.query(
      'SELECT id, nome, senha_hash FROM usuarios WHERE email = $1',
      [email]
    );
    const usuario = resultado.rows[0];

    const senhaConfere = usuario && await bcrypt.compare(senha, usuario.senha_hash);

    if (!senhaConfere) {
      return res.status(401).send('E-mail ou senha inválidos.');
    }

    // Gera uma sessão nova ao logar (evita session fixation)
    req.session.regenerate((err) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Erro ao fazer login.');
      }
      req.session.usuario = { id: usuario.id, nome: usuario.nome };
      res.redirect('/painel');
    });
  } catch (erro) {
    console.error(erro);
    res.status(500).send('Erro ao fazer login.');
  }
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login.html'));
});

app.post('/esqueci-senha', async (req, res) => {
  const { email } = req.body;

  try {
    const resultado = await pool.query(
      'SELECT id FROM usuarios WHERE email = $1',
      [email]
    );

    if (resultado.rows.length > 0) {
      const usuarioId = resultado.rows[0].id;
      const token = crypto.randomBytes(32).toString('hex');

      await pool.query('DELETE FROM redefinicao_senha WHERE usuario_id = $1', [usuarioId]);
      await pool.query(
        `INSERT INTO redefinicao_senha (usuario_id, token_hash, expira_em)
         VALUES ($1, $2, NOW() + INTERVAL '1 hour')`,
        [usuarioId, gerarHashToken(token)]
      );

      const link = `${BASE_URL}/redefinir-senha.html?token=${token}`;
      console.log('Link de redefinição:', link); 
    }

    
    res.redirect('/esqueci-senha.html?enviado=1');
  } catch (erro) {
    console.error(erro);
    res.status(500).send('Erro ao processar o pedido.');
  }
});

app.post('/redefinir-senha', async (req, res) => {
  const { token, senha, confirmar } = req.body;

  if (!token || !senha || senha !== confirmar || senha.length < SENHA_MINIMA) {
    return res.status(400).send(
      `Dados inválidos. A senha precisa ter ${SENHA_MINIMA} caracteres e ser igual nos dois campos.`
    );
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const resultado = await client.query(
      `UPDATE redefinicao_senha
       SET usado = TRUE
       WHERE token_hash = $1 AND usado = FALSE AND expira_em > NOW()
       RETURNING usuario_id`,
      [gerarHashToken(token)]
    );

    if (resultado.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(400).send('Link inválido ou expirado. Peça um novo.');
    }

    const novaSenhaHash = await bcrypt.hash(senha, 10);

    await client.query(
      'UPDATE usuarios SET senha_hash = $1 WHERE id = $2',
      [novaSenhaHash, resultado.rows[0].usuario_id]
    );

    await client.query('COMMIT');
    res.redirect('/login.html');
  } catch (erro) {
    await client.query('ROLLBACK').catch(() => {});
    console.error(erro);
    res.status(500).send('Erro ao redefinir a senha.');
  } finally {
    client.release();
  }
});


app.get('/painel', exigirLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'privado', 'painel.html'));
});

app.get('/api/usuario', exigirLogin, (req, res) => {
  res.json({ nome: req.session.usuario.nome });
});


app.listen(PORT, () => {
  console.log(`Rodando em ${BASE_URL}`);

  const esperados = [
    'public/login.html',
    'public/criar-conta.html',
    'public/esqueci-senha.html',
    'public/redefinir-senha.html',
    'public/script.js',
    'privado/painel.html',
  ];

  esperados.forEach((arquivo) => {
    if (!fs.existsSync(path.join(__dirname, arquivo))) {
      console.warn(`ATENÇÃO: arquivo não encontrado: ${arquivo}`);
    }
  });
});