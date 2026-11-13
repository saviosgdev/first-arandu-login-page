require('dotenv').config();

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,                 // o JavaScript do navegador não lê o cookie
    maxAge: 1000 * 60 * 60 * 24     // 1 dia
  }
}));

function exigirLogin(req, res, next) {
  if (!req.session.usuario) {
    return res.redirect('/login.html');
  }
  next();
}

app.use(express.urlencoded({ extended: true }));

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

app.post('/cadastro', async (req, res) => {
  const { nome, email, senha, confirmar } = req.body;

  if (senha !== confirmar) {
    return res.status(400).send('As senhas não são iguais.');
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

    req.session.usuario = { id: usuario.id, nome: usuario.nome };
    res.redirect('/painel');
  } catch (erro) {
    console.error(erro);
    res.status(500).send('Erro ao fazer login.');
  }
});

app.get('/painel', exigirLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'privado', 'painel.html'));
});

app.get('/api/usuario', exigirLogin, (req, res) => {
  res.json({ nome: req.session.usuario.nome });
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login.html'));
});


app.listen(3000, () => console.log('Rodando em http://localhost:3000'));