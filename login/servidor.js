require('dotenv').config();

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,                 
    maxAge: 1000 * 60 * 60 * 24     
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

// Passo 1: pedir o link de redefinição
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
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

      // apaga pedidos antigos e cria o novo (válido por 1 hora)
      await pool.query('DELETE FROM redefinicao_senha WHERE usuario_id = $1', [usuarioId]);
      await pool.query(
        `INSERT INTO redefinicao_senha (usuario_id, token_hash, expira_em)
         VALUES ($1, $2, NOW() + INTERVAL '1 hour')`,
        [usuarioId, tokenHash]
      );

      const link = `http://localhost:3000/redefinir-senha.html?token=${token}`;
      console.log('Link de redefinição:', link); // depois trocamos por envio de e-mail
    }

    // resposta igual exista o e-mail ou não
    res.redirect('/esqueci-senha.html?enviado=1');
  } catch (erro) {
    console.error(erro);
    res.status(500).send('Erro ao processar o pedido.');
  }
});

// Passo 2: salvar a nova senha
app.post('/redefinir-senha', async (req, res) => {
  const { token, senha, confirmar } = req.body;

  if (!token || senha !== confirmar || senha.length < 8) {
    return res.status(400).send('Dados inválidos. A senha precisa ter 8 caracteres e ser igual nos dois campos.');
  }

  try {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    const resultado = await pool.query(
      `SELECT id, usuario_id FROM redefinicao_senha
       WHERE token_hash = $1 AND usado = FALSE AND expira_em > NOW()`,
      [tokenHash]
    );

    if (resultado.rows.length === 0) {
      return res.status(400).send('Link inválido ou expirado. Peça um novo.');
    }

    const { id, usuario_id } = resultado.rows[0];
    const novaSenhaHash = await bcrypt.hash(senha, 10);

    await pool.query('UPDATE usuarios SET senha_hash = $1 WHERE id = $2', [novaSenhaHash, usuario_id]);
    await pool.query('UPDATE redefinicao_senha SET usado = TRUE WHERE id = $1', [id]);

    res.redirect('/login.html');
  } catch (erro) {
    console.error(erro);
    res.status(500).send('Erro ao redefinir a senha.');
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