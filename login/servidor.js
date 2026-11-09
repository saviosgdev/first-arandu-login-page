require('dotenv').config();

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

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

app.listen(3000, () => console.log('Rodando em http://localhost:3000'));