# Sistema de Cadastro com Node.js e PostgreSQL

## O que o projeto faz

Aplicação web simples de cadastro de usuários. A pessoa preenche o formulário de criação de conta, o servidor Node.js valida os dados, protege a senha com hash (bcrypt) e salva tudo em um banco PostgreSQL. O projeto também inclui a interface da tela de login, que será conectada ao banco nas próximas etapas.

## Tecnologias usadas

- **HTML e CSS:** interface das telas de login e cadastro, responsiva e com suporte ao modo escuro
- **JavaScript:** validação no navegador (confere se as senhas são iguais antes de enviar)
- **Node.js:** ambiente que executa o servidor
- **Express:** framework que cria as rotas e serve os arquivos do site
- **PostgreSQL:** banco de dados onde os usuários ficam salvos
- **pg:** biblioteca que conecta o Node.js ao PostgreSQL
- **bcrypt:** gera o hash das senhas, para que nunca sejam salvas em texto puro
- **dotenv:** carrega as credenciais do banco a partir de um arquivo `.env`

## Como rodar

### 1. Pré-requisitos

- [Node.js](https://nodejs.org) (versão 18 ou mais recente)
- [PostgreSQL](https://www.postgresql.org/download/) instalado e rodando
- Um cliente de banco, como o DBeaver (opcional)

### 2. Clone o repositório e instale as dependências

```bash
git clone https://github.com/SEU_USUARIO/SEU_REPOSITORIO.git
cd SEU_REPOSITORIO/login
npm install
```

### 3. Crie o banco, o usuário e a tabela

Entre no PostgreSQL como administrador (no Linux: `sudo -u postgres psql`) e rode:

```sql
CREATE USER loginarandu_user WITH PASSWORD 'escolha_uma_senha_forte';
CREATE DATABASE loginarandu OWNER loginarandu_user;
```

Depois conecte no banco `loginarandu` com o usuário `loginarandu_user` e crie a tabela:

```sql
CREATE TABLE usuarios (
  id SERIAL PRIMARY KEY,
  nome TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  senha_hash TEXT NOT NULL,
  criado_em TIMESTAMP DEFAULT NOW()
);
```

> **Linux:** se aparecer o erro `autenticação do tipo ident falhou`, edite o arquivo `pg_hba.conf` e troque `ident` por `scram-sha-256` nas linhas de `127.0.0.1/32` e `::1/128`. Depois rode `sudo systemctl reload postgresql`.

### 4. Configure o arquivo `.env`

Na pasta `login`, crie um arquivo chamado `.env` com os dados do seu banco:

```
DB_HOST=localhost
DB_PORT=5432
DB_USER=loginarandu_user
DB_PASSWORD=a_senha_que_voce_escolheu
DB_NAME=loginarandu
```

Sem aspas e sem espaços ao redor do `=`. Este arquivo **não deve ser enviado ao GitHub**, e já está listado no `.gitignore`.

### 5. Inicie o servidor

```bash
node servidor.js
```

Deve aparecer `Rodando em http://localhost:3000`.

### 6. Teste

Abra no navegador:

- Cadastro: <http://localhost:3000/criar-conta.html>
- Login (somente interface por enquanto): <http://localhost:3000/login.html>

Para conferir se o cadastro foi salvo, rode no banco:

```sql
SELECT id, nome, email, criado_em FROM usuarios;
```

## Estrutura do projeto

```
login/
├── public/
│   ├── criar-conta.html
│   ├── login.html
│   └── script.js
├── .env              (não vai para o GitHub)
├── .gitignore
├── package.json
└── servidor.js
```

## Segurança

- Senhas salvas apenas como hash (bcrypt), nunca em texto puro
- Consultas parametrizadas (`$1, $2, $3`), que protegem contra SQL injection
- Credenciais do banco em variáveis de ambiente, fora do código

## Próximos passos

- Implementar o login, conferindo e-mail e senha no banco
- Manter o usuário logado com sessões
- Criar uma página restrita a usuários autenticados
