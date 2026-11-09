const formulario = document.querySelector('form');

formulario.addEventListener('submit', (evento) => {
  const senha = document.getElementById('senha').value;
  const confirmar = document.getElementById('confirmar').value;

  if (senha !== confirmar) {
    evento.preventDefault();
    alert('As senhas não são iguais.');
  }
});