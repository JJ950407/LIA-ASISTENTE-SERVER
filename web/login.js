const params = new URLSearchParams(window.location.search);
const error = params.get('error');
const errorEl = document.getElementById('login-error');

if (error && errorEl) {
  errorEl.textContent = 'Credenciales incorrectas.';
}
