/***** HELPERS *****/
const $ = s => document.querySelector(s);

/***** VALIDAR TELÉFONO *****/
function validarTelefono(telefono) {
  // Validar que sea un número de teléfono válido (8 dígitos mínimo)
  const regex = /^[0-9]{8,}$/;
  return regex.test(telefono.replace(/\D/g, ''));
}

/***** VALIDAR CONTRASEÑA *****/
function validarContrasena(password) {
  // Mínimo 6 caracteres
  return password.length >= 6;
}

/***** AGREGAR VALIDACIÓN AL FORMULARIO DE LOGIN *****/
document.addEventListener('DOMContentLoaded', () => {
  const formulario = document.querySelector('form');
  
  if (!formulario) return;
  
  formulario.addEventListener('submit', e => {
    const telefono = $('input[name="telefono"]')?.value || '';
    const password = $('input[name="password"]')?.value || '';
    
    // Validaciones básicas
    if (!telefono || !telefono.trim()) {
      e.preventDefault();
      alert('El teléfono es requerido');
      return false;
    }
    
    if (!validarTelefono(telefono)) {
      e.preventDefault();
      alert('El teléfono debe tener al menos 8 dígitos');
      return false;
    }
    
    if (!password) {
      e.preventDefault();
      alert('La contraseña es requerida');
      return false;
    }
    
    if (!validarContrasena(password)) {
      e.preventDefault();
      alert('La contraseña debe tener al menos 6 caracteres');
      return false;
    }
  });
  
  // Efectos visuales en los campos
  const inputs = document.querySelectorAll('input[type="text"], input[type="password"], input[type="tel"]');
  
  inputs.forEach(input => {
    input.addEventListener('focus', function() {
      this.style.boxShadow = '0 0 8px rgba(0, 150, 255, 0.5)';
    });
    
    input.addEventListener('blur', function() {
      this.style.boxShadow = 'none';
    });
  });
  
  // Efectos visuales en el botón
  const submitBtn = formulario.querySelector('button[type="submit"]');
  if (submitBtn) {
    submitBtn.addEventListener('click', function() {
      this.style.transform = 'scale(0.98)';
      setTimeout(() => {
        this.style.transform = 'scale(1)';
      }, 100);
    });
    
    submitBtn.addEventListener('mouseover', function() {
      this.style.cursor = 'pointer';
      this.style.opacity = '0.9';
    });
    
    submitBtn.addEventListener('mouseout', function() {
      this.style.opacity = '1';
    });
  }
});