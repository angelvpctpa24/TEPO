/***** HELPERS *****/
const $ = s => document.querySelector(s);

/***** DETECTAR TIPO DE REGISTRO *****/
function getTipoRegistro() {
  const url = window.location.pathname;
  if (url.includes('estudiante')) return 'estudiante';
  if (url.includes('padre')) return 'padre';
  if (url.includes('admin')) return 'admin';
  return null;
}

/***** OCULTAR CAMPO SERVICIO PARA ADMIN *****/
function ocultarServicioParaAdmin() {
  const tipo = getTipoRegistro();
  
  if (tipo === 'admin') {
    // Ocultar cualquier elemento relacionado con servicio
    const servicioField = $('#servicio-field') || $('input[name="servicio"]')?.closest('div');
    const servicioLabel = $('label[for="servicio"]');
    const servicioSelect = $('#servicio') || $('select[name="servicio"]');
    
    if (servicioField) servicioField.style.display = 'none';
    if (servicioLabel) servicioLabel.style.display = 'none';
    if (servicioSelect) servicioSelect.style.display = 'none';
  }
}

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

/***** VALIDAR SERVICIO (solo para estudiantes y padres) *****/
function validarServicio(servicio) {
  const servicios = ['mg', 'pdd', 'roca'];
  return servicios.includes(servicio);
}

/***** VALIDAR FORMULARIO *****/
function validarFormulario(formData) {
  const tipo = getTipoRegistro();
  const { telefono, password, servicio, nombre, apellido } = formData;
  
  // Validaciones básicas
  if (!nombre || !nombre.trim()) {
    alert('El nombre es requerido');
    return false;
  }
  
  if (!apellido || !apellido.trim()) {
    alert('El apellido es requerido');
    return false;
  }
  
  if (!telefono || !telefono.trim()) {
    alert('El teléfono es requerido');
    return false;
  }
  
  if (!validarTelefono(telefono)) {
    alert('El teléfono debe tener al menos 8 dígitos');
    return false;
  }
  
  if (!password) {
    alert('La contraseña es requerida');
    return false;
  }
  
  if (!validarContrasena(password)) {
    alert('La contraseña debe tener al menos 6 caracteres');
    return false;
  }
  
  // Validar servicio solo para estudiantes y padres
  if ((tipo === 'estudiante' || tipo === 'padre') && !servicio) {
    alert('Debes seleccionar un servicio de transporte');
    return false;
  }
  
  if ((tipo === 'estudiante' || tipo === 'padre') && !validarServicio(servicio)) {
    alert('Servicio de transporte no válido');
    return false;
  }
  
  return true;
}

/***** AGREGAR VALIDACIÓN AL FORMULARIO *****/
document.addEventListener('DOMContentLoaded', () => {
  const formulario = document.querySelector('form');
  
  if (!formulario) return;
  
  // Ocultar servicio para admin si es necesario
  ocultarServicioParaAdmin();
  
  // Agregar validación al envío
  formulario.addEventListener('submit', e => {
    const tipo = getTipoRegistro();
    
    const formData = {
      nombre: $('input[name="nombre"]')?.value || '',
      apellido: $('input[name="apellido"]')?.value || '',
      telefono: $('input[name="telefono"]')?.value || '',
      numero: $('input[name="numero"]')?.value || '',
      password: $('input[name="password"]')?.value || '',
      servicio: $('select[name="servicio"]')?.value || 
                $('input[name="servicio"]')?.value || ''
    };
    
    if (!validarFormulario(formData)) {
      e.preventDefault();
      return false;
    }
  });
  
  // Efectos visuales en los botones
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

/***** ANIMACIÓN DE CAMPOS *****/
document.addEventListener('DOMContentLoaded', () => {
  const inputs = document.querySelectorAll('input[type="text"], input[type="email"], input[type="password"], input[type="tel"], select');
  
  inputs.forEach(input => {
    input.addEventListener('focus', function() {
      this.style.boxShadow = '0 0 8px rgba(0, 150, 255, 0.5)';
    });
    
    input.addEventListener('blur', function() {
      this.style.boxShadow = 'none';
    });
  });
});