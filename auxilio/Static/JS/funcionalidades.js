/***** HELPERS *****/
const $ = s => document.querySelector(s);
const AV_KEY = 'avisosTepo';
const HR_KEY = 'horariosTepo';

/***** DETECTAR PÁGINA ACTUAL *****/
function getPaginaActual() {
  const url = window.location.pathname;
  if (url.includes('/mg')) return 'mg';
  if (url.includes('/pdd')) return 'pdd';
  if (url.includes('/roca')) return 'roca';
  return null;
}

/***** VALIDAR ACCESO - REDIRIGIR SI NO COINCIDE *****/
function validarAccesoPagina() {
  const paginaActual = getPaginaActual();
  if (!paginaActual) return;
  
  // En una aplicación real, traerías esto del backend o de la sesión
  // Por ahora, esto es una validación básica del frontend
  const servicioGuardado = localStorage.getItem('servicio_transporte');
  
  if (servicioGuardado && servicioGuardado !== paginaActual) {
    console.warn(`Acceso no autorizado. Tu servicio es: ${servicioGuardado}`);
    window.location.href = `/${servicioGuardado}`;
  }
}

/***** RENDER AVISOS *****/
function nAviso({texto, img64, fecha}) {
  const art = document.createElement('article');
  art.className = 'post';
  art.innerHTML = `<p>${texto}</p>${img64 ? `<img src="${img64}">` : ''}
    <span class="time">${new Date(fecha).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'})}</span>`;
  return art;
}

function loadAvisos() {
  const board = $('#board');
  const overlayBody = $('#overlay-body');
  
  if (!board) return;
  
  const avisos = JSON.parse(localStorage.getItem(AV_KEY) || '[]');
  board.innerHTML = '';
  
  if (overlayBody) overlayBody.innerHTML = '';
  
  if (!avisos.length) {
    board.innerHTML = '<p class="empty">No hay avisos por el momento</p>';
    return;
  }
  
  avisos.forEach(a => {
    board.append(nAviso(a));
    if (overlayBody) overlayBody.append(nAviso(a));
  });
}

/***** RENDER HORARIOS *****/
function nHorario({parada, hora}) {
  const div = document.createElement('div');
  div.className = 'row';
  div.innerHTML = `<span>${parada}</span><span>${hora}</span>`;
  return div;
}

function loadHorarios() {
  const sched = $('#sched-board');
  
  if (!sched) return;
  
  const h = JSON.parse(localStorage.getItem(HR_KEY) || '[]');
  sched.innerHTML = '';
  
  if (!h.length) {
    sched.innerHTML = '<p class="empty">No hay horarios publicados</p>';
    return;
  }
  
  h.forEach(r => sched.append(nHorario(r)));
}

/***** EVENT LISTENERS *****/
document.addEventListener('DOMContentLoaded', () => {
  const board = $('#board');
  const overlay = $('#overlay');
  const closeOverlay = $('#close-overlay');
  
  // Abrir overlay al hacer click en avisos
  if (board) {
    board.addEventListener('click', () => {
      if (overlay) overlay.classList.remove('hidden');
    });
  }
  
  // Cerrar overlay
  if (closeOverlay) {
    closeOverlay.addEventListener('click', () => {
      if (overlay) overlay.classList.add('hidden');
    });
  }
  
  // Validar acceso a la página
  validarAccesoPagina();
  
  // Cargar contenido
  loadAvisos();
  loadHorarios();
});