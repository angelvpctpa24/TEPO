/***** HELPERS *****/
const $ = s => document.querySelector(s);
const $$ = s => document.querySelectorAll(s);
const hide = sel => $(sel).classList.add('hidden');
const show = sel => $(sel).classList.remove('hidden');
const fileTo64 = f => new Promise((res, rej) => {
  const r = new FileReader();
  r.onload = () => res(r.result);
  r.onerror = rej;
  r.readAsDataURL(f);
});

const AV_KEY = 'avisosTepo';
const HR_KEY = 'horariosTepo';
const BOARD = $('#board');
const SCHED = $('#sched-board');

/***** NAVEGACIÓN ADMIN - SELECCIONAR SERVICIO *****/
$('#btn-mg')?.onclick = () => window.location.href = '/mg';
$('#btn-pdd')?.onclick = () => window.location.href = '/pdd';
$('#btn-roca')?.onclick = () => window.location.href = '/roca';

/***** RENDER AVISOS *****/
function nodeAviso({id, texto, img64, fecha}) {
  const art = document.createElement('article');
  art.className = 'post';
  art.dataset.id = id;
  art.innerHTML = `<p>${texto}</p>${img64 ? `<img src="${img64}">` : ''}
    <span class="time">${new Date(fecha).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'})}</span>`;
  return art;
}

function drawAvisos() {
  if (!BOARD) return;
  BOARD.innerHTML = '';
  const avisos = JSON.parse(localStorage.getItem(AV_KEY) || '[]');
  if (!avisos.length) {
    BOARD.innerHTML = '<p class="empty">No hay avisos por el momento</p>';
    return;
  }
  avisos.forEach(a => BOARD.append(nodeAviso(a)));
}

/***** RENDER HORARIOS *****/
function nodeHorario({parada, hora}) {
  const div = document.createElement('div');
  div.className = 'row';
  div.innerHTML = `<span>${parada}</span><span>${hora}</span>`;
  return div;
}

function drawHorarios() {
  if (!SCHED) return;
  SCHED.innerHTML = '';
  const h = JSON.parse(localStorage.getItem(HR_KEY) || '[]');
  if (!h.length) {
    SCHED.innerHTML = '<p class="empty">No hay horarios publicados</p>';
    return;
  }
  h.forEach(r => SCHED.append(nodeHorario(r)));
}

/***** AVISO: CREAR / BORRAR / LIMPIAR *****/
let deleteId = null;

$('#new-btn')?.onclick = () => {
  if ($('#form-new')) $('#form-new').reset();
  show('#modal-new');
};

$('#modal-new .close-btn')?.onclick = () => hide('#modal-new');

$('#form-new')?.onsubmit = async e => {
  e.preventDefault();
  const texto = $('#input-new').value.trim();
  const file = $('#image-new').files[0];
  if (!texto && !file) return alert('Agrega texto o imagen');
  const img64 = file ? await fileTo64(file) : '';
  const avisos = [{id: Date.now(), texto, img64, fecha: new Date().toISOString()}, ...JSON.parse(localStorage.getItem(AV_KEY) || '[]')];
  localStorage.setItem(AV_KEY, JSON.stringify(avisos));
  hide('#modal-new');
  drawAvisos();
};

BOARD?.addEventListener('click', e => {
  const art = e.target.closest('.post');
  if (!art) return;
  deleteId = Number(art.dataset.id);
  show('#modal-del');
});

$('#modal-del .close-btn')?.onclick = () => hide('#modal-del');

$('#delete-btn')?.onclick = () => {
  const avisos = JSON.parse(localStorage.getItem(AV_KEY) || '[]');
  localStorage.setItem(AV_KEY, JSON.stringify(avisos.filter(a => a.id !== deleteId)));
  hide('#modal-del');
  drawAvisos();
};

$('#clear-btn')?.onclick = () => {
  if (confirm('¿Borrar TODOS los avisos?')) {
    localStorage.removeItem(AV_KEY);
    drawAvisos();
  }
};

/***** HORARIOS: CREAR / LIMPIAR *****/
$('#add-sched-btn')?.onclick = () => {
  resetSchedForm();
  show('#modal-sched');
};

$('#modal-sched .close-btn')?.onclick = () => hide('#modal-sched');

function resetSchedForm() {
  if ($('#form-sched')) $('#form-sched').reset();
  const schedRows = $('#sched-rows');
  if (schedRows) {
    schedRows.innerHTML = `<div class="sched-row">
      <input type="text" placeholder="Parada" required>
      <input type="time" required>
    </div>`;
  }
}

$('#add-row-btn')?.onclick = () => {
  const schedRows = $('#sched-rows');
  if (schedRows) {
    schedRows.insertAdjacentHTML('beforeend', `
      <div class="sched-row">
        <input type="text" placeholder="Parada" required>
        <input type="time" required>
      </div>`);
  }
};

$('#form-sched')?.onsubmit = e => {
  e.preventDefault();
  const filas = [...$$('.sched-row')];
  const nuevos = filas.map(r => {
    const parada = r.querySelector('input[type=text]').value.trim();
    const hora = r.querySelector('input[type=time]').value;
    return {parada, hora};
  }).filter(h => h.parada && h.hora);
  if (!nuevos.length) return alert('Completa los datos');
  const horarios = [...nuevos, ...JSON.parse(localStorage.getItem(HR_KEY) || '[]')];
  localStorage.setItem(HR_KEY, JSON.stringify(horarios));
  hide('#modal-sched');
  drawHorarios();
};

$('#clear-sched-btn')?.onclick = () => {
  if (confirm('¿Eliminar TODOS los horarios?')) {
    localStorage.removeItem(HR_KEY);
    drawHorarios();
  }
};

/***** INIT *****/
$$('.modal .close-btn').forEach(btn => {
  if (!btn.onclick) btn.onclick = () => hide('#' + btn.closest('.modal').id);
});

drawAvisos();
drawHorarios();