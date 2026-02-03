const steps = {
  docs: document.getElementById('step-docs'),
  venta: document.getElementById('step-venta'),
  cliente: document.getElementById('step-cliente'),
  predio: document.getElementById('step-predio'),
  resumen: document.getElementById('step-resumen')
};

const progressLabel = document.getElementById('progress-label');
const progressBar = document.getElementById('progress-bar');
const nextButton = document.getElementById('next');
const prevButton = document.getElementById('prev');
const submitButton = document.getElementById('submit');
const statusText = document.getElementById('status');
const resultsSection = document.getElementById('results');
const downloadContrato = document.getElementById('download-contrato');
const downloadPagares = document.getElementById('download-pagares');
const printPagares = document.getElementById('print-pagares');

const anualidadesFields = document.getElementById('anualidades-fields');
const lugarPagoToggle = document.getElementById('lugarPagoIgual');
const lugarPagoContainer = document.getElementById('lugarPagoContainer');

const summaryVenta = document.getElementById('summary-venta');
const summaryCliente = document.getElementById('summary-cliente');
const summaryPredio = document.getElementById('summary-predio');
const editPredioButton = document.querySelector('[data-edit="predio"]');

let stepOrder = ['docs', 'venta', 'cliente', 'predio', 'resumen'];
let currentIndex = 0;

function formatCurrency(value) {
  const number = Number(value || 0);
  return number.toLocaleString('es-MX', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

function parseMoney(raw) {
  const cleaned = String(raw || '')
    .replace(/[^0-9.,-]/g, '')
    .replace(/,(?=\d{3}\b)/g, '')
    .replace(',', '.');
  const number = Number(cleaned || 0);
  return Number.isFinite(number) ? number : 0;
}

function getCheckedValue(name) {
  const selected = document.querySelector(`input[name="${name}"]:checked`);
  return selected ? selected.value : '';
}

function getFieldValue(id) {
  const element = document.getElementById(id);
  return element ? element.value.trim() : '';
}

function updateStepOrder() {
  const tipo = getCheckedValue('tipoDocumento');
  if (tipo === 'pagares') {
    stepOrder = ['docs', 'venta', 'cliente', 'resumen'];
  } else {
    stepOrder = ['docs', 'venta', 'cliente', 'predio', 'resumen'];
  }
}

function showStep(index) {
  updateStepOrder();
  currentIndex = Math.min(Math.max(index, 0), stepOrder.length - 1);

  Object.values(steps).forEach((step) => step.classList.add('hidden'));
  steps[stepOrder[currentIndex]].classList.remove('hidden');

  prevButton.classList.toggle('hidden', currentIndex === 0);
  nextButton.classList.toggle('hidden', currentIndex === stepOrder.length - 1);

  const stepNumber = currentIndex + 1;
  progressLabel.textContent = `Paso ${stepNumber} de ${stepOrder.length}`;
  progressBar.style.width = `${(stepNumber / stepOrder.length) * 100}%`;
}

function setError(input, message) {
  const errorEl = input.closest('.field, .options')?.querySelector('.error');
  if (errorEl) {
    errorEl.textContent = message || '';
  }
}

function validateStep(stepKey) {
  const container = steps[stepKey];
  if (!container) return true;
  let valid = true;
  const requiredFields = container.querySelectorAll('[data-required="true"]');
  const radioGroupsChecked = new Set();

  requiredFields.forEach((field) => {
    if (field.closest('.hidden')) return;
    if (field.disabled) return;

    if (field.type === 'radio') {
      if (radioGroupsChecked.has(field.name)) return;
      radioGroupsChecked.add(field.name);
      const selected = container.querySelector(`input[name="${field.name}"]:checked`);
      const message = selected ? '' : 'Selecciona una opción.';
      if (message) valid = false;
      setError(field, message);
      return;
    }

    const value = field.value?.trim ? field.value.trim() : '';
    const type = field.dataset.type;
    let message = '';

    if (!value && field.id !== 'enganche') {
      message = 'Este campo es obligatorio.';
    } else if (type === 'date') {
      if (!/^(hoy|\d{1,2}\/\d{1,2}\/\d{4})$/i.test(value)) {
        message = 'Usa "hoy" o dd/mm/aaaa.';
      }
    } else if (type === 'money') {
      if (field.id === 'enganche') {
        if (value && parseMoney(value) < 0) {
          message = 'Ingresa un monto válido.';
        }
      } else if (parseMoney(value) <= 0) {
        message = 'Ingresa un monto válido.';
      }
    } else if (type === 'percent') {
      const num = Number(value);
      if (!Number.isFinite(num) || num < 0 || num > 100) {
        message = 'Porcentaje inválido.';
      }
    } else if (type === 'phone') {
      const digits = value.replace(/\D+/g, '');
      if (digits.length < 10 || digits.length > 13) {
        message = 'Teléfono inválido.';
      }
    }

    if (message) {
      valid = false;
    }
    setError(field, message);
  });

  return valid;
}

function updateAnualidadesVisibility() {
  const anualidades = getCheckedValue('anualidades');
  const isVisible = anualidades === 'si';
  anualidadesFields.classList.toggle('hidden', !isVisible);
  anualidadesFields.querySelectorAll('input').forEach((input) => {
    input.disabled = !isVisible;
  });
}

function updateLugarPagoVisibility() {
  lugarPagoContainer.classList.toggle('hidden', lugarPagoToggle.checked);
  lugarPagoContainer.querySelectorAll('input').forEach((input) => {
    input.disabled = lugarPagoToggle.checked;
  });
}

function buildPayload() {
  const anualidades = getCheckedValue('anualidades');
  const regla = getCheckedValue('regla1530');
  const tipoDocumento = getCheckedValue('tipoDocumento');
  const lugarPagoIgual = lugarPagoToggle.checked;
  const lugarExpedicion = getFieldValue('lugarExpedicion');
  const engancheRaw = getFieldValue('enganche');

  return {
    tipoDocumento,
    fechaEmision: getFieldValue('fechaEmision'),
    total: parseMoney(getFieldValue('total')),
    enganche: engancheRaw ? engancheRaw : '0',
    mensual: parseMoney(getFieldValue('mensual')),
    _tieneAnualidades: anualidades === 'si',
    anualidadMonto: anualidades === 'si' ? parseMoney(getFieldValue('anualidadMonto')) : 0,
    numeroAnualidades: anualidades === 'si' ? Number(getFieldValue('numeroAnualidades') || 0) : 0,
    anualidadMes: anualidades === 'si' ? getFieldValue('anualidadMes') : 12,
    reglaPref: regla === 'siguiente' ? 'siguiente' : 'mismo',
    moratorios: Number(getFieldValue('moratorios') || 0),
    interes: Number(getFieldValue('interes') || 0),
    beneficiario: getFieldValue('beneficiario'),
    vendedorNombre: getFieldValue('vendedorNombre'),
    vendedorDomicilio: getFieldValue('vendedorDomicilio'),
    deudor: getFieldValue('deudor'),
    deudorGenero: getFieldValue('deudorGenero'),
    direccion: getFieldValue('direccion'),
    poblacion: getFieldValue('poblacion'),
    lugarExpedicion,
    lugarPagoIgualExpedicion: lugarPagoIgual,
    lugarPago: lugarPagoIgual ? lugarExpedicion : getFieldValue('lugarPago'),
    telefono: getFieldValue('telefono'),
    predioNombre: getFieldValue('predioNombre'),
    predioUbicacion: getFieldValue('predioUbicacion'),
    predioMunicipio: getFieldValue('predioMunicipio'),
    predioManzanaLote: getFieldValue('predioManzanaLote'),
    predioSuperficie: getFieldValue('predioSuperficie'),
    linderoNorte: getFieldValue('linderoNorte'),
    linderoSur: getFieldValue('linderoSur'),
    linderoOriente: getFieldValue('linderoOriente'),
    linderoPoniente: getFieldValue('linderoPoniente'),
    testigos: getFieldValue('testigos')
  };
}

function renderSummary(payload) {
  const engancheValue = parseMoney(payload.enganche);
  const saldo = Number(payload.total) - engancheValue;
  const anualTotal = Number(payload.anualidadMonto) * Number(payload.numeroAnualidades || 0);
  const numeroPagares = payload.mensual ? Math.ceil((saldo - anualTotal) / payload.mensual) : 0;

  summaryVenta.textContent = [
    '🧾 Venta y pagos',
    `• Documentos: ${payload.tipoDocumento}`,
    `• Fecha de emisión: ${payload.fechaEmision}`,
    `• Total: $${formatCurrency(payload.total)}`,
    `• Enganche: $${formatCurrency(engancheValue)}`,
    `• Saldo: $${formatCurrency(saldo)}`,
    `• Mensualidad: $${formatCurrency(payload.mensual)}`,
    payload._tieneAnualidades
      ? `• Anualidades: $${formatCurrency(payload.anualidadMonto)} x ${payload.numeroAnualidades} (mes ${payload.anualidadMes})`
      : '• Anualidades: No',
    `• Número de pagarés: ${numeroPagares}`,
    `• Regla 15/30: ${payload.reglaPref === 'siguiente' ? 'siguiente mes' : 'este mes'}`,
    `• Moratorios: ${payload.moratorios}%`,
    `• Interés anual: ${payload.interes}%`
  ].join('\n');

  summaryCliente.textContent = [
    '👥 Cliente y deudor',
    `• Beneficiario: ${payload.beneficiario}`,
    `• Vendedor: ${payload.vendedorNombre}`,
    `• Domicilio vendedor: ${payload.vendedorDomicilio}`,
    `• Deudor: ${payload.deudor}`,
    `• Género: ${payload.deudorGenero}`,
    `• Dirección: ${payload.direccion}`,
    `• Población: ${payload.poblacion}`,
    `• Lugar expedición: ${payload.lugarExpedicion}`,
    `• Lugar pago: ${payload.lugarPago}`,
    `• Teléfono: ${payload.telefono}`
  ].join('\n');

  if (stepOrder.includes('predio')) {
    summaryPredio.textContent = [
      '🏡 Predio y testigos',
      `• Predio: ${payload.predioNombre}`,
      `• Ubicación: ${payload.predioUbicacion}`,
      `• Municipio: ${payload.predioMunicipio}`,
      `• Manzana/Lote: ${payload.predioManzanaLote}`,
      `• Superficie: ${payload.predioSuperficie}`,
      `• Norte: ${payload.linderoNorte}`,
      `• Sur: ${payload.linderoSur}`,
      `• Oriente: ${payload.linderoOriente}`,
      `• Poniente: ${payload.linderoPoniente}`,
      `• Testigos: ${payload.testigos}`
    ].join('\n');
    summaryPredio.classList.remove('hidden');
    if (editPredioButton) editPredioButton.classList.remove('hidden');
  } else {
    summaryPredio.textContent = 'Se omitió la sección de predio porque solo se generarán pagarés.';
    summaryPredio.classList.remove('hidden');
    if (editPredioButton) editPredioButton.classList.add('hidden');
  }
}

function clearStatus() {
  statusText.textContent = '';
}

nextButton.addEventListener('click', () => {
  const stepKey = stepOrder[currentIndex];
  if (!validateStep(stepKey)) return;
  if (stepKey === 'docs') updateStepOrder();
  if (stepKey === 'venta') updateAnualidadesVisibility();
  if (stepKey === 'cliente') updateLugarPagoVisibility();
  showStep(currentIndex + 1);
  renderSummary(buildPayload());
});

prevButton.addEventListener('click', () => {
  showStep(currentIndex - 1);
  renderSummary(buildPayload());
});

lugarPagoToggle.addEventListener('change', updateLugarPagoVisibility);

document.querySelectorAll('input[name="anualidades"]').forEach((radio) => {
  radio.addEventListener('change', updateAnualidadesVisibility);
});

document.querySelectorAll('input[name="tipoDocumento"]').forEach((radio) => {
  radio.addEventListener('change', () => {
    updateStepOrder();
    renderSummary(buildPayload());
  });
});

document.querySelectorAll('[data-edit]').forEach((button) => {
  button.addEventListener('click', () => {
    const target = button.getAttribute('data-edit');
    const index = stepOrder.indexOf(target);
    if (index >= 0) {
      showStep(index);
    }
  });
});

submitButton.addEventListener('click', async () => {
  clearStatus();
  const payload = buildPayload();
  const allValid = stepOrder.every((stepKey) => validateStep(stepKey));
  if (!allValid) return;

  submitButton.disabled = true;
  statusText.textContent = 'Enviando captura...';

  try {
    const captureRes = await fetch('/api/capturas', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ payload })
    });

    const captureData = await captureRes.json();
    if (!captureData.ok) {
      throw new Error(captureData.error || 'Error al guardar la captura');
    }

    statusText.textContent = 'Generando documentos...';
    const generateRes = await fetch('/api/generar', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ basePath: captureData.basePath, docs: payload.tipoDocumento })
    });

    const generateData = await generateRes.json();
    if (!generateData.ok) {
      throw new Error(generateData.error || 'Error al generar documentos');
    }

    statusText.textContent = 'Documentos listos para descarga.';
    const { contratoPdfUrl, pagaresPdfUrl } = generateData.outputs || {};

    downloadContrato.classList.toggle('hidden', !contratoPdfUrl);
    downloadPagares.classList.toggle('hidden', !pagaresPdfUrl);
    printPagares.classList.toggle('hidden', !pagaresPdfUrl);

    if (contratoPdfUrl) downloadContrato.href = contratoPdfUrl;
    if (pagaresPdfUrl) downloadPagares.href = pagaresPdfUrl;

    resultsSection.classList.remove('hidden');
  } catch (error) {
    statusText.textContent = error.message;
  } finally {
    submitButton.disabled = false;
  }
});

printPagares.addEventListener('click', () => {
  if (!downloadPagares.href || downloadPagares.href === '#') return;
  const printWindow = window.open(downloadPagares.href, '_blank');
  if (!printWindow) return;
  printWindow.addEventListener('load', () => {
    printWindow.focus();
    printWindow.print();
  });
});

updateAnualidadesVisibility();
updateLugarPagoVisibility();
showStep(0);
renderSummary(buildPayload());
