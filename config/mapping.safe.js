/**
 * mapping.safe.js (VERSIÓN CORREGIDA CON TABLA DE PAGARÉS + MENSUALIDAD ESPECIAL)
 * - Corrige ANEXO I: array de pagarés para Docxtemplater
 * - Agrega lógica robusta para mensualidad especial (pago distinto al base)
 * - Ahora también toma predio, colindancias, superficie y testigos desde el core modular
 */

module.exports = function buildMapping(data, opts = {}) {
  // ========= Helpers básicos =========
  const toFloat = (v) => {
    if (typeof v === 'number') return v;
    if (!v) return 0;
    const s = String(v).replace(/[^\d.,-]/g, '').replace(/,/g, '');
    const n = parseFloat(s);
    return Number.isFinite(n) ? n : 0;
  };

  const pad2 = (n) => String(n).padStart(2, '0');

  /**
   * Formatea un número como moneda MXN: $250,000.00
   */
  function formatCurrency(value) {
    const num = Number(value) || 0;
    return '$' + num.toLocaleString('es-MX', {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2
    });
  }

  // ==== Fechas (local, sin desfases) ====
  function parseIsoLocal(iso) {
    if (!iso) return null;
    const m = String(iso).match(/^(\d{4})-(\d{2})-(\d{2})$/);
    if (m) {
      const y = Number(m[1]), mo = Number(m[2]), d = Number(m[3]);
      return new Date(y, mo - 1, d); // LOCAL
    }
    const d = new Date(iso);
    return isNaN(d) ? null : d;
  }

  function formatDateDMY(isoLike) {
    try {
      const d = (isoLike instanceof Date) ? isoLike : parseIsoLocal(isoLike);
      if (!(d instanceof Date) || isNaN(d)) return '';
      const dd = pad2(d.getDate());
      const mm = pad2(d.getMonth() + 1);
      const yyyy = d.getFullYear();
      return `${dd}/${mm}/${yyyy}`;
    } catch {
      return '';
    }
  }

  const addMonths = (date, months) => {
    const d = new Date(date.getTime());
    d.setMonth(d.getMonth() + months);
    return d;
  };
  const endOfMonth = (date) => new Date(date.getFullYear(), date.getMonth() + 1, 0);

  const MESES = [
    'enero','febrero','marzo','abril','mayo','junio',
    'julio','agosto','septiembre','octubre','noviembre','diciembre'
  ];

  function normalizaFecha(fecha) {
    if (!fecha) return null;
    if (fecha instanceof Date && !isNaN(fecha)) return fecha;
    const s = String(fecha).trim();
    if (/^\d{4}-\d{2}-\d{2}$/.test(s)) {
      const [y, m, d] = s.split('-').map(Number);
      return new Date(y, m - 1, d);
    }
    const m = s.match(/^(\d{1,2})[\/-](\d{1,2})[\/-](\d{4})$/);
    if (m) {
      const dd = Number(m[1]), mm = Number(m[2]), yy = Number(m[3]);
      return new Date(yy, mm - 1, dd);
    }
    const d = new Date(s);
    return isNaN(d) ? null : d;
  }

  // ========= numeroALetras con fallback =========
  let numeroALetras;
  try {
    numeroALetras = require('../utils/numeroALetras');
  } catch {
    try {
      const nal = require('numero-a-letras');
      numeroALetras = nal.NumerosALetras || nal;
    } catch {
      numeroALetras = (n) => String(n);
    }
  }

  const monedaEnLetras = (num) => {
    try {
      if (typeof numeroALetras === 'function') {
        const resultado = numeroALetras(num);
        if (/PESOS/i.test(resultado)) {
          return resultado.toUpperCase();
        }
        const enteros = Math.floor(num);
        const centavos = Math.round((num - enteros) * 100);
        return `${resultado} PESOS ${pad2(centavos)}/100 M.N.`.toUpperCase();
      }
      return String(num);
    } catch (e) {
      console.error('Error en monedaEnLetras:', e);
      return String(num);
    }
  };

  // ========= Normalización de entradas =========
  const total = toFloat(data.total);
  const enganche = toFloat(data.enganche);
  const saldo = toFloat(data.saldo || (total - enganche));
  const mensual = toFloat(data.mensual || data.mensualidad);
  const anualidadMonto = toFloat(data.anualidadMonto || data.anualidad_monto || 0);
  const numeroAnualidades = Number.isFinite(data.numeroAnualidades)
    ? Number(data.numeroAnualidades)
    : (Number(data.numero_anualidades) || 0);

  const fechaEmision = normalizaFecha(data.fechaEmision) || new Date();
  const dia = fechaEmision.getDate();
  const mesIdx = fechaEmision.getMonth();
  const anio = fechaEmision.getFullYear();

  // === FECHA PRIMER PAGO ===
  let fechaPrimerPago = data.fechaPrimerPago || '';
  if (!fechaPrimerPago && Array.isArray(data.listaPagares) && data.listaPagares.length > 0) {
    // Usar la fecha EXACTA del primer pagaré generado
    const primerPagare = data.listaPagares[0];
    if (primerPagare && primerPagare.fecha_vencimiento) {
      const [y, m, d] = primerPagare.fecha_vencimiento.split('-');
      fechaPrimerPago = `${d}/${m}/${y}`;
      console.log('[DEBUG] fechaPrimerPago calculada desde listaPagares[0]:', fechaPrimerPago);
    }
  }
  // Fallback simple (si no hay listaPagares): mes siguiente día 30, y si es febrero, EOM
  if (!fechaPrimerPago) {
    const proxMes = addMonths(fechaEmision, 1);
    const isFeb = (proxMes.getMonth() === 1);
    const venc = isFeb ? endOfMonth(proxMes) : new Date(proxMes.getFullYear(), proxMes.getMonth(), 30);
    fechaPrimerPago = formatDateDMY(venc);
    console.warn('[WARN] Fallback fechaPrimerPago:', fechaPrimerPago);
  }

  // Género (ahora acepta deudorGenero del core)
  function etiquetaGenero(g) {
    const s = String(g || '').trim().toLowerCase();
    if (['m','h','hombre','masculino','comprador','el comprador','el','1','01'].includes(s)) return 'EL COMPRADOR';
    if (['f','mujer','femenino','compradora','la compradora','la','2','02'].includes(s)) return 'LA COMPRADORA';
    return 'EL COMPRADOR';
  }
  const generoEtiqueta = etiquetaGenero(data.genero || data.deudorGenero || data.genero_deudor);

  // Colindancias y valores seguros
  const safeVal = (v, fallback = '') => {
    if (v === undefined || v === null) return fallback;
    const s = String(v).trim();
    return s || fallback;
  };

  // Superficie (ahora toma también predioSuperficie del core)
  const supNum = toFloat(
    data['superficie numero'] ||
    data.superficie_numero ||
    data.superficie_m2 ||
    data.predioSuperficie ||
    data.predioSuperficieM2 ||
    0
  );
  let superficie_letras = data['superficie letra'] || data.superficie_letra || '';
  if (!superficie_letras && supNum > 0) {
    try {
      superficie_letras = monedaEnLetras(supNum).replace(/PESOS.*$/i, 'METROS CUADRADOS').trim();
    } catch {
      superficie_letras = String(supNum);
    }
  }

  // Linderos: ahora considera los campos que arma generator.js
  const norte_medida = safeVal(
    data['norte numero'] ||
    data.norte_medida ||
    data.linderoNorteMetros ||
    data.norteMetros ||
    data.NORTE_METROS,
    '0'
  );
  const norte_colinda = safeVal(
    data['colindancia norte'] ||
    data.norte_colinda ||
    data.linderoNorteColinda ||
    data.norteColinda ||
    data.NORTE_COLINDA,
    'SIN ESPECIFICAR'
  );
  const sur_medida = safeVal(
    data['sur numero'] ||
    data.sur_medida ||
    data.linderoSurMetros ||
    data.surMetros ||
    data.SUR_METROS,
    '0'
  );
  const sur_colinda = safeVal(
    data['colindancia sur'] ||
    data.sur_colinda ||
    data.linderoSurColinda ||
    data.surColinda ||
    data.SUR_COLINDA,
    'SIN ESPECIFICAR'
  );
  const oriente_medida = safeVal(
    data['oriente numero'] ||
    data.oriente_medida ||
    data.linderoOrienteMetros ||
    data.orienteMetros ||
    data.ORIENTE_METROS,
    '0'
  );
  const oriente_colinda = safeVal(
    data['colindancia oriente'] ||
    data.oriente_colinda ||
    data.linderoOrienteColinda ||
    data.orienteColinda ||
    data.ORIENTE_COLINDA,
    'SIN ESPECIFICAR'
  );
  const poniente_medida = safeVal(
    data['poniente numero'] ||
    data.poniente_medida ||
    data.linderoPonienteMetros ||
    data.ponienteMetros ||
    data.PONIENTE_METROS,
    '0'
  );
  const poniente_colinda = safeVal(
    data['colindancia poniente'] ||
    data.poniente_colinda ||
    data.linderoPonienteColinda ||
    data.ponienteColinda ||
    data.PONIENTE_COLINDA,
    'SIN ESPECIFICAR'
  );

  // ========= Tabla {#pagares} =========
  console.log('[DEBUG] Construyendo array de pagarés...');
  console.log('[DEBUG] data.listaPagares:', data.listaPagares ? `Array de ${data.listaPagares.length} elementos` : 'undefined');

  const pagaritos = Array.isArray(data.listaPagares) && data.listaPagares.length > 0
    ? data.listaPagares.map((p, idx) => {
        const m = toFloat(p.monto != null ? p.monto : p.cantidad);
        const fecha = p.fecha_vencimiento ? formatDateDMY(p.fecha_vencimiento) : '';
        const pagarito = {
          folio: p.folio != null && String(p.folio).trim() !== '' ? pad2(Number(p.folio)) : pad2(idx + 1),
          monto: formatCurrency(m),
          monto_letra: monedaEnLetras(m),
          fecha,
          obs: p.tipo === 'anualidad' ? 'ANUALIDAD' : 'MENSUALIDAD'
        };
        console.log(`[DEBUG] Pagaré ${pagarito.folio}: ${pagarito.monto} - ${pagarito.fecha} (${pagarito.obs})`);
        return pagarito;
      })
    : [];

  console.log(`[DEBUG] Total de pagarés generados: ${pagaritos.length}`);

  // === MSP (Mensualidad base + especial) — UN SOLO BLOQUE ==================
  const _mspToAmt = (val) => {
    if (typeof val === 'number' && Number.isFinite(val)) return val;
    if (typeof val !== 'string') return NaN;
    const clean = val.replace(/[^\d.,-]/g, '').replace(/,/g, '');
    const num = parseFloat(clean);
    return Number.isFinite(num) ? num : NaN;
  };

  const _mspMensAll = Array.isArray(pagaritos) ? pagaritos.filter(p => p.obs === 'MENSUALIDAD') : [];

  let mspMensualBaseNum = NaN;
  let mspNumeroMensualidadesBase = 0;
  let mspMontoMensualidadDiferente = '';
  let mspMontoMensualidadDiferente_letra = '';
  let mspPosMensualidadDiferente = '';
  let mspFolioMensualidadDiferente = '';

  if (_mspMensAll.length > 0) {
    const freq = _mspMensAll.reduce((acc, p) => {
      const n = _mspToAmt(p.monto);
      if (Number.isFinite(n)) acc[n] = (acc[n] || 0) + 1;
      return acc;
    }, {});
    const modaPar = Object.entries(freq).sort((a, b) => b[1] - a[1])[0]; // [monto, count]
    mspMensualBaseNum = modaPar ? Number(modaPar[0]) : NaN;

    const igualesBase = _mspMensAll.filter(p => _mspToAmt(p.monto) === mspMensualBaseNum);
    const diferentes  = _mspMensAll.filter(p => _mspToAmt(p.monto) !== mspMensualBaseNum);

    mspNumeroMensualidadesBase = igualesBase.length; // ← {numeroMensualidades}

    if (diferentes.length > 0) {
      const especial = diferentes[diferentes.length - 1]; // normalmente la de cierre
      const mNum = _mspToAmt(especial.monto);
      if (Number.isFinite(mNum) && mNum > 0) {
        mspMontoMensualidadDiferente = formatCurrency(mNum);
        try { mspMontoMensualidadDiferente_letra = monedaEnLetras(mNum); } catch { mspMontoMensualidadDiferente_letra = ''; }
        const esUltima = especial.folio === _mspMensAll[_mspMensAll.length - 1]?.folio;
        mspPosMensualidadDiferente = esUltima ? 'final' : 'extraordinaria';
        mspFolioMensualidadDiferente = especial.folio || '';
      }
    }
  }

  console.log('[MSP] base=', mspMensualBaseNum, 'igualesBase=', mspNumeroMensualidadesBase);
  console.log('[MSP] especial ->', {
    monto: mspMontoMensualidadDiferente,
    pos: mspPosMensualidadDiferente,
    folio: mspFolioMensualidadDiferente
  });

  // === Conteos globales útiles ===
  const numMensualidades = pagaritos.filter(p => p.obs === 'MENSUALIDAD').length;
  const numAnualidadesCalc = pagaritos.filter(p => p.obs === 'ANUALIDAD').length;
  console.log(`[DEBUG] Mensualidades: ${numMensualidades}, Anualidades: ${numAnualidadesCalc}`);

  // === Testigos: aceptar data.testigos con distintos separadores ("A | B", "A / B", "A/B") o testigo1/testigo2 ===
  //
  // El campo `testigos` puede venir con diversos caracteres separadores. Históricamente se
  // usaba el pipe ("|") pero algunos usuarios ingresan los nombres separados por una
  // diagonal ("/"). Para robustez aceptamos ambos delimitadores. Si existen
  // `testigo1` y `testigo2` por separado, esos prevalecen.
  const testigosRaw = safeVal(data.testigos, '');
  let t1 = safeVal(data.testigo1, '');
  let t2 = safeVal(data.testigo2, '');
  if ((!t1 || !t2) && testigosRaw) {
    // Dividir por cualquiera de los caracteres de separación admitidos. Utilizamos una
    // expresión regular para capturar '|' o '/' sin importar espacios alrededor.
    const parts = String(testigosRaw)
      .split(/\s*[\/|]\s*/)
      .filter((p) => p != null && p !== '');
    if (!t1 && parts[0]) t1 = parts[0].trim().toUpperCase();
    if (!t2 && parts[1]) t2 = parts[1].trim().toUpperCase();
  }

  // ========= Mapeo EXACTO de tokens del DOCX =========
  const vendedorNombre = (
    data.vendedor_nombre ||
    data.vendedorNombre ||
    data['vendedor_nombre'] ||
    data.beneficiario ||
    ''
  );
  const vendedorDomicilio = (
    data.vendedor_domicilio ||
    data.vendedorDomicilio ||
    data['vendedor_domicilio'] ||
    ''
  );

  if (!vendedorNombre) {
    throw new Error('CONTRATO_INCOMPLETO: vendedor_nombre vacío');
  }
  if (!vendedorDomicilio) {
    throw new Error('CONTRATO_INCOMPLETO: vendedor_domicilio vacío');
  }

  const mapping = {
    // Encabezado / partes
    'nombre deudor': (data.deudor || data['nombre deudor'] || '').toUpperCase(),
    'genero': generoEtiqueta,
    'VENDEDOR_NOMBRE': vendedorNombre.toUpperCase(),
    'nombre_vendedor': vendedorNombre.toUpperCase(),

    // Domicilios
    'direccion deudor': (data.direccion || data['direccion deudor'] || data.deudorDireccion || '').toUpperCase(),
    'poblacion deudor': (data.poblacion || data['poblacion deudor'] || data.deudorPoblacion || '').toUpperCase(),
    'VENDEDOR_DOMICILIO': vendedorDomicilio.toUpperCase(),
    'domicilio_vendedor': vendedorDomicilio.toUpperCase(),

    // Predio
    'nombre predio': (
      data['nombre predio'] ||
      data.predio_nombre ||
      data.nombre_predio ||
      data.predioNombre ||
      data.nombrePredio ||
      ''
    ).toUpperCase(),
    'ubicación predio': (
      data['ubicación predio'] ||
      data.ubicacion_predio ||
      data.ubicacion_completa ||
      data.predioUbicacion ||
      data.ubicacionPredio ||
      ''
    ).toUpperCase(),
    'municipio predio': (
      data['municipio predio'] ||
      data.municipio_predio ||
      data.municipio ||
      data.predioMunicipio ||
      data.municipioPredio ||
      ''
    ).toUpperCase(),
    'manzana y lote(s)': (
      data['manzana y lote(s)'] ||
      data.predioManzanaLote ||
      data.manzana_lote ||
      [data.manzana, data.lotes].filter(Boolean).join(' ') ||
      ''
    ).toUpperCase(),

    'superficie numero': supNum ? String(supNum) : '',
    'superficie letra': superficie_letras.toUpperCase(),

    // Colindancias
    'norte numero': norte_medida,
    'colindancia norte': norte_colinda.toUpperCase(),
    'sur numero': sur_medida,
    'colindancia sur': sur_colinda.toUpperCase(),
    'oriente numero': oriente_medida,
    'colindancia oriente': oriente_colinda.toUpperCase(),
    'poniente numero': poniente_medida,
    'colindancia poniente': poniente_colinda.toUpperCase(),

    // Importes
    'total': formatCurrency(total),
    'total_en_letra': monedaEnLetras(total),
    'enganche': formatCurrency(enganche),
    'enganche_letra': monedaEnLetras(enganche),
    'saldo': formatCurrency(saldo),
    'saldo_letra': monedaEnLetras(saldo),

    // Mensualidad base (moda) para cláusula
    'mensual': Number.isFinite(mspMensualBaseNum) ? formatCurrency(mspMensualBaseNum) : formatCurrency(mensual),
    'mensual_letra': Number.isFinite(mspMensualBaseNum) ? monedaEnLetras(mspMensualBaseNum) : monedaEnLetras(mensual),

    'numeroPagares': pagaritos.length || Number(data.numeroPagares || 0),

    // 🆕 CAMPOS NUEVOS PARA EL CONTRATO
    'numeroMensualidades': mspNumeroMensualidadesBase,
    'numeroAnualidadesReal': numAnualidadesCalc,

    // === Tokens para cláusula condicional de mensualidad diferente ===
    'montoMensualidadDiferente': mspMontoMensualidadDiferente,
    'montoMensualidadDiferente_letra': mspMontoMensualidadDiferente_letra,
    'posMensualidadDiferente': mspPosMensualidadDiferente,
    'folioMensualidadDiferente': mspFolioMensualidadDiferente,

    'numero_anualidades': numeroAnualidades,
    'anualidad_mes_nombre': (function() {
      const mm = Number(data.anualidadMes || data.anualidad_mes || 0);
      return mm >= 1 && mm <= 12 ? MESES[mm-1].toUpperCase() : '';
    })(),
    'anualidad_monto': formatCurrency(anualidadMonto),
    'anualidad_letra': monedaEnLetras(anualidadMonto),

    'fechaPrimerPago': fechaPrimerPago || '',

    // Interés anual
    'interes': toFloat(data.interes || data.interes_anual_pct || data.interesAnual || 0),

    // Testigos (ya normalizados arriba)
    'testigo1': t1,
    'testigo2': t2,

    // Fechas finales de firma
    'dia': String(dia),
    'dia_letra': monedaEnLetras(dia).replace(/PESOS.*$/i, '').trim().toUpperCase(),
    'mes_en_letra': MESES[mesIdx] ? MESES[mesIdx].toUpperCase() : '',
    'anio': String(anio),
    'anio_en_letra': monedaEnLetras(anio).replace(/PESOS.*$/i, '').trim().toUpperCase(),

    // Número de hojas
    'num_hojas': data.num_hojas || 0,
    'num_hojas_letra':
      data.num_hojas_letra ||
      (data.num_hojas
        ? monedaEnLetras(data.num_hojas).replace(/PESOS.*$/i, '').trim().toUpperCase()
        : ''),

    // Loop de pagarés (ANEXO I)
    'pagares': pagaritos
  };

  console.log('[DEBUG] Mapping final - pagares.length:', mapping.pagares.length);
  console.log('[DEBUG] Mapping final - numeroMensualidades:', mapping.numeroMensualidades);
  console.log('[DEBUG] Mapping final - montoMensualidadDiferente:', mapping.montoMensualidadDiferente);
  console.log('[DEBUG] Mapping final - posMensualidadDiferente:', mapping.posMensualidadDiferente);

  return mapping;
};
