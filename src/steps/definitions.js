// src/steps/definitions.js

const STEPS = [
  // =========================================================
  // BLOQUE A — Venta y tiempos
  // =========================================================

  // A0. Tipo de documento
  {
    id: 'tipoDocumento',
    block: 'A',
    q: '👋 Bienvenido.\n¿Qué documentos deseas generar?\n1️⃣ Contrato\n2️⃣ Pagarés\n3️⃣ Ambos',
    field: 'tipoDocumento',
    parse: 'parseDocType',
  },

  // A1. Fecha de emisión al inicio
  {
    id: 'fechaEmision',
    block: 'A',
    q: '🗓️ Indica la **fecha de emisión del lote**.\nPuedes escribir "hoy" o una fecha como **dd/mm/aaaa**:',
    field: 'fechaEmision',
    parse: 'parseDateDMYLoose',
  },

  // A2. Total
  {
    id: 'total',
    block: 'A',
    q: '💰 Indica el **monto total de la venta** (ejemplo: 250000, $250,000, 250 mil):',
    field: 'total',
    parse: 'parseMoneyLoose',
  },

  // A3. Enganche
  {
    id: 'enganche',
    block: 'A',
    q: '💵 ¿Cuánto será el **enganche**? (escribe 0 si no habrá):',
    field: 'enganche',
    parse: 'parseMoneyLoose',
  },

  // A4. Mensualidad
  {
    id: 'mensualidad',
    block: 'A',
    q: '📅 ¿De cuánto será la **mensualidad**? (formato libre, ejemplo: 13000):',
    field: 'mensual', // baseData.mensual
    parse: 'parseMoneyLoose',
  },

  // A5. Anualidades
  {
    id: 'anualidadConfirm',
    block: 'A',
    q: '🎯 ¿Habrá **anualidades especiales** además de las mensualidades? (responde sí/no):',
    field: '_tieneAnualidades', // core usa esto para saltar
    parse: 'parseYesNo',
  },
  {
    id: 'anualidadMonto',
    block: 'A',
    q: '💎 ¿De cuánto será **cada anualidad**? (ejemplo: 60000):',
    field: 'anualidadMonto',
    parse: 'parseMoneyLoose',
    onlyAnualidad: true,
  },
  {
    id: 'anualidadCount',
    block: 'A',
    q: '🔢 ¿Cuántas **anualidades** serán en total?',
    field: 'numeroAnualidades', // baseData.numeroAnualidades
    parse: 'parseMoneyLoose',
    onlyAnualidad: true,
  },
  {
    id: 'anualidadMes',
    block: 'A',
    q: '🗓️ ¿En qué **mes** vence cada anualidad? (1..12 o nombre de mes, ej. 2 o "febrero"):',
    field: 'anualidadMes',
    parse: 'parseMesLoose',
    onlyAnualidad: true,
  },

  // A6. Regla 15/30
  {
    id: 'regla1530',
    block: 'A',
    q: '📆 Para la **regla 15/30**, ¿el primer pago vence en **este mes** o en el **mes siguiente**?\n(Escribe "este mes" o "siguiente mes")',
    field: 'primerPagoMes',
    parse: 'parseRegla1530',
  },

  // A7. Moratorios
  {
    id: 'moratorios',
    block: 'A',
    q: '⚠️ ¿Cuál será el **interés moratorio anual (%)**?',
    field: 'moratorios',
    parse: 'parsePercentLoose',
  },

  // A8. Interés anual
  {
    id: 'interesAnual',
    block: 'A',
    q: '💹 Indica la **tasa de interés anual (%)** para la cláusula cuarta (escribe 0 si no aplica):',
    field: 'interes',
    parse: 'parsePercentLoose',
  },

  // (A9: cálculo saldo + pagarés lo hace el core internamente)

  // =========================================================
  // BLOQUE B — Personas
  // =========================================================

  // B1. Beneficiario
  {
    id: 'beneficiario',
    block: 'B',
    q: '👤 Nombre completo del **beneficiario** (a la orden de):',
    field: 'beneficiario',
  },

  // B1.1 Nombre del vendedor
  {
    id: 'vendedorNombre',
    block: 'B',
    q: '🧑‍💼 Nombre completo del **vendedor**:',
    field: 'vendedor_nombre',
  },

  // B1.2 Domicilio del vendedor
  {
    id: 'vendedorDomicilio',
    block: 'B',
    q: '🏠 Domicilio del **vendedor**:',
    field: 'vendedor_domicilio',
  },

  // B2. Nombre del deudor
  {
    id: 'deudorNombre',
    block: 'B',
    q: '🙋 Nombre completo del **deudor**:',
    field: 'deudor',
  },

  // B3. Género del deudor
  {
    id: 'deudorGenero',
    block: 'B',
    q: '🚻 ¿Género del deudor?\n1️⃣ Hombre\n2️⃣ Mujer\n(O escribe Hombre/Mujer):',
    field: 'deudorGenero',
    parse: 'parseGenero',
  },

  // B4. Dirección del deudor
  {
    id: 'deudorDireccion',
    block: 'B',
    q: '🏠 Dirección completa del **deudor**:',
    field: 'direccion',
  },

  // B5. Población del deudor
  {
    id: 'deudorPoblacion',
    block: 'B',
    q: '🏙️ Población del **deudor** (ciudad, estado, C.P.):',
    field: 'poblacion',
  },

  // B6. Lugar de expedición
  {
    id: 'lugarExpedicion',
    block: 'B',
    q: '📍 Lugar de **expedición** del documento (ciudad/estado):',
    field: 'lugarExpedicion',
  },

  // B7. Lugar de pago
  {
    id: 'lugarPago',
    block: 'B',
    q: '🏦 ¿Cuál será el **lugar de pago**?\n(Escribe "sí" si será igual al de expedición, o indica otro lugar):',
    field: 'lugarPago',
  },

  // B8. Teléfono del cliente
  {
    id: 'telefono',
    block: 'B',
    q: '📞 Teléfono del cliente (10 dígitos o +52…):',
    field: 'telefono',
    parse: 'parseTelefono',
  },

  // =========================================================
  // BLOQUE C — Predio y testigos
  // (solo si NO es solo pagarés)
  // =========================================================

  // C1. Nombre del predio
  {
    id: 'predioNombre',
    block: 'C',
    q: '🏷️ Nombre del **predio**:',
    field: 'predioNombre',
    onlyContrato: true,
  },

  // C2. Ubicación completa
  {
    id: 'predioUbicacion',
    block: 'C',
    q: '📌 **Ubicación completa** del predio:',
    field: 'predioUbicacion',
    onlyContrato: true,
  },

  // C3. Municipio
  {
    id: 'predioMunicipio',
    block: 'C',
    q: '🏛️ Municipio del predio:',
    field: 'predioMunicipio',
    onlyContrato: true,
  },

  // C4. Manzana y lote
  {
    id: 'predioManzanaLote',
    block: 'C',
    q: '🗺️ Manzana y lote(s) del predio:',
    field: 'predioManzanaLote',
    onlyContrato: true,
  },

  // C5. Superficie
  {
    id: 'predioSuperficie',
    block: 'C',
    q: '📏 Superficie del predio (en metros cuadrados):',
    field: 'predioSuperficie',
    onlyContrato: true,
  },

  // C6–C9. Linderos
  {
    id: 'linderoNorte',
    block: 'C',
    q: '🧭 Norte – responde: **metros | colinda**',
    field: 'linderoNorte',
    onlyContrato: true,
  },
  {
    id: 'linderoSur',
    block: 'C',
    q: '🧭 Sur – responde: **metros | colinda**',
    field: 'linderoSur',
    onlyContrato: true,
  },
  {
    id: 'linderoOriente',
    block: 'C',
    q: '🧭 Oriente – responde: **metros | colinda**',
    field: 'linderoOriente',
    onlyContrato: true,
  },
  {
    id: 'linderoPoniente',
    block: 'C',
    q: '🧭 Poniente – responde: **metros | colinda**',
    field: 'linderoPoniente',
    onlyContrato: true,
  },

  // C10. Testigos
  {
    id: 'testigos',
    block: 'C',
    q: '🧾 Testigos – responde: **Testigo 1 | Testigo 2** (formato: `Testigo 1 | Testigo 2`):',
    field: 'testigos',
    // si luego quieres usar parseTestigos, solo añade parse: 'parseTestigos' y actualiza runParser
    onlyContrato: true,
  },

  // =========================================================
  // BLOQUE D — Resumen + edición
  // =========================================================

  {
    id: 'confirm',
    block: 'D',
    q: '📋 Aquí iría el **resumen general** con todos los datos.\n\nEscribe:\n• APROBAR – para generar PDFs definitivos\n• EDITAR – para ajustar campos\n• CANCELAR – para descartar el borrador',
  },
];

module.exports = { STEPS };
