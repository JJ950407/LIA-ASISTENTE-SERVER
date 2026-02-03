// test.js – generación end-to-end usando el mismo motor del API

const fs = require('fs');
const path = require('path');
const { parseDateDMYLoose } = require('./src/parsers/date');
const { generateFromMeta } = require('./src/app/generateFromMeta');

function slugifyWeb(text) {
  return String(text || '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-zA-Z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .toLowerCase()
    .slice(0, 60);
}

function ymd(date) {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

async function run() {
  const payload = {
    tipoDocumento: 'ambos',
    fechaEmision: 'hoy',
    total: 485000,
    enganche: 75000,
    mensual: 22500,
    _tieneAnualidades: true,
    anualidadMonto: 15000,
    numeroAnualidades: 3,
    anualidadMes: 'febrero',
    reglaPref: 'siguiente',
    moratorios: 2,
    interes: 1.5,
    beneficiario: 'Marina Hernández Olvera',
    vendedorNombre: 'Roberto Carlos Méndez Soto',
    vendedorDomicilio: 'Calle Primavera 128, Col. Jardines del Sol',
    deudor: 'Ana Sofía Ramírez Castro',
    deudorGenero: 'Mujer',
    direccion: 'Av. Insurgentes Sur 3847 Depto 402, Col. Tlalpan Centro',
    poblacion: 'Tlalpan, CDMX, C.P. 14000',
    lugarExpedicion: 'Chalco, Estado de México',
    lugarPagoIgualExpedicion: false,
    lugarPago: 'Texcoco, Edo. Méx.',
    telefono: '5587654321',
    predioNombre: 'Terreno Las Flores',
    predioUbicacion: 'Camino Real a San Miguel km 2.5, Paraje El Cerrito',
    predioMunicipio: 'Chalco',
    predioManzanaLote: 'Manzana 14 Lote 22',
    predioSuperficie: '320',
    linderoNorte: '10 | con camino vecinal',
    linderoSur: '10 | con lote 23',
    linderoOriente: '32 | con terreno ejidal',
    linderoPoniente: '32 | con barranca',
    testigos: 'María González Pérez | Carlos Alberto Ruiz Montes'
  };

  const fechaEmision = parseDateDMYLoose(payload.fechaEmision);
  const slug = slugifyWeb(payload.deudor);
  const dateISO = ymd(fechaEmision);

  const basePathRel = path.join('data', 'clientes', slug, dateISO);
  const basePathAbs = path.resolve(__dirname, basePathRel);
  fs.mkdirSync(basePathAbs, { recursive: true });

  const now = new Date().toISOString();
  const meta = {
    ...payload,
    slug,
    dateISO,
    basePath: basePathRel,
    createdAt: now,
    updatedAt: now
  };

  fs.writeFileSync(path.join(basePathAbs, 'meta.json'), JSON.stringify(meta, null, 2));

  console.log('🚀 Ejecutando generación con motor compartido...');
  const outputs = await generateFromMeta({ basePath: basePathAbs, docs: payload.tipoDocumento });

  console.log('✅ Documentos generados:', outputs);
}

run().catch((error) => {
  console.error('❌ Error en test:', error);
  process.exit(1);
});
