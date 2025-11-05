#!/usr/bin/env node
/* Simple DB check script for backend project */
const dotenv = require('dotenv');
const { Client } = require('pg');

dotenv.config();

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('No DATABASE_URL found in environment. Create a .env file with DATABASE_URL.');
  process.exit(1);
}

(async function main() {
  const client = new Client({ connectionString: DATABASE_URL });
  try {
    await client.connect();
    console.log('Connected to database');

    const tables = ['inventario_costos', 'ventas'];

    for (const t of tables) {
      console.log('\n=== Table:', t, '===');
      const colRes = await client.query(
        `SELECT column_name, data_type
         FROM information_schema.columns
         WHERE table_name = $1
         ORDER BY ordinal_position;`,
        [t]
      );
      if (colRes.rows.length === 0) {
        console.log('  (no columns found or table does not exist)');
        continue;
      }
      for (const r of colRes.rows) {
        console.log(`  ${r.column_name}  ${r.data_type}`);
      }

      try {
        const sample = await client.query(`SELECT * FROM ${t} LIMIT 5;`);
        console.log('\n  Sample rows (up to 5):');
        if (sample.rows.length === 0) console.log('    (no rows)');
        else console.table(sample.rows);
      } catch (e) {
        console.log('  Could not fetch sample rows:', e.message);
      }
    }

    await client.end();
    console.log('\nDone.');
  } catch (err) {
    console.error('Error connecting/querying database:', err.message);
    process.exitCode = 2;
  }
})();
