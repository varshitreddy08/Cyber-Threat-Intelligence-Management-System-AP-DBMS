import { Pool } from 'pg';

const pool = new Pool({
  host:     'ep-muddy-sea-b4anq2mq-pooler.c-6.us-east-2.aws.neon.tech',
  database: 'neondb',
  user:     'neondb_owner',
  password: 'npg_8Tbm4ChDXQqf',
  ssl:      { rejectUnauthorized: false },
  max: 5,
});

export async function query(sql: string, params?: unknown[]) {
  const client = await pool.connect();
  try {
    const res = await client.query(sql, params);
    return res.rows;
  } finally {
    client.release();
  }
}

export default pool;
