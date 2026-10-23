-- Principais consumidores (processos) no momento em que um alerta de CPU/memória disparou: {source, window_seconds, at, processes[]}.
ALTER TABLE alerts ADD COLUMN culprits jsonb;
