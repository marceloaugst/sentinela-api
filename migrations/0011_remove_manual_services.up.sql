-- O cadastro manual de serviços (http/tcp/systemd) foi removido: tudo vem da descoberta automática.
-- Os serviços cadastrados antes ficam arquivados (exclusão lógica, nada é apagado): o avaliador
-- resolve os alertas e incidentes que dependiam deles.
UPDATE monitored_services SET deleted_at = now(), updated_at = now()
WHERE service_type <> 'discovered' AND deleted_at IS NULL;
