## Why SQLite?
- Chosen for MVP simplicity
- Production would use PostgreSQL with TimescaleDB for time-series data

## Security Tradeoffs
| MVP Approach       | Production Ready          |
|--------------------|---------------------------|
| HTTP               | Mutual TLS + SPIFFE IDs   |
| Environment vars   | AWS Parameter Store       |
