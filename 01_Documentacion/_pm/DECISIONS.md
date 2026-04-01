# DECISIONS — pill_tracker (MediControl)

## 2026-04-01 — Stack: FastAPI + SQLite + Vanilla JS
- **Decision:** Usar FastAPI (Python) como backend con SQLite, y vanilla JS para el frontend.
- **Razon:** MVP rapido sin complejidad. React descartado — no aporta valor para este caso y agrega build process innecesario.
- **Nota:** Si la app crece mucho, reconsiderar frontend. Pero para MVP es perfecto.

## 2026-04-01 — Estilo mobile-first tipo Medisafe
- **Decision:** UI mobile-first (max 480px), paleta medica azul (#1E88E5), fondo claro, cards redondeadas.
- **Razon:** El uso principal es desde el celular. Referencia visual: Medisafe y ADHERE.

## 2026-04-01 — Info medica hardcodeada (no API externa)
- **Decision:** La informacion medica de tratamientos y enfermedades viene hardcodeada en el backend (TREATMENT_DB, DISEASE_DB).
- **Razon:** No depender de APIs externas. Datos fiables de prospectos/vademecum. Se puede expandir la base progresivamente.

## 2026-04-01 — Deploy en Render free tier
- **Decision:** Deploy en Render (free, 512MB RAM). URL publica permanente.
- **Problema:** SQLite se borra en cada deploy. Solucion pendiente: PostgreSQL.
- **Razon:** Gratis, simple, deploy automatico desde GitHub.

## 2026-04-01 — Lecciones aprendidas
- **Leccion:** passlib + bcrypt no funciona en Python 3.14. Workaround: hashlib.sha256 con salt.
- **Leccion:** Render free tier borra SQLite en cada deploy. Migrar a PostgreSQL.
- **Leccion:** Al registrar usuarios contra Render, hacerlo via la API de produccion (no local) porque la SECRET_KEY es distinta.
- **Leccion:** Auditar con Claude Chrome genera reportes detallados y encuentra bugs reales. Practica estandar.

## 2026-04-01 — Multilenguaje
- **Decision:** 6 idiomas (es-LA, es-ES, en-UK, catala, valencia, euskera). Diccionario en JS con ~100 keys por idioma.
- **Razon:** Paula vive en España. Soporte para lenguas cooficiales + ingles.
