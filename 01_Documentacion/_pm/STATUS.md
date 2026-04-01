# STATUS — pill_tracker (MediControl)

## Estado actual
- **Fase:** MVP funcional
- **Sprint:** Sin sprint activo
- **Fecha inicio proyecto:** 2026-04-01
- **Para:** Paula Garcia Martinez

## URLs
- **Produccion:** https://pill-tracker-dun6.onrender.com
- **Repo:** https://github.com/maximmarca/pill-tracker
- **Login test:** paula / paula123

## Stack
- Backend: FastAPI (Python 3.14) + SQLite
- Frontend: Vanilla JS + CSS mobile-first
- Deploy: Render free tier
- Auth: JWT (python-jose) + hashlib.sha256

## Features implementadas
- [x] Auth (registro/login con JWT)
- [x] CRUD medicamentos (nombre, dosis, horarios, frecuencia, color, notas)
- [x] Tomas diarias (marcar tomado/saltado por dia)
- [x] Dashboard (progreso circular, semana, lista de tomas)
- [x] Tratamientos (fichas medicas con 7 secciones por medicamento)
- [x] Enfermedades ("Entiende tu salud" con organos afectados, factores de riesgo, tips)
- [x] Asistente (chatbot con preguntas predefinidas + texto libre)
- [x] Diario (stats 30 dias + calendario de adherencia)
- [x] Compartir (link publico read-only para medico)
- [x] Disclaimer medico (modal primer uso)
- [x] Multilenguaje (es-LA, es-ES, en-UK, catala, valencia, euskera)
- [x] Auditoria completa realizada + 4 bugs corregidos

## Problemas conocidos
- Render free tier borra SQLite en cada deploy — hay que recrear datos
- Algunos textos internos siguen hardcodeados en español
- Info medica solo para 5 de 10 medicamentos en TREATMENT_DB

## Bloqueos
- Persistencia de datos: migrar a PostgreSQL para solucion definitiva
