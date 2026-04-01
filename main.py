"""
PillTracker — Backend FastAPI
Seguimiento de toma de medicación.
"""
import os
import sqlite3
import uuid
from datetime import datetime, date, timedelta
from contextlib import contextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from jose import JWTError, jwt
import hashlib

# ============================================================
# CONFIG
# ============================================================
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30
DB_PATH = os.path.join(os.path.dirname(__file__), "pilltracker.db")

# ============================================================
# APP
# ============================================================
app = FastAPI(title="PillTracker", version="0.1.0")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login", auto_error=False)

def hash_password(password: str) -> str:
    return hashlib.sha256((password + SECRET_KEY).encode()).hexdigest()

def verify_password(password: str, hashed: str) -> bool:
    return hash_password(password) == hashed

# ============================================================
# DATABASE
# ============================================================
@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                share_token TEXT UNIQUE,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS medications (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id),
                name TEXT NOT NULL,
                dose TEXT NOT NULL,
                frequency TEXT NOT NULL DEFAULT 'daily',
                times_per_day INTEGER NOT NULL DEFAULT 1,
                schedule TEXT NOT NULL DEFAULT '08:00',
                color TEXT NOT NULL DEFAULT '#2196f3',
                active INTEGER NOT NULL DEFAULT 1,
                notes TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS takes (
                id TEXT PRIMARY KEY,
                medication_id TEXT NOT NULL REFERENCES medications(id) ON DELETE CASCADE,
                user_id TEXT NOT NULL REFERENCES users(id),
                scheduled_date TEXT NOT NULL,
                scheduled_time TEXT NOT NULL,
                taken INTEGER NOT NULL DEFAULT 0,
                taken_at TEXT,
                skipped INTEGER NOT NULL DEFAULT 0,
                notes TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_takes_date ON takes(user_id, scheduled_date);
            CREATE INDEX IF NOT EXISTS idx_takes_med ON takes(medication_id, scheduled_date);
        """)


init_db()

# ============================================================
# MODELS
# ============================================================
class UserCreate(BaseModel):
    username: str
    display_name: str
    password: str

class MedicationCreate(BaseModel):
    name: str
    dose: str
    frequency: str = "daily"
    times_per_day: int = 1
    schedule: str = "08:00"
    color: str = "#2196f3"
    notes: Optional[str] = None

class MedicationUpdate(BaseModel):
    name: Optional[str] = None
    dose: Optional[str] = None
    frequency: Optional[str] = None
    times_per_day: Optional[int] = None
    schedule: Optional[str] = None
    color: Optional[str] = None
    active: Optional[bool] = None
    notes: Optional[str] = None

class TakeAction(BaseModel):
    taken: bool
    skipped: bool = False
    notes: Optional[str] = None

# ============================================================
# AUTH HELPERS
# ============================================================
def create_token(user_id: str) -> str:
    expire = datetime.utcnow() + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    return jwt.encode({"sub": user_id, "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: Optional[str] = Depends(oauth2_scheme)):
    if not token:
        raise HTTPException(status_code=401, detail="No autenticado")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Token invalido")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalido")

    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    return dict(user)

# ============================================================
# ROUTES — AUTH
# ============================================================
@app.post("/api/auth/register")
def register(data: UserCreate):
    with get_db() as db:
        existing = db.execute("SELECT id FROM users WHERE username=?", (data.username,)).fetchone()
        if existing:
            raise HTTPException(400, "Usuario ya existe")

        user_id = str(uuid.uuid4())
        share_token = str(uuid.uuid4())[:8]
        db.execute(
            "INSERT INTO users (id, username, display_name, password_hash, share_token, created_at) VALUES (?,?,?,?,?,?)",
            (user_id, data.username, data.display_name, hash_password(data.password), share_token, datetime.utcnow().isoformat())
        )
    return {"token": create_token(user_id), "user_id": user_id, "display_name": data.display_name}


@app.post("/api/auth/login")
def login(form: OAuth2PasswordRequestForm = Depends()):
    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE username=?", (form.username,)).fetchone()
    if not user or not verify_password(form.password, user["password_hash"]):
        raise HTTPException(400, "Credenciales invalidas")
    return {"access_token": create_token(user["id"]), "token_type": "bearer", "display_name": user["display_name"]}

# ============================================================
# ROUTES — MEDICATIONS
# ============================================================
@app.get("/api/medications")
def list_medications(user=Depends(get_current_user)):
    with get_db() as db:
        meds = db.execute("SELECT * FROM medications WHERE user_id=? ORDER BY created_at", (user["id"],)).fetchall()
    return [dict(m) for m in meds]


@app.post("/api/medications")
def create_medication(data: MedicationCreate, user=Depends(get_current_user)):
    med_id = str(uuid.uuid4())
    with get_db() as db:
        db.execute(
            "INSERT INTO medications (id, user_id, name, dose, frequency, times_per_day, schedule, color, notes, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (med_id, user["id"], data.name, data.dose, data.frequency, data.times_per_day, data.schedule, data.color, data.notes, datetime.utcnow().isoformat())
        )
    return {"id": med_id, "status": "created"}


@app.put("/api/medications/{med_id}")
def update_medication(med_id: str, data: MedicationUpdate, user=Depends(get_current_user)):
    with get_db() as db:
        med = db.execute("SELECT * FROM medications WHERE id=? AND user_id=?", (med_id, user["id"])).fetchone()
        if not med:
            raise HTTPException(404, "Medicamento no encontrado")

        updates = {k: v for k, v in data.model_dump().items() if v is not None}
        if "active" in updates:
            updates["active"] = 1 if updates["active"] else 0
        if updates:
            sets = ", ".join(f"{k}=?" for k in updates)
            vals = list(updates.values()) + [med_id]
            db.execute(f"UPDATE medications SET {sets} WHERE id=?", vals)
    return {"status": "updated"}


@app.delete("/api/medications/{med_id}")
def delete_medication(med_id: str, user=Depends(get_current_user)):
    with get_db() as db:
        db.execute("DELETE FROM medications WHERE id=? AND user_id=?", (med_id, user["id"]))
    return {"status": "deleted"}

# ============================================================
# ROUTES — DAILY TAKES
# ============================================================
def ensure_daily_takes(db, user_id: str, target_date: str):
    """Generate take entries for a given date if they don't exist."""
    existing = db.execute("SELECT COUNT(*) as c FROM takes WHERE user_id=? AND scheduled_date=?", (user_id, target_date)).fetchone()["c"]
    if existing > 0:
        return

    meds = db.execute("SELECT * FROM medications WHERE user_id=? AND active=1", (user_id,)).fetchall()
    for med in meds:
        times = med["schedule"].split(",")
        for t in times:
            take_id = str(uuid.uuid4())
            db.execute(
                "INSERT INTO takes (id, medication_id, user_id, scheduled_date, scheduled_time, taken, skipped) VALUES (?,?,?,?,?,0,0)",
                (take_id, med["id"], user_id, target_date, t.strip())
            )


@app.get("/api/takes/{target_date}")
def get_takes(target_date: str, user=Depends(get_current_user)):
    with get_db() as db:
        ensure_daily_takes(db, user["id"], target_date)
        takes = db.execute("""
            SELECT t.*, m.name as med_name, m.dose, m.color
            FROM takes t JOIN medications m ON t.medication_id = m.id
            WHERE t.user_id=? AND t.scheduled_date=?
            ORDER BY t.scheduled_time, m.name
        """, (user["id"], target_date)).fetchall()
    return [dict(t) for t in takes]


@app.put("/api/takes/{take_id}")
def update_take(take_id: str, data: TakeAction, user=Depends(get_current_user)):
    with get_db() as db:
        take = db.execute("SELECT * FROM takes WHERE id=? AND user_id=?", (take_id, user["id"])).fetchone()
        if not take:
            raise HTTPException(404, "Toma no encontrada")

        taken_at = datetime.utcnow().isoformat() if data.taken else None
        db.execute(
            "UPDATE takes SET taken=?, skipped=?, taken_at=?, notes=? WHERE id=?",
            (1 if data.taken else 0, 1 if data.skipped else 0, taken_at, data.notes, take_id)
        )
    return {"status": "updated"}

# ============================================================
# ROUTES — STATS
# ============================================================
@app.get("/api/stats")
def get_stats(days: int = 30, user=Depends(get_current_user)):
    end_date = date.today()
    start_date = end_date - timedelta(days=days-1)

    with get_db() as db:
        rows = db.execute("""
            SELECT scheduled_date,
                   COUNT(*) as total,
                   SUM(taken) as taken,
                   SUM(skipped) as skipped
            FROM takes
            WHERE user_id=? AND scheduled_date BETWEEN ? AND ?
            GROUP BY scheduled_date
            ORDER BY scheduled_date
        """, (user["id"], start_date.isoformat(), end_date.isoformat())).fetchall()

    daily = []
    total_takes = 0
    total_taken = 0
    for r in rows:
        pct = round(r["taken"] / r["total"] * 100) if r["total"] > 0 else 0
        daily.append({"date": r["scheduled_date"], "total": r["total"], "taken": r["taken"], "skipped": r["skipped"], "pct": pct})
        total_takes += r["total"]
        total_taken += r["taken"]

    overall_pct = round(total_taken / total_takes * 100) if total_takes > 0 else 0

    return {"days": days, "overall_pct": overall_pct, "total_takes": total_takes, "total_taken": total_taken, "daily": daily}

# ============================================================
# ROUTES — SHARE
# ============================================================
@app.get("/api/share/token")
def get_share_token(user=Depends(get_current_user)):
    return {"share_token": user["share_token"], "display_name": user["display_name"]}


@app.get("/api/shared/{share_token}")
def get_shared_data(share_token: str):
    with get_db() as db:
        user = db.execute("SELECT * FROM users WHERE share_token=?", (share_token,)).fetchone()
        if not user:
            raise HTTPException(404, "Token invalido")

        end_date = date.today()
        start_date = end_date - timedelta(days=6)

        meds = db.execute("SELECT * FROM medications WHERE user_id=? AND active=1", (user["id"],)).fetchall()

        takes = db.execute("""
            SELECT t.*, m.name as med_name, m.dose, m.color
            FROM takes t JOIN medications m ON t.medication_id = m.id
            WHERE t.user_id=? AND t.scheduled_date BETWEEN ? AND ?
            ORDER BY t.scheduled_date, t.scheduled_time
        """, (user["id"], start_date.isoformat(), end_date.isoformat())).fetchall()

        stats = db.execute("""
            SELECT COUNT(*) as total, SUM(taken) as taken
            FROM takes WHERE user_id=? AND scheduled_date BETWEEN ? AND ?
        """, (user["id"], start_date.isoformat(), end_date.isoformat())).fetchone()

    pct = round(stats["taken"] / stats["total"] * 100) if stats["total"] and stats["total"] > 0 else 0

    return {
        "display_name": user["display_name"],
        "medications": [dict(m) for m in meds],
        "takes": [dict(t) for t in takes],
        "adherence_pct": pct,
        "period": f"{start_date.isoformat()} a {end_date.isoformat()}"
    }

# ============================================================
# ROUTES — DISEASE INFO
# ============================================================
DISEASE_DB = {
    "hipertension": {
        "name": "Hipertension Arterial",
        "description": "La hipertension arterial es una condicion cronica en la que la presion de la sangre contra las paredes de las arterias es consistentemente alta (mayor a 140/90 mmHg). Es conocida como 'el asesino silencioso' porque generalmente no presenta sintomas hasta que causa daño significativo.",
        "organs": [
            {"name": "Corazon", "icon": "heart", "description": "Supone una mayor resistencia para el corazon, pudiendo producir insuficiencia coronaria, angina de pecho, arritmias e infarto de miocardio. El corazon se agranda para compensar el esfuerzo extra."},
            {"name": "Ojos", "icon": "eye", "description": "Daña las arterias de la retina (retinopatia hipertensiva), provocando alteraciones en la vision que pueden llegar a la ceguera si no se controla."},
            {"name": "Riñones", "icon": "kidney", "description": "Causa rigidez en las arterias que suministran sangre a los riñones, pudiendo desembocar en insuficiencia renal cronica y necesidad de dialisis."},
            {"name": "Cerebro", "icon": "brain", "description": "Cuando las arterias se vuelven rigidas y estrechas, puede provocar infartos cerebrales (ACV), hemorragias cerebrales y deterioro cognitivo."},
            {"name": "Arterias", "icon": "artery", "description": "Endurece y estrecha las arterias (arteriosclerosis), reduciendo el flujo sanguineo a todos los organos y aumentando el riesgo de aneurismas."}
        ],
        "risk_factors": ["Sedentarismo", "Exceso de sal en la dieta", "Sobrepeso/obesidad", "Estres cronico", "Tabaquismo", "Consumo excesivo de alcohol", "Antecedentes familiares", "Edad avanzada"],
        "lifestyle_tips": [
            "Reducir el consumo de sal a menos de 5g/dia",
            "Realizar 30 minutos de actividad fisica moderada al menos 5 dias por semana",
            "Mantener un peso saludable (IMC entre 18.5 y 24.9)",
            "Limitar el consumo de alcohol",
            "No fumar",
            "Controlar el estres con tecnicas de relajacion",
            "Medir la presion arterial regularmente en casa"
        ],
        "related_meds": ["enalapril"]
    },
    "diabetes": {
        "name": "Diabetes Tipo 2",
        "description": "La diabetes tipo 2 es una enfermedad metabolica cronica en la que el cuerpo no produce suficiente insulina o no la utiliza eficientemente (resistencia a la insulina). Esto resulta en niveles elevados de glucosa (azucar) en sangre que, con el tiempo, dañan organos y vasos sanguineos.",
        "organs": [
            {"name": "Ojos", "icon": "eye", "description": "La retinopatia diabetica daña los vasos sanguineos de la retina. Es la principal causa de ceguera en adultos en edad laboral. Control glucemico reduce el riesgo significativamente."},
            {"name": "Riñones", "icon": "kidney", "description": "La nefropatia diabetica afecta los filtros renales. La diabetes es la causa numero 1 de insuficiencia renal terminal. Control de glucosa y presion arterial son claves para prevenirla."},
            {"name": "Nervios", "icon": "nerve", "description": "La neuropatia diabetica causa hormigueo, dolor, perdida de sensibilidad en pies y manos. Puede llevar a ulceras e infecciones que no se sienten. Revisar los pies diariamente."},
            {"name": "Corazon", "icon": "heart", "description": "Duplica o triplica el riesgo de enfermedad cardiovascular. Los diabeticos tienen mayor riesgo de infarto, ACV y enfermedad arterial periferica."},
            {"name": "Pies", "icon": "foot", "description": "El pie diabetico combina neuropatia + mala circulacion. Pequeñas heridas pueden convertirse en ulceras graves. Inspeccion diaria y cuidado podologico son esenciales."}
        ],
        "risk_factors": ["Sobrepeso/obesidad", "Sedentarismo", "Antecedentes familiares", "Edad mayor a 45 años", "Hipertension arterial", "Colesterol alto", "Diabetes gestacional previa"],
        "lifestyle_tips": [
            "Controlar la glucosa en sangre segun las indicaciones del medico",
            "Seguir un plan de alimentacion equilibrado, bajo en azucares simples",
            "Realizar actividad fisica regularmente (ayuda a controlar la glucosa)",
            "Mantener un peso saludable",
            "Revisar los pies diariamente buscando heridas o cambios",
            "No saltear comidas ni medicacion",
            "Realizar controles medicos periodicos (HbA1c cada 3-6 meses)"
        ],
        "related_meds": ["metformina"]
    },
    "hipotiroidismo": {
        "name": "Hipotiroidismo",
        "description": "El hipotiroidismo es una condicion en la que la glandula tiroides no produce suficientes hormonas tiroideas. Estas hormonas regulan el metabolismo, la energia, la temperatura corporal y el funcionamiento de casi todos los organos. Sin tratamiento, el metabolismo se ralentiza progresivamente.",
        "organs": [
            {"name": "Metabolismo", "icon": "metabolism", "description": "El metabolismo se ralentiza: aumento de peso inexplicable, fatiga persistente, intolerancia al frio, piel seca y cabello quebradizo."},
            {"name": "Corazon", "icon": "heart", "description": "Puede causar bradicardia (ritmo cardiaco lento), aumento del colesterol y mayor riesgo cardiovascular a largo plazo."},
            {"name": "Cerebro", "icon": "brain", "description": "Afecta el animo (depresion), la memoria y la concentracion. En casos severos puede causar mixedema, una emergencia medica."},
            {"name": "Sistema reproductivo", "icon": "reproductive", "description": "Puede causar irregularidades menstruales, dificultad para concebir e infertilidad. En embarazo no tratado, riesgo para el desarrollo del bebe."}
        ],
        "risk_factors": ["Sexo femenino (8x mas frecuente)", "Edad mayor a 60 años", "Enfermedades autoinmunes", "Cirugia o radiacion de tiroides", "Antecedentes familiares", "Tratamiento con litio o amiodarona"],
        "lifestyle_tips": [
            "Tomar la levotiroxina SIEMPRE en ayunas, 30-60 min antes de comer",
            "No tomar levotiroxina con cafe, leche, calcio ni hierro",
            "Realizar controles de TSH cada 6-12 meses",
            "No cambiar de marca de levotiroxina sin consultar al medico",
            "Mantener una dieta equilibrada (no es necesario evitar yodo en la mayoria de casos)",
            "Reportar sintomas nuevos al medico (pueden indicar ajuste de dosis)"
        ],
        "related_meds": ["levotiroxina"]
    },
    "gastritis": {
        "name": "Gastritis / Reflujo Gastroesofagico",
        "description": "La gastritis es la inflamacion del revestimiento del estomago. El reflujo gastroesofagico (ERGE) ocurre cuando el acido del estomago sube hacia el esofago. Ambas condiciones causan dolor, ardor y malestar digestivo. Son muy comunes y generalmente tratables.",
        "organs": [
            {"name": "Estomago", "icon": "stomach", "description": "Inflamacion de la mucosa gastrica que causa dolor, ardor, nauseas y sensacion de plenitud. Puede progresar a ulceras si no se trata."},
            {"name": "Esofago", "icon": "esophagus", "description": "El reflujo de acido irrita el esofago causando ardor (pirosis). El reflujo cronico puede causar esofago de Barrett, una condicion pre-cancerosa."},
            {"name": "Garganta", "icon": "throat", "description": "El acido puede llegar a la garganta causando tos cronica, ronquera, y sensacion de nudo en la garganta."}
        ],
        "risk_factors": ["Uso prolongado de antiinflamatorios (AINE)", "Infeccion por H. pylori", "Estres cronico", "Tabaquismo", "Consumo excesivo de alcohol", "Comidas picantes/grasas en exceso", "Obesidad"],
        "lifestyle_tips": [
            "Comer porciones pequeñas y frecuentes",
            "No acostarse hasta 2-3 horas despues de comer",
            "Elevar la cabecera de la cama 15cm",
            "Evitar alimentos que empeoran los sintomas (cafe, alcohol, picante, chocolate, citricos)",
            "No fumar",
            "Mantener un peso saludable",
            "Manejar el estres"
        ],
        "related_meds": ["omeprazol"]
    },
    "colesterol": {
        "name": "Colesterol Alto (Dislipidemia)",
        "description": "La dislipidemia es la elevacion del colesterol y/o trigliceridos en sangre. El colesterol LDL alto ('malo') se deposita en las paredes de las arterias formando placas que las estrechan (aterosclerosis), aumentando el riesgo de infarto y ACV. Generalmente no tiene sintomas.",
        "organs": [
            {"name": "Arterias", "icon": "artery", "description": "Las placas de colesterol estrechan las arterias (aterosclerosis), reduciendo el flujo sanguineo. Pueden romperse y causar coagulos que bloquean completamente la arteria."},
            {"name": "Corazon", "icon": "heart", "description": "La enfermedad coronaria por colesterol es la causa numero 1 de muerte en el mundo. Las arterias coronarias estrechadas causan angina e infarto."},
            {"name": "Cerebro", "icon": "brain", "description": "Si una placa bloquea una arteria cerebral, se produce un ACV (accidente cerebrovascular). El colesterol alto duplica el riesgo de ACV."}
        ],
        "risk_factors": ["Dieta alta en grasas saturadas", "Sedentarismo", "Obesidad", "Tabaquismo", "Diabetes", "Antecedentes familiares", "Edad (hombres >45, mujeres >55)"],
        "lifestyle_tips": [
            "Reducir grasas saturadas (carnes rojas, lacteos enteros, fritos)",
            "Aumentar fibra (avena, frutas, verduras, legumbres)",
            "Realizar 30 min de ejercicio aerobico 5 dias por semana",
            "Mantener un peso saludable",
            "No fumar (el tabaco baja el colesterol bueno HDL)",
            "Controlar colesterol en sangre cada 6-12 meses"
        ],
        "related_meds": ["atorvastatina"]
    },
    "anemia": {
        "name": "Anemia Ferropenica",
        "description": "La anemia ferropenica ocurre cuando el cuerpo no tiene suficiente hierro para producir hemoglobina, la proteina que transporta oxigeno en los globulos rojos. Sin suficiente hemoglobina, los tejidos y organos no reciben el oxigeno que necesitan. Es la deficiencia nutricional mas comun en el mundo.",
        "organs": [
            {"name": "Sangre", "icon": "blood", "description": "Los globulos rojos son mas pequeños y palidos de lo normal (microciticos hipocromicos). La capacidad de transportar oxigeno se reduce significativamente."},
            {"name": "Corazon", "icon": "heart", "description": "El corazon trabaja mas para compensar la falta de oxigeno: taquicardia, palpitaciones, y en casos severos insuficiencia cardiaca."},
            {"name": "Cerebro", "icon": "brain", "description": "Fatiga extrema, dificultad para concentrarse, mareos, dolor de cabeza. En niños afecta el desarrollo cognitivo."},
            {"name": "Piel y mucosas", "icon": "skin", "description": "Palidez en piel, uñas quebradizas y en forma de cuchara (coiloniquia), caida de cabello, lengua inflamada y fisuras en comisuras labiales."}
        ],
        "risk_factors": ["Menstruacion abundante", "Embarazo", "Dieta pobre en hierro", "Sangrado digestivo cronico", "Enfermedad celiaca", "Donacion frecuente de sangre", "Vegetarianismo/veganismo sin suplementacion"],
        "lifestyle_tips": [
            "Tomar el hierro con jugo de naranja o vitamina C (mejora la absorcion)",
            "NO tomar hierro con leche, cafe, te ni calcio (inhiben absorcion)",
            "Incluir carnes rojas, legumbres, espinaca y frutos secos en la dieta",
            "Separar el hierro al menos 2 horas de otros medicamentos",
            "Controlar hemoglobina y ferritina cada 3 meses durante el tratamiento",
            "Las heces pueden tornarse oscuras — es normal con suplemento de hierro"
        ],
        "related_meds": ["hierro"]
    }
}

@app.get("/api/diseases")
def get_diseases(user=Depends(get_current_user)):
    """Returns disease info relevant to user's medications."""
    with get_db() as db:
        meds = db.execute("SELECT name FROM medications WHERE user_id=? AND active=1", (user["id"],)).fetchall()

    med_names = [m["name"].lower().strip() for m in meds]
    result = []
    seen = set()

    for disease_key, disease in DISEASE_DB.items():
        for related_med in disease.get("related_meds", []):
            if related_med in med_names and disease_key not in seen:
                seen.add(disease_key)
                result.append(disease)

    return result


# ============================================================
# ROUTES — TREATMENT INFO (medical data)
# ============================================================
TREATMENT_DB = {
    "omeprazol": {
        "drug": "Omeprazol",
        "condition": "Reflujo gastroesofagico / Gastritis / Ulcera peptica",
        "purpose": "El omeprazol es un inhibidor de la bomba de protones (IBP). Reduce la produccion de acido en el estomago. Se utiliza para tratar el reflujo gastroesofagico (ERGE), ulceras gastricas y duodenales, sindrome de Zollinger-Ellison, y para proteger el estomago cuando se toman antiinflamatorios (AINE) de forma prolongada. Tambien se usa en combinacion con antibioticos para erradicar la bacteria Helicobacter pylori.",
        "if_not_taken": "Si olvidas una dosis, los sintomas de acidez, ardor estomacal o reflujo pueden reaparecer o empeorar. En tratamientos para ulceras, la omision prolongada de dosis puede retrasar la cicatrizacion o provocar recaidas. Si estas en tratamiento de erradicacion de H. pylori, saltear dosis puede reducir la eficacia del tratamiento antibiotico.",
        "how_to_take": "Tomar en ayunas, 30 minutos antes del desayuno. Tragar la capsula entera con un vaso de agua, sin masticar ni triturar. Si tenes dificultad para tragar capsulas, se puede abrir y mezclar el contenido con una cucharada de compota de manzana (no masticar los granulos). No tomar con leche ni con antiacidos de forma simultanea.",
        "side_effects": "Los efectos secundarios mas comunes son: dolor de cabeza, nauseas, diarrea, dolor abdominal, estreñimiento y flatulencia. A largo plazo (mas de 1 año), puede reducir la absorcion de magnesio, calcio y vitamina B12. En tratamientos prolongados, consultar con el medico sobre suplementacion. Efectos raros pero graves: reacciones alergicas, fracturas oseas, infeccion por Clostridioides difficile.",
        "other_forms": "Capsulas (10mg, 20mg, 40mg), comprimidos con cubierta enterica, suspension oral, polvo para solucion inyectable (uso hospitalario). Tambien existe como comprimidos bucodispersables (MUPS) que se disuelven en la boca para pacientes con dificultad para tragar.",
        "inventory_unit": "capsulas",
        "missed_dose": "Si te olvidaste de tomar la dosis de la mañana y todavia no almorzaste, tomala apenas te acuerdes. Si ya paso mucho tiempo y estas cerca de la siguiente dosis, saltea la olvidada y segui con el horario habitual. NUNCA tomes dosis doble para compensar. Si olvidas dosis frecuentemente, considera poner una alarma o dejar el medicamento junto al cepillo de dientes."
    },
    "ibuprofeno": {
        "drug": "Ibuprofeno",
        "condition": "Dolor / Inflamacion / Fiebre",
        "purpose": "El ibuprofeno es un antiinflamatorio no esteroideo (AINE). Actua bloqueando la produccion de prostaglandinas, sustancias que causan inflamacion, dolor y fiebre. Se utiliza para tratar dolores musculares, articulares, dentales, menstruales, cefaleas, dolor postquirurgico, artritis reumatoide, osteoartritis y para reducir la fiebre.",
        "if_not_taken": "Si olvidas una dosis, el dolor o la inflamacion pueden reaparecer o intensificarse. En tratamientos cronicos (artritis), la omision de dosis puede provocar brotes de dolor e inflamacion articular. No hay riesgo de efecto rebote peligroso, pero el malestar puede volver.",
        "how_to_take": "Tomar SIEMPRE con comida o inmediatamente despues de comer para proteger el estomago. Tragar con un vaso lleno de agua. No acostarse durante al menos 10 minutos despues de tomar la dosis. Respetar el intervalo minimo de 6-8 horas entre dosis. No exceder 1200mg diarios sin indicacion medica (3 comprimidos de 400mg).",
        "side_effects": "Efectos comunes: nauseas, dolor de estomago, indigestion, mareos. Puede irritar la mucosa gastrica y causar ulceras con uso prolongado. Puede aumentar levemente la presion arterial. Efectos raros pero graves: sangrado gastrointestinal (heces negras, vomito con sangre), reacciones alergicas, problemas renales. No combinar con alcohol. Precaucion en mayores de 65 años.",
        "other_forms": "Comprimidos (200mg, 400mg, 600mg), capsulas blandas, suspension oral (para niños, 100mg/5ml), granulado efervescente, gel topico (5%), parches transdermicos, supositorios. La forma topica (gel) tiene menos efectos secundarios gastrointestinales.",
        "inventory_unit": "comprimidos",
        "missed_dose": "Tomala apenas te acuerdes, siempre con comida. Si falta poco para la siguiente dosis (menos de 2 horas), saltea la olvidada. NUNCA tomes dosis doble. El ibuprofeno actua durante 6-8 horas, asi que una dosis olvidada significa un periodo sin cobertura analgesica pero no es peligroso."
    },
    "vitamina d": {
        "drug": "Vitamina D (Colecalciferol)",
        "condition": "Deficit de vitamina D / Salud osea / Prevencion de osteoporosis",
        "purpose": "La vitamina D es esencial para la absorcion de calcio en el intestino y la mineralizacion de los huesos. Su deficit esta asociado a debilidad osea (osteoporosis, osteomalacia), debilidad muscular, mayor riesgo de fracturas, fatiga y alteraciones del sistema inmunologico. Se suplementa cuando los niveles en sangre estan bajos (menos de 30 ng/mL) o como prevencion en personas con poca exposicion solar.",
        "if_not_taken": "Saltear dosis ocasionales no tiene consecuencias inmediatas porque la vitamina D se acumula en el cuerpo. Sin embargo, la omision frecuente o prolongada puede llevar a deficit, con consecuencias como: dolor oseo, debilidad muscular, mayor riesgo de fracturas, fatiga cronica y depresion estacional. En personas con osteoporosis, mantener niveles adecuados es critico.",
        "how_to_take": "Tomar con el desayuno o la comida principal, ya que la vitamina D es liposoluble y se absorbe mejor con grasas. Idealmente acompañar con alimentos que contengan algo de grasa (tostada con manteca, frutos secos, yogur entero). Puede tomarse en cualquier momento del dia, pero es mas facil no olvidarla si se asocia a una comida fija.",
        "side_effects": "En dosis habituales (400-2000 UI/dia) los efectos secundarios son muy raros. En sobredosis prolongada (mas de 4000 UI/dia sin control medico): hipercalcemia (exceso de calcio en sangre) con nauseas, vomitos, debilidad, confulsion, calculos renales. Siempre respetar la dosis indicada por el medico. Controlar niveles en sangre periodicamente.",
        "other_forms": "Gotas orales (cada gota suele ser 400 UI), capsulas blandas (1000 UI, 2000 UI, 5000 UI, 50000 UI), ampollas bebibles (dosis semanal o mensual de 25000-100000 UI), comprimidos masticables, spray sublingual. Las ampollas de dosis alta se usan para correcciones rapidas de deficit bajo supervision medica.",
        "inventory_unit": "capsulas",
        "missed_dose": "Si te olvidaste hoy, tomala mañana con normalidad. NO dupliques la dosis. Como la vitamina D se acumula, un dia sin tomarla no afecta significativamente tus niveles. Si olvidas frecuentemente, considera las presentaciones semanales o mensuales (ampollas) que son mas faciles de recordar."
    },
    "enalapril": {
        "drug": "Enalapril",
        "condition": "Hipertension arterial / Insuficiencia cardiaca",
        "purpose": "El enalapril es un inhibidor de la enzima convertidora de angiotensina (IECA). Relaja los vasos sanguineos y reduce la presion arterial. Se usa para tratar la hipertension, la insuficiencia cardiaca congestiva, y para proteger los riñones en pacientes con diabetes. Reduce el riesgo de infarto, ACV y complicaciones cardiovasculares.",
        "if_not_taken": "Saltear dosis de enalapril puede causar un aumento brusco de la presion arterial (efecto rebote). La hipertension no controlada es peligrosa: aumenta el riesgo de infarto de miocardio, accidente cerebrovascular (ACV), daño renal y daño ocular. Es uno de los medicamentos que NO se debe olvidar. En insuficiencia cardiaca, la omision puede provocar acumulacion de liquidos y empeoramiento de los sintomas.",
        "how_to_take": "Tomar a la misma hora todos los dias, con o sin comida. La consistencia horaria es mas importante que el momento del dia. Muchos medicos recomiendan tomarlo por la noche porque la presion arterial sube naturalmente por la mañana. Tragar con agua. No tomar con suplementos de potasio ni sustitutos de sal (contienen potasio). Evitar alcohol (potencia el efecto hipotensor).",
        "side_effects": "El efecto secundario mas caracteristico es la tos seca persistente (10-15% de pacientes). Si la tos es muy molesta, el medico puede cambiar a un ARA-II (losartan, valsartan). Otros efectos: mareos (especialmente al levantarse rapido), fatiga, dolor de cabeza. Efectos raros pero graves: angioedema (hinchazon de cara/lengua — ir a urgencias inmediatamente), hiperpotasemia, deterioro de funcion renal. Controlar presion y funcion renal periodicamente.",
        "other_forms": "Comprimidos (5mg, 10mg, 20mg). Tambien existe la combinacion enalapril + hidroclorotiazida (diuretico) en un solo comprimido para pacientes que necesitan ambos. No existe en forma liquida comercial, pero se puede preparar en farmacia magistral para pacientes que no pueden tragar comprimidos.",
        "inventory_unit": "comprimidos",
        "missed_dose": "Tomala apenas te acuerdes, EXCEPTO si falta menos de 6 horas para la siguiente dosis. En ese caso, saltea la olvidada y segui el horario normal. NUNCA tomes dosis doble — puede causar hipotension severa (mareos, desmayo). Si olvidaste mas de un dia, retoma el tratamiento pero avisale a tu medico. Este medicamento requiere toma diaria consistente."
    },
    "melatonina": {
        "drug": "Melatonina",
        "condition": "Insomnio / Trastornos del ritmo circadiano",
        "purpose": "La melatonina es una hormona que el cuerpo produce naturalmente cuando oscurece, señalando al cerebro que es hora de dormir. Como suplemento, se usa para tratar el insomnio, el jet lag, trastornos del ritmo circadiano (personas que se duermen muy tarde), y para mejorar la calidad del sueño en adultos mayores (que producen menos melatonina). No es un sedante — ayuda a regular el ciclo de sueño.",
        "if_not_taken": "No hay consecuencias medicas graves por saltear una dosis. Simplemente es posible que tardes mas en conciliar el sueño esa noche. La melatonina no genera dependencia ni efecto rebote significativo. Si no la tomas un dia, tu cuerpo sigue produciendo su propia melatonina (aunque en menor cantidad si tenes deficit).",
        "how_to_take": "Tomar 30-60 minutos ANTES de acostarte. Es fundamental tomarla siempre a la misma hora para regular el ritmo circadiano. Tomarla con la luz baja o apagada (la luz brillante inhibe su efecto). No usar pantallas (celular, TV) despues de tomarla. Tragar con un poco de agua. No tomar con alcohol (interfiere con el sueño). Empezar con la dosis mas baja (0.5-1mg) y subir solo si es necesario.",
        "side_effects": "Es generalmente muy segura. Efectos posibles: somnolencia matutina residual (especialmente con dosis altas), dolor de cabeza leve, mareos, nauseas. En raras ocasiones: sueños vividos o pesadillas. No manejar ni operar maquinaria despues de tomarla. No recomendada durante embarazo/lactancia sin consulta medica. Puede interactuar con anticoagulantes, antidepresivos y medicamentos para la diabetes.",
        "other_forms": "Comprimidos de liberacion inmediata (0.5mg, 1mg, 3mg, 5mg), comprimidos de liberacion prolongada (2mg — para mantener el sueño toda la noche), gotas sublinguales (absorcion mas rapida), gomitas masticables, spray oral. La liberacion prolongada es mejor para quienes se despiertan a mitad de la noche. La liberacion inmediata es mejor para quienes tardan en dormirse.",
        "inventory_unit": "comprimidos",
        "missed_dose": "Si te olvidaste y ya estas en la cama, podes tomarla en ese momento siempre que falten al menos 6 horas para levantarte. Si ya es muy tarde o ya te dormiste, simplemente saltea esa noche. No tomes dosis doble la noche siguiente. No pasa nada por un dia sin melatonina."
    }
}

@app.get("/api/treatments")
def get_treatments(user=Depends(get_current_user)):
    """Returns treatment info for user's active medications, matched against the drug database."""
    with get_db() as db:
        meds = db.execute("SELECT * FROM medications WHERE user_id=? AND active=1", (user["id"],)).fetchall()

    result = []
    for med in meds:
        med_dict = dict(med)
        name_lower = med["name"].lower().strip()
        info = TREATMENT_DB.get(name_lower)
        if info:
            med_dict["treatment_info"] = info
        else:
            med_dict["treatment_info"] = None
        result.append(med_dict)

    return result


# ============================================================
# STATIC FILES
# ============================================================
static_dir = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(static_dir, exist_ok=True)

@app.get("/")
def index():
    return FileResponse(os.path.join(static_dir, "index.html"))

@app.get("/shared/{share_token}")
def shared_page(share_token: str):
    return FileResponse(os.path.join(static_dir, "shared.html"))

app.mount("/static", StaticFiles(directory=static_dir), name="static")

# ============================================================
# RUN
# ============================================================
if __name__ == "__main__":
    import uvicorn
    print("\n  PillTracker corriendo en http://localhost:8000\n")
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=port == 8000)
