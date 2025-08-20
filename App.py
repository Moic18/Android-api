############# API SymptoTrack (PLANO) #############
# Requisitos:
#   pip install Flask flask-mysqldb flask-cors
#
# Esquema esperado en MySQL (symptotrack):
#   - users(id BIGINT UNSIGNED PK, first_name, last_name, phone, email, username, password, created_at)
#   - doctors(doctor_id INT PK, first_name, last_name, email, username, password)
#   - symptom_entries(id, user_id, symptom_name, intensity, entry_date, entry_time, notes, created_at)
#   - doctor_patients(id BIGINT UNSIGNED PK, doctor_id INT, patient_id BIGINT UNSIGNED, note, fecha, created_at)
#
# Nota: ESTE BACKEND ES SOLO PARA PRUEBAS (passwords en TEXTO PLANO)

from flask import Flask, request, jsonify
from flask_mysqldb import MySQL
from flask_cors import CORS
import re
from datetime import date

# -----------------------------
# Inicialización
# -----------------------------
app = Flask(__name__)
CORS(app)

# ---- Config MySQL (XAMPP) ----
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''        
app.config['MYSQL_DB'] = 'symptotrack'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
mysql = MySQL(app)

app.secret_key = "change-me-in-production"

# -----------------------------
# Utilidades
# -----------------------------
EMAIL_RE = re.compile(r"[^@]+@[^@]+\.[^@]+")

def get_db():
    return mysql.connection

def required_fields(payload, fields):
    return [f for f in fields if payload.get(f) in (None, "", [])]

def ok(data=None, status=200):
    return jsonify({"ok": True, "data": data}), status

def err(msg, status=400):
    return jsonify({"ok": False, "error": msg}), status

# -----------------------------
# Health
# -----------------------------
@app.get("/")
def health():
    return ok({"service": "SymptoTrack API", "db": app.config['MYSQL_DB']})

# -----------------------------
# AUTH: Usuarios (pacientes) - TEXTO PLANO
# -----------------------------
@app.post("/auth/register_user")
def register_user():
    """
    body: {first_name, last_name, phone, usuario_correo, password}
    - usuario_correo puede ser email o username
    - password se guarda en TEXTO PLANO (solo pruebas)
    """
    payload = request.get_json(silent=True) or {}
    missing = required_fields(payload, ["first_name","last_name","phone","usuario_correo","password"])
    if missing:
        return err(f"Faltan campos: {', '.join(missing)}")

    first_name = payload["first_name"].strip()
    last_name  = payload["last_name"].strip()
    phone      = payload["phone"].strip()
    usuario_correo = payload["usuario_correo"].strip()
    password   = payload["password"]  # TEXTO PLANO

    # Decide si es email o username
    email = usuario_correo.lower() if EMAIL_RE.match(usuario_correo) else None
    username = None if email else usuario_correo

    if username and len(username) < 4:
        return err("El usuario debe tener al menos 4 caracteres")
    if not re.fullmatch(r"\d{7,20}", phone):
        return err("El teléfono debe ser numérico (7-20 dígitos)")

    db = get_db()
    cur = db.cursor()
    try:
        if email:
            cur.execute("SELECT id FROM users WHERE email=%s", (email,))
            if cur.fetchone():
                return err("Correo ya registrado")
        if username:
            cur.execute("SELECT id FROM users WHERE username=%s", (username,))
            if cur.fetchone():
                return err("Usuario ya registrado")

        cur.execute("""
            INSERT INTO users(first_name, last_name, phone, email, username, password)
            VALUES (%s,%s,%s,%s,%s,%s)
        """, (first_name, last_name, phone, email, username, password))
        db.commit()

        return ok({
            "id": cur.lastrowid,
            "first_name": first_name,
            "last_name": last_name,
            "phone": phone,
            "email": email,
            "username": username
        }, status=201)
    except Exception as e:
        db.rollback()
        return err(f"Error insertando usuario: {str(e)}", 500)
    finally:
        cur.close()

@app.post("/auth/login")
def login():
    """
    body: {identifier, password, role?}
      - identifier: email o username
      - role (opcional): 'user' o 'doctor'
    Valida TODO en TEXTO PLANO para users y doctors (modo prueba).
    """
    try:
        payload = request.get_json(silent=True)
        if not payload:
            return err("Body JSON vacío o Content-Type incorrecto (usa application/json)")

        identifier = (payload.get("identifier") or "").strip()
        password = payload.get("password")
        role = (payload.get("role") or "").lower() if payload.get("role") else None

        if not identifier or not password:
            return err("Faltan campos: identifier y password son obligatorios")

        db = get_db()
        cur = None
        try:
            cur = db.cursor()

            # ---- forzar role=user (texto plano) ----
            if role == "user":
                cur.execute("""
                    SELECT id, first_name, last_name, phone, email, username, password
                    FROM users
                    WHERE (LOWER(email)=LOWER(%s) OR LOWER(username)=LOWER(%s))
                    LIMIT 1
                """, (identifier, identifier))
                row = cur.fetchone()
                if not row or row.get("password") != password:
                    return err("Credenciales inválidas (user)", 401)
                return ok({"role": "user", "id": row["id"], "first_name": row["first_name"], "last_name": row["last_name"]})

            # ---- forzar role=doctor (texto plano) ----
            if role == "doctor":
                cur.execute("""
                    SELECT doctor_id, first_name, last_name, email, username, password
                    FROM doctors
                    WHERE (LOWER(email)=LOWER(%s) OR LOWER(username)=LOWER(%s))
                    LIMIT 1
                """, (identifier, identifier))
                row = cur.fetchone()
                if not row or row.get("password") != password:
                    return err("Credenciales inválidas (doctor)", 401)
                return ok({"role": "doctor", "id": row["doctor_id"], "first_name": row["first_name"], "last_name": row["last_name"]})

            # ---- sin role: intenta user y luego doctor (ambos texto plano) ----
            cur.execute("""
                SELECT id, first_name, last_name, phone, email, username, password
                FROM users
                WHERE (LOWER(email)=LOWER(%s) OR LOWER(username)=LOWER(%s))
                LIMIT 1
            """, (identifier, identifier))
            row = cur.fetchone()
            if row and row.get("password") == password:
                return ok({"role": "user", "id": row["id"], "first_name": row["first_name"], "last_name": row["last_name"]})

            cur.execute("""
                SELECT doctor_id, first_name, last_name, email, username, password
                FROM doctors
                WHERE (LOWER(email)=LOWER(%s) OR LOWER(username)=LOWER(%s))
                LIMIT 1
            """, (identifier, identifier))
            row = cur.fetchone()
            if row and row.get("password") == password:
                return ok({"role": "doctor", "id": row["doctor_id"], "first_name": row["first_name"], "last_name": row["last_name"]})

            return err("Credenciales inválidas", 401)
        finally:
            if cur:
                cur.close()

    except Exception as e:
        import traceback, sys
        print("ERROR /auth/login:", e, file=sys.stderr)
        traceback.print_exc()
        return err("Error interno en /auth/login", 500)

# -----------------------------
# AUTH: Doctores (registro simple, TEXTO PLANO)
# -----------------------------
@app.post("/auth/register_doctor")
def register_doctor():
    """
    body: {first_name, last_name, email, username, password}
    - password plano (ej: '0000') para PRUEBAS
    """
    payload = request.get_json(silent=True) or {}
    missing = required_fields(payload, ["first_name", "last_name", "email", "username", "password"])
    if missing:
        return err(f"Faltan campos: {', '.join(missing)}")

    first_name = payload["first_name"].strip()
    last_name  = payload["last_name"].strip()
    email      = payload["email"].strip().lower()
    username   = payload["username"].strip()
    password   = payload["password"]  # plano por ahora

    db = get_db()
    cur = db.cursor()
    try:
        cur.execute("SELECT doctor_id FROM doctors WHERE LOWER(email)=LOWER(%s) OR LOWER(username)=LOWER(%s)",
                    (email, username))
        if cur.fetchone():
            return err("Email o usuario ya existe en doctores")

        cur.execute("""
            INSERT INTO doctors(first_name, last_name, email, username, password)
            VALUES (%s,%s,%s,%s,%s)
        """, (first_name, last_name, email, username, password))
        db.commit()
        return ok({"doctor_id": cur.lastrowid, "first_name": first_name, "last_name": last_name}, status=201)

    except Exception as e:
        db.rollback()
        return err(f"Error insertando doctor: {str(e)}", 500)
    finally:
        cur.close()

# -----------------------------
# Compartir con doctor (tabla doctor_patients)
# -----------------------------
@app.post("/patients/share")
def share_with_doctor():
    """Comparte un paciente con un doctor."""
    cur = None
    try:
        body = request.get_json(silent=True) or {}
        doctor_id  = body.get("doctor_id")
        patient_id = body.get("patient_id")
        note       = body.get("note") or None
        fecha_str  = body.get("fecha")

        if not doctor_id or not patient_id:
            return err("doctor_id y patient_id son obligatorios")

        # Normaliza fecha (si no viene, hoy)
        if fecha_str:
            try:
                y, m, d = map(int, fecha_str.split("-"))
                fecha = date(y, m, d)
            except Exception:
                return err("fecha debe tener formato yyyy-MM-dd")
        else:
            fecha = date.today()

        db = get_db()
        cur = db.cursor()

        # Verifica existencia
        cur.execute("SELECT doctor_id FROM doctors WHERE doctor_id=%s LIMIT 1", (doctor_id,))
        if cur.fetchone() is None:
            return err("doctor_id no existe")

        cur.execute("SELECT id FROM users WHERE id=%s LIMIT 1", (patient_id,))
        if cur.fetchone() is None:
            return err("patient_id no existe")

        # Inserta
        cur.execute("""
            INSERT INTO doctor_patients (doctor_id, patient_id, note, fecha)
            VALUES (%s, %s, %s, %s)
        """, (doctor_id, patient_id, note, fecha))
        db.commit()

        new_id = cur.lastrowid
        return ok({"id": new_id, "doctor_id": doctor_id, "patient_id": patient_id, "fecha": str(fecha)}, status=201)

    except Exception as e:
        import traceback, sys
        print("ERROR /patients/share:", e, file=sys.stderr)
        traceback.print_exc()
        return err(f"DB error: {str(e)}", 500)
    finally:
        if cur:
            cur.close()

@app.get("/doctors/<int:doctor_id>/patients")
def list_patients_for_doctor(doctor_id):
    """Lista pacientes que han compartido con el doctor."""
    cur = None
    try:
        db = get_db()
        cur = db.cursor()

        # Confirmar doctor
        cur.execute("SELECT doctor_id FROM doctors WHERE doctor_id=%s LIMIT 1", (doctor_id,))
        if cur.fetchone() is None:
            return err("doctor_id no existe", 404)

        # Resumen
        cur.execute("""
            SELECT
              dp.patient_id,
              CONCAT(u.first_name, ' ', u.last_name) AS patient_fullname,
              MAX(dp.fecha) AS last_shared_date,
              COUNT(*) AS shares_count
            FROM doctor_patients dp
            JOIN users u ON u.id = dp.patient_id
            WHERE dp.doctor_id = %s
            GROUP BY dp.patient_id, patient_fullname
            ORDER BY last_shared_date DESC, patient_fullname ASC
        """, (doctor_id,))
        rows = cur.fetchall()
        return ok(rows)
    except Exception as e:
        import traceback, sys
        print("ERROR GET /doctors/<id>/patients:", e, file=sys.stderr)
        traceback.print_exc()
        return err("Error interno en /doctors/{id}/patients", 500)
    finally:
        if cur:
            cur.close()

@app.get("/doctors/<int:doctor_id>/patients/<int:patient_id>")
def patient_detail_for_doctor(doctor_id, patient_id):
    """Detalle de un paciente y sus notas/fechas compartidas."""
    cur = None
    try:
        db = get_db()
        cur = db.cursor()

        # Confirmar doctor
        cur.execute("SELECT doctor_id FROM doctors WHERE doctor_id=%s LIMIT 1", (doctor_id,))
        if cur.fetchone() is None:
            return err("doctor_id no existe", 404)

        # Datos del paciente
        cur.execute("""
            SELECT id, first_name, last_name, email, phone, username
            FROM users WHERE id=%s LIMIT 1
        """, (patient_id,))
        patient = cur.fetchone()
        if patient is None:
            return err("patient_id no existe", 404)

        # Notas compartidas a ese doctor
        cur.execute("""
            SELECT id, fecha, note, created_at
            FROM doctor_patients
            WHERE doctor_id=%s AND patient_id=%s
            ORDER BY fecha DESC, id DESC
        """, (doctor_id, patient_id))
        notes = cur.fetchall()

        return ok({"patient": patient, "notes": notes})
    except Exception as e:
        import traceback, sys
        print("ERROR GET /doctors/<id>/patients/<pid>:", e, file=sys.stderr)
        traceback.print_exc()
        return err("Error interno en detalle de paciente", 500)
    finally:
        if cur:
            cur.close()

# -----------------------------
# Síntomas (Registros diarios)
# -----------------------------
@app.post("/symptoms")
def create_symptom():
    """
    body: {user_id, symptom_name, intensity, entry_date, entry_time?, notes?}
    - intensity: 0..10
    - entry_date: 'YYYY-MM-DD'
    - entry_time: 'HH:MM:SS' (opcional)
    """
    payload = request.get_json(silent=True) or {}
    missing = required_fields(payload, ["user_id", "symptom_name", "intensity", "entry_date"])
    if missing:
        return err(f"Faltan campos: {', '.join(missing)}")

    user_id      = payload["user_id"]
    symptom_name = payload["symptom_name"].strip()
    intensity    = int(payload["intensity"])
    entry_date   = payload["entry_date"].strip()
    entry_time   = payload.get("entry_time")
    notes        = payload.get("notes")

    if not (0 <= intensity <= 10):
        return err("intensity debe estar entre 0 y 10")

    db = get_db()
    cur = db.cursor()
    try:
        # verificar usuario existe
        cur.execute("SELECT id FROM users WHERE id=%s", (user_id,))
        if not cur.fetchone():
            return err("user_id no existe")

        cur.execute("""
            INSERT INTO symptom_entries(user_id, symptom_name, intensity, entry_date, entry_time, notes)
            VALUES (%s,%s,%s,%s,%s,%s)
        """, (user_id, symptom_name, intensity, entry_date, entry_time, notes))
        db.commit()
        return ok({"id": cur.lastrowid}, status=201)
    except Exception as e:
        db.rollback()
        return err(f"Error creando registro: {str(e)}", 500)
    finally:
        cur.close()

@app.get("/users/<int:user_id>/symptoms")
def list_symptoms(user_id: int):
    """
    query params:
      - from (YYYY-MM-DD) opcional
      - to   (YYYY-MM-DD) opcional
    """
    date_from = request.args.get("from")
    date_to   = request.args.get("to")

    db = get_db()
    cur = db.cursor()
    try:
        sql = """
            SELECT id, user_id, symptom_name, intensity, entry_date,
                   DATE_FORMAT(entry_time, '%%H:%%i:%%s') AS entry_time, notes, created_at
            FROM symptom_entries
            WHERE user_id=%s
        """
        args = [user_id]
        if date_from:
            sql += " AND entry_date >= %s"
            args.append(date_from)
        if date_to:
            sql += " AND entry_date <= %s"
            args.append(date_to)
        sql += " ORDER BY entry_date DESC, id DESC"

        cur.execute(sql, tuple(args))
        rows = cur.fetchall()
        return ok(rows)
    except Exception as e:
        return err(f"Error listando registros: {str(e)}", 500)
    finally:
        cur.close()

# -----------------------------
# Punto de entrada
# -----------------------------
if __name__ == "__main__":
    # Flask dev server (para pruebas locales)
    app.run(host="0.0.0.0", port=8000, debug=True)
