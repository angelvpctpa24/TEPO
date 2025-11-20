from flask import Flask, render_template, request, redirect, url_for, session, abort
from flask_bcrypt import Bcrypt
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

app = Flask(__name__)
app.secret_key = 'clave_secreta'
bcrypt = Bcrypt(app)

# Conexión MongoDB
uri = "mongodb+srv://keniarcctpa:topitos@tepo.y4anhg9.mongodb.net/?appName=TEPO"
client = MongoClient(uri, server_api=ServerApi('1'))

try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(e)

db = client.bdtepo


# ------------------------- INDEX - REDIRECCIÓN AUTOMÁTICA ------------------------

@app.route('/')
def index():
    return render_template('index.html')


# ------------------------- INICIO DE SESIÓN GENERAL ------------------------------

@app.route('/iniciar-sesion')
def inise():
    return render_template('inise.html')


# ------------------------- INICIO DE SESIÓN ADMIN ------------------------------

@app.route('/admin-login')
def admin_login():
    return render_template('inia.html')


# ------------------------- LOGIN PROCESO -----------------------------------------

@app.route('/login', methods=['POST'])
def login():
    telefono = request.form['telefono']
    password = request.form['password']

    usuario = db.usuarios.find_one({'telefono': telefono})

    if usuario and bcrypt.check_password_hash(usuario['password'], password):
        session['telefono'] = telefono
        session['rol'] = usuario['rol']

        # ADMIN
        if usuario['rol'] == 'admin':
            return redirect('/admin-panel')

        # TRANSPORTISTA (lo mando igual al panel admin por ahora)
        if usuario['rol'] == 'transportista':
            return redirect('/admin-panel')

        # ESTUDIANTE O ENCARGADO - DEPENDE DEL SERVICIO
        servicio_transporte = usuario.get('servicio_transporte')

        if servicio_transporte == 'mg':
            return redirect('/mg')
        elif servicio_transporte == 'pdd':
            return redirect('/pdd')
        elif servicio_transporte == 'roca':
            return redirect('/roca')
        else:
            return "Servicio desconocido"

    return "Credenciales incorrectas"


# ------------------------------- PÁGINAS DE SERVICIO ------------------------------

@app.route('/mg')
def mg():
    if 'rol' not in session or session['rol'] not in ['estudiante', 'encargado']:
        return abort(403)
    return render_template('mg.html')

@app.route('/pdd')
def pdd():
    if 'rol' not in session or session['rol'] not in ['estudiante', 'encargado']:
        return abort(403)
    return render_template('pdd.html')

@app.route('/roca')
def roca():
    if 'rol' not in session or session['rol'] not in ['estudiante', 'encargado']:
        return abort(403)
    return render_template('roca.html')


# --------------------------- PANEL ADMIN ------------------------------------

@app.route('/admin-panel')
def admin_panel():
    if 'rol' not in session or session['rol'] not in ['admin', 'transportista']:
        return abort(403)
    return render_template('admin.html')


# --------------------------- SELECTOR DE REGISTRO --------------------------------

@app.route('/registro')
def registro():
    return render_template('select_register.html')


# --------------------------- REGISTRO ESTUDIANTE ---------------------------------

@app.route('/registro/estudiante', methods=['GET', 'POST'])
def registro_estudiante():
    if request.method == 'POST':
        data = {
            'rol': 'estudiante',
            'telefono': request.form['telefono'],
            'nombre': request.form['nombre'],
            'apellido': request.form['apellido'],
            'numero': request.form['numero'],
            'servicio_transporte': request.form['servicio_transporte'],
            'password': bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        }
        db.usuarios.insert_one(data)
        return redirect('/iniciar-sesion')
    return render_template('estre.html')


# --------------------------- REGISTRO PADRE (ENCARGADO) ---------------------------

@app.route('/registro/padre', methods=['GET', 'POST'])
def registro_padres():
    if request.method == 'POST':
        data = {
            'rol': 'encargado',
            'telefono': request.form['telefono'],
            'nombre': request.form['nombre'],
            'apellido': request.form['apellido'],
            'numero': request.form['numero'],
            'servicio_transporte': request.form['servicio_transporte'],
            'password': bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        }
        db.usuarios.insert_one(data)
        return redirect('/iniciar-sesion')
    return render_template('padresre.html')


# --------------------------- REGISTRO ADMIN/TRANSPORTISTA -------------------------

@app.route('/registro/admin', methods=['GET', 'POST'])
def registro_admin():
    if request.method == 'POST':
        data = {
            'rol': 'admin',
            'telefono': request.form['telefono'],
            'nombre': request.form['nombre'],
            'apellido': request.form['apellido'],
            'numero': request.form['numero'],
            'servicio_transporte': None,
            'password': bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        }
        db.usuarios.insert_one(data)
        return redirect('/admin-login')
    return render_template('adminre.html')


# -------------------- ERROR 403 --------------------------------------

@app.errorhandler(403)
def acceso_prohibido(error):
    return "Acceso no autorizado", 403


if __name__ == '__main__':
    app.run(debug=True)