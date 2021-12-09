from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity
import mysql.connector

db = mysql.connector.connect(
    host = 'academia.c1mebdhdxytu.us-east-1.rds.amazonaws.com',
    user = 'p5',
    password = 'IMpERchAMbucEnES',
    database = 'p5',
    port = 3306
)

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "ELPRRITONICKOSEMURO"
jwt = JWTManager(app)
CORS(app)
bcrypt = Bcrypt(app)

@app.route('/')
def index():
    return "Hola mundo"

######### LOGIN #########

@app.post('/login')
def login():
    email = request.json.get("email", None)
    password = request.json.get("password", None)

    cursor = db.cursor(dictionary=True, buffered=True)

    cursor.execute('SELECT * FROM usuario WHERE email = %s and contrasena = %s', (email, password,))

    usuario = cursor.fetchone()
    
    if not usuario:
        return jsonify({
            "message":"Usuario no existe"
        })
    
    pass_correct = bcrypt.check_password_hash(usuario[2], password)
            if pass_correct:
                token = create_access_token(identity=usuario['id'])
                return jsonify({
                    "token": token
                })
            return jsonify({"message": "credenciales invalidas"})

######### USUARIOS #########
######### REGISTER #########

@app.post('/usuarios')
def crearUsuario():
    datos = request.json
    
    cursor = db.cursor()
    print(datos["password"])
    pwd_hash = bcrypt.generate_password_hash(datos['password']).decode('utf-8')


    cursor.execute('''INSERT INTO usuario(nombres, email, contrasena)
        VALUE(%s, %s, %s)''', (
        datos['nombres'],
        datos['email'],
        pwd_hash,
    ))

    db.commit()

    return jsonify({
        "mensaje": "Usuario almacenado correctamente"
    })

@app.get('/usuarios')
@jwt_required()
def listarUsuarios():
    cursor = db.cursor(dictionary=True)

    cursor.execute('SELECT * FROM usuario')

    usuarios = cursor.fetchall()

    return jsonify(usuarios)

@app.get('/usuarios/<id>')
@jwt_required()
def obtenerUnUsuario(id):
    cursor = db.cursor(dictionary=True)
    cursor.execute('SELECT * FROM usuario WHERE id=%s', (id,))

    usuario = cursor.fetchone()

    return jsonify(usuario)

@app.put('/usuarios/<id>')
@jwt_required()
def actualizarUsuario(id):
    usuario = get_jwt_identity()

    datos = request.json
    cursor = db.cursor()

    cursor.execute('UPDATE usuario SET nombres=%s, email=%s WHERE id=%s',(
        datos['nombres'],
        datos['email'],
        usuario
    ))

    db.commit()

    return jsonify({
        "mensaje": "Usuario actualizado correctamente"
    })

@app.delete('/usuarios/<id>')
@jwt_required()
def eliminarUsuario(id):
    cursor = db.cursor()

    cursor.execute('DELETE FROM usuario WHERE id=%s', (id,))
    db.commit()

    return jsonify({
        "mensaje":"Usuario eliminado correctamente"
    })

@app.post('/encuestas')
@jwt_required()
def crearEncuesta():
    usuario = get_jwt_identity()
    datos = request.json
    cursor = db.cursor()

    cursor.execute('''INSERT INTO encuesta(nombre, usuario_id, descripcion)
        VALUE(%s, %s, %s)''', (
        datos['nombre'],
        usuario,
        datos['descripcion'],
    ))

    db.commit()

    return jsonify({
        "mensaje": "Encuesta almacenada correctamente"
    })

@app.get('/encuestas')
@jwt_required()
def listarEncuestas():
    cursor = db.cursor(dictionary=True)

    cursor.execute('SELECT * FROM encuesta')

    encuestas = cursor.fetchall()

    return jsonify(encuestas)

@app.get('/encuestas/<id>')
@jwt_required()
def obtenerUnaEncuesta(id):
    cursor = db.cursor(dictionary=True)

    cursor.execute('SELECT * FROM encuesta WHERE id=%s', (id,))

    encuesta = cursor.fetchone()

    return jsonify(encuesta)

@app.put('/encuestas/<id>')
@jwt_required()
def actualizarEncuesta(id):
    usuario = get_jwt_identity()
    datos = request.json

    cursor = db.cursor()

    cursor.execute('UPDATE encuesta SET nombre=%s, usuario_id=%s, descripcion=%s WHERE id=%s',(
        datos['nombre'],
        usuario,
        datos['descripcion'],
        id
    ))

    db.commit()

    return jsonify({
        "mensaje": "Encuesta actualizada correctamente"
    })

@app.delete('/encuestas/<id>')
@jwt_required()
def eliminarEncuesta(id):
    cursor = db.cursor()

    cursor.execute('DELETE FROM encuesta WHERE id=%s', (id,))
    db.commit()

    return jsonify({
        "mensaje":"Encuesta eliminada correctamente"
    })

######### SECCIONES #########

@app.post('/secciones')
@jwt_required()
def crearSeccion():
    datos = request.json
    cursor = db.cursor()

    cursor.execute('''INSERT INTO seccion(nombre, encuesta_id)
        VALUE(%s, %s)''', (
        datos['nombre'],
        datos['encuesta_id'],
    ))

    db.commit()

    return jsonify({
        "mensaje": "Seccion almacenada correctamente"
    })

@app.get('/secciones')
@jwt_required()
def listarSecciones():
    cursor = db.cursor(dictionary=True)

    cursor.execute('SELECT * FROM seccion')

    seccion = cursor.fetchall()

    return jsonify(seccion)

@app.get('/secciones/<id>')
@jwt_required()
def obtenerUnaSeccion(id):
    cursor = db.cursor(dictionary=True)

    cursor.execute('SELECT * FROM seccion WHERE id=%s', (id,))

    seccion = cursor.fetchone()

    return jsonify(seccion)

@app.put('/secciones/<id>') #alt + 60 < | alt + 62 >
@jwt_required()
def actualizarSeccion(id):
    datos = request.json

    cursor = db.cursor()

    cursor.execute('UPDATE seccion SET nombre=%s, encuesta_id=%s WHERE id=%s',(
        datos['nombre'],
        datos['encuesta_id'],
        id
    ))

    db.commit()

    return jsonify({
        "mensaje": "Seccion actualizada correctamente"
    })

@app.delete('/secciones/<id>')
@jwt_required()
def eliminarSeccion(id):
    cursor = db.cursor()

    cursor.execute('DELETE FROM seccion WHERE id=%s', (id,))
    db.commit()

    return jsonify({
        "mensaje":"Seccion eliminada correctamente"
    })

######### PREGUNTAS #########

@app.post('/preguntas')
@jwt_required()
def crearPregunta():
    datos = request.json
    
    cursor = db.cursor()

    cursor.execute('''INSERT INTO pregunta(pregunta, seccion_id, tipoPregunta)
        VALUE(%s, %s, %s)''', (
        datos['pregunta'],
        datos['seccion_id'],
        datos['tipoPregunta'],
    ))

    db.commit()

    return jsonify({
        "mensaje": "Pregunta almacenada correctamente"
    })

@app.get('/preguntas')
@jwt_required()
def listarPreguntas():
    cursor = db.cursor(dictionary=True)

    cursor.execute('SELECT * FROM pregunta')

    pregunta = cursor.fetchall()

    return jsonify(pregunta)

@app.get('/preguntas/<id>')
@jwt_required()
def obtenerUnaPregunta(id):
    cursor = db.cursor(dictionary=True)

    cursor.execute('SELECT * FROM pregunta WHERE id=%s', (id,))

    pregunta = cursor.fetchone()

    return jsonify(pregunta)

@app.put('/preguntas/<id>')
@jwt_required()
def actualizarPregunta(id):
    datos = request.json

    cursor = db.cursor()

    cursor.execute('UPDATE pregunta SET pregunta=%s, seccion_id=%s, tipoPregunta=%s WHERE id=%s',(
        datos['pregunta'],
        datos['seccion_id'],
        datos['tipoPregunta'],
        id
    ))

    db.commit()

    return jsonify({
        "mensaje": "Pregunta actualizada correctamente"
    })

@app.delete('/preguntas/<id>')
@jwt_required()
def eliminarPregunta(id):
    cursor = db.cursor()

    cursor.execute('DELETE FROM pregunta WHERE id=%s', (id,))
    db.commit()

    return jsonify({
        "mensaje":"Pregunta eliminada correctamente"
    })

######### RESPUESTAS #########

@app.post('/respuestas')
@jwt_required()
def crearRespuesta():
    datos = request.json
    
    cursor = db.cursor()

    cursor.execute('''INSERT INTO respuesta(respuesta, usuario_id, pregunta_id)
        VALUE(%s, %s, %s)''', (
        datos['respuesta'],
        datos['usuario_id'],
        datos['pregunta_id'],
    ))

    db.commit()

    return jsonify({
        "mensaje": "Respuesta almacenada correctamente"
    })

@app.get('/respuestas')
@jwt_required()
def listarRespuestas():
    cursor = db.cursor(dictionary=True)

    cursor.execute('SELECT * FROM respuesta')

    respuesta = cursor.fetchall()

    return jsonify(respuesta)

@app.get('/respuestas/<id>')
@jwt_required()
def obtenerUnaRespuesta(id):
    cursor = db.cursor(dictionary=True)

    cursor.execute('SELECT * FROM respuesta WHERE id=%s', (id,))

    respuesta = cursor.fetchone()

    return jsonify(respuesta)

@app.put('/respuestas/<id>')
@jwt_required()
def actualizarRespuesta(id):
    usuario = get_jwt_identity()
    datos = request.json

    cursor = db.cursor()

    cursor.execute('UPDATE respuesta SET respuesta=%s, usuario_id=%s, pregunta_id=%s WHERE id=%s',(
        datos['respuesta'],
        usuario,
        datos['pregunta_id'],
        id
    ))

    db.commit()

    return jsonify({
        "mensaje": "Respuesta actualizada correctamente"
    })

@app.delete('/respuestas/<id>')
@jwt_required()
def eliminarRespuesta(id):

    cursor = db.cursor()

    cursor.execute('DELETE FROM respuesta WHERE id=%s', (id,))
    db.commit()

    return jsonify({
        "mensaje":"Respuesta eliminada correctamente"
    })

if __name__ == "__main__":
    app.run(debug=True)
