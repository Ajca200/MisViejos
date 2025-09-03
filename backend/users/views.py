from rest_framework import generics, status
from django.views.decorators.csrf import csrf_exempt
from rest_framework.views import APIView
from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect
from django.db import connection, DatabaseError
from django.urls import reverse
import jwt
from datetime import datetime, timezone
from django.conf import settings
from functools import wraps
import os

def make_access_token(user_dict: dict):
    now = datetime.now(timezone.utc)

    payload = {
        "sub": user_dict["user_id"],   # id del usuario
        "role": user_dict.get("role", "user"),
        "email": user_dict["email"],
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + settings.JWT_ACCESS_TTL).timestamp()),
    }

    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALG)

def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALG])

def jwt_required(view_func):
    @wraps(view_func)
    def _wrapped(request, *args, **kwargs):
        token = request.COOKIES.get("access_token")
        if not token:
            return render(request, 'login.html')
        try:
            payload = decode_token(token)
        except jwt.ExpiredSignatureError:
            return JsonResponse({"detail": "Token expirado"}, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({"detail": "Token inválido"}, status=401)
        request.jwt = payload
        return view_func(request, *args, **kwargs)
    return _wrapped

def obtener_nom_usuario(user_id):
    try:
        with connection.cursor() as cursor:
            cursor.execute(f"SELECT * FROM usuarios_dat.obtener_nombre({user_id})")
            result = cursor.fetchone()

            if result:
                usu_nom = result[0]

                return usu_nom
            else:
                return HttpResponse("<h1>No se han encontrado resultados</h1>")

    except DatabaseError as e:
        return HttpResponse(f"<h1>Error en la BD: {str(e)}</h1>", status=400)

def LoginPage(request):
    return render(request, 'login.html')

def RegisterPage(request):
    return render(request, 'register.html')

@jwt_required
def ConfigurationPage(request):
    return render(request, 'configuracion.html')

@jwt_required
def ProductsPage(request):
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT * FROM obtener_datos_productos()')
            cols = [col[0] for col in cursor.description]
            resultados_productos = [dict(zip(cols, row)) for row in cursor.fetchall()]

            cursor.execute('SELECT * FROM obtener_categorias()')
            resultados_categorias = [dict(zip(cols, row)) for row in cursor.fetchall()]

            return render(request, 'productos_dashboard.html', {"productos": resultados_productos, "categorias": resultados_categorias})
    except DatabaseError as e:
        return HttpResponse(f"<h1>Error en la BD: {str(e)}</h1>", status=400)

@jwt_required
def PedidosPage(request):
    return render(request, 'pedidos.html')

@jwt_required
def UsuariosPage(request):
    return render(request, 'usuarios_admin.html')

@jwt_required
def DomiciliosPage(request):
    return render(request, 'domicilios.html')

def HomePage(request):
    return render(request, 'home.html')

@jwt_required   
def ResumenPage(request):
    token = request.COOKIES.get("access_token")
    if not token:
        return HttpResponse("<h1>No autenticado</h1>", status=401)

    try:
        payload = decode_token(token)
        user_id = payload["sub"]
        user_rol = payload["role"]

        usu_nom = obtener_nom_usuario(user_id)
        if user_rol == 'admin':
            return render(request, 'dashboard_admin.html', {
                'usu_nom': usu_nom,
                'user_rol': user_rol
            })
        else:
            return render(request, 'dashboard_client.html', {
                'usu_nom': usu_nom,
                'user_rol': user_rol
            })

    except jwt.ExpiredSignatureError:
        return HttpResponse("<h1>Token expirado</h1>", status=401)
    except jwt.InvalidTokenError:
        return HttpResponse("<h1>Token inválido</h1>", status=401)

@csrf_exempt
def LoginView(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM usuarios_dat.inicio_sesion(%s, %s)', [email, password])
                result = cursor.fetchone()

                if result:
                    user_id = result[0]   # ID del usuario
                    user_rol = result[1]  # Rol del usuario

                    payload = {
                        "user_id": user_id,
                        "role": user_rol,
                        "email": email
                    }
                    # Generar JWT
                    token = make_access_token(payload)

                    resp = redirect('/users/resumen')
                    resp.set_cookie(
                        "access_token",
                        token,
                        httponly=True,
                        secure=True,     # exige HTTPS en prod
                        samesite="Lax",  # si frontend/backend en mismo dominio
                        path="/",
                        max_age=60*15    # 15 min
                    )
                    return resp

                return HttpResponse("<h1>Error: Credenciales inválidas</h1>", status=401)

        except DatabaseError as e:
            return HttpResponse(f"<h1>Error en la BD: {str(e)}</h1>", status=400)

    return HttpResponse("<h1>Método no permitido</h1>", status=405)

@csrf_exempt
def RegisterView(request):
    if request.method == 'POST':
        name = request.POST.get('nombre')
        lastname = request.POST.get('apellido')
        fn = request.POST.get('fecha_nacimiento') # fecha de nacimiento
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM usuarios_dat.registrar_usuario(%s, %s, %s, %s, %s)', [name, lastname, fn, email, password])

                result = cursor.fetchone()

                if result:
                    user_id = result[0]   # ID del usuario
                    user_rol = result[1]  # Rol del usuario

                    payload = {
                        "user_id": user_id,
                        "role": user_rol,
                        "email": email
                    }
                    # Generar JWT
                    token = make_access_token(payload)

                    resp = redirect('/users/resumen')
                    resp.set_cookie(
                        "access_token",
                        token,
                        httponly=True,
                        secure=True,     # exige HTTPS en prod
                        samesite="Lax",  # si frontend/backend en mismo dominio
                        path="/",
                        max_age=60*15    # 15 min
                    )
                    return resp

                return HttpResponse("<h1>Error: Credenciales inválidas</h1>", status=401)
        except DatabaseError as e:
            return HttpResponse(f"<h1>Error en la BD: {str(e)}</h1>", status=400)

@csrf_exempt
def ActualizarDatosView(request):
    token = request.COOKIES.get("access_token")

    if not token:
        return HttpResponse("<h1>No autenticado</h1>", status=401)
    
    payload = decode_token(token)
    user_id = payload["sub"]

    if request.method == 'POST':
        nombre = request.POST.get('name')
        apellido = request.POST.get('lastname')
        fecha_nacimiento = request.POST.get('fn')

        try:
            with connection.cursor() as cursor:
                cursor.execute('CALL usuarios_dat.actualizar_usuario(%s, %s, %s, %s)', [user_id, nombre, apellido, fecha_nacimiento])

                return JsonResponse({"Exito": "Los Datos han sido actualizados exitosamente"}, status=200)
        except DatabaseError as e:
            return HttpResponse(f"<h1>Error en la BD: {str(e)}</h1>", status=400)
        except Exception as e:
            return HttpResponse(f"<h1>Error en la BD: {str(e)}</h1>", status=500)

    return HttpResponse("<h1>Método no permitido</h1>", status=405)

@jwt_required
def ObtenerDatosActualizables(request):
    if request.method == 'GET':
        token = request.COOKIES.get('access_token')

        if not token:
            return HttpResponse("<h1>No autenticado</h1>", status=401)
        
        payload = decode_token(token)
        user_id = payload["sub"]

        try:
            with connection.cursor() as cursor:
                cursor.execute(f'SELECT * FROM usuarios_dat.obtener_datos_actualizables({user_id})')
                result = cursor.fetchone()

                if result:
                    return JsonResponse({"datos": result}, status=200)
        except DatabaseError as e:
            return HttpResponse(f"<h1>Error en la BD: {str(e)}</h1>", status=400)
        
@csrf_exempt
def RegistrarProductoView(request):
    if request.method == "POST":
        try:
            # === OBTENER DATOS DEL FORM ===
            nombre = request.POST.get("nombre", "").strip()
            categoria_id = request.POST.get("cat_id")
            descripcion = request.POST.get("descripcion", "").strip()
            precio = request.POST.get("precio")
            stock = request.POST.get("stock")

            imagen = request.FILES.get("imagen")  # Puede ser None
            ruta_imagen = None

            # === VALIDACIONES BÁSICAS ===
            if not nombre or not categoria_id or not precio or stock is None:
                return JsonResponse({"detail": "Campos obligatorios faltantes."}, status=400)

            try:
                precio = float(precio)
                stock = int(stock)
            except ValueError:
                return JsonResponse({"detail": "Precio o stock inválidos."}, status=400)

            # === GUARDAR IMAGEN SI EXISTE ===
            if imagen:
                ext = os.path.splitext(imagen.name)[1].lower()
                if ext not in [".jpg", ".jpeg", ".png"]:
                    return JsonResponse({"detail": "Formato de imagen no válido. Solo JPG o PNG."}, status=400)

                # Carpeta donde se guardarán las imágenes
                upload_dir = os.path.join(settings.MEDIA_ROOT, "productos")
                os.makedirs(upload_dir, exist_ok=True)

                # Guardar archivo
                file_name = f"{nombre.replace(' ', '_')}{ext}"
                file_path = os.path.join(upload_dir, file_name)

                with open(file_path, "wb+") as destination:
                    for chunk in imagen.chunks():
                        destination.write(chunk)

                # Ruta que se guardará en BD
                ruta_imagen = f"productos/{file_name}"

            # === EJECUTAR FUNCIÓN SQL ===
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT crear_producto(%s, %s, %s, %s, %s, %s)",
                    [nombre, categoria_id, descripcion, stock, precio, ruta_imagen]
                )
                nuevo_id = cursor.fetchone()[0]

            return JsonResponse({
                "success": True,
                "message": "Producto creado exitosamente.",
                "id": nuevo_id,
                "imagen": ruta_imagen
            }, status=201)

        except Exception as e:
            return JsonResponse({"detail": str(e)}, status=500)
        
    elif request.method in ["PUT", "PATCH"]:
        try:
            # Django no parsea automáticamente FormData en PUT,
            # así que usamos request.POST y request.FILES igual que con POST
            prod_id = request.POST.get("prod_id")
            nombre = request.POST.get("nombre", "").strip()
            descripcion = request.POST.get("descripcion", "").strip()
            categoria = request.POST.get("cat_id")
            precio = request.POST.get("precio")
            stock = request.POST.get("stock")
            imagen = request.FILES.get("imagen")
            ruta_imagen = None

            if not prod_id or not nombre or not categoria or not precio or stock is None:
                return JsonResponse({"detail": "Campos obligatorios faltantes."}, status=400)

            try:
                precio = float(precio)
                stock = int(stock)
            except ValueError:
                return JsonResponse({"detail": "Precio o stock inválidos."}, status=400)

            # Guardar imagen si se envía
            if imagen:
                ext = os.path.splitext(imagen.name)[1].lower()
                if ext not in [".jpg", ".jpeg", ".png"]:
                    return JsonResponse({"detail": "Formato no válido. Solo JPG o PNG."}, status=400)

                upload_dir = os.path.join(settings.MEDIA_ROOT, "productos")
                os.makedirs(upload_dir, exist_ok=True)

                file_name = f"{nombre.replace(' ', '_')}{ext}"
                file_path = os.path.join(upload_dir, file_name)

                with open(file_path, "wb+") as destination:
                    for chunk in imagen.chunks():
                        destination.write(chunk)

                ruta_imagen = f"productos/{file_name}"

            # === Ejecutar función SQL ===
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT actualizar_producto(%s, %s, %s, %s, %s, %s, %s)",
                    [prod_id, nombre, descripcion, categoria, precio, stock, ruta_imagen]
                )
                updated_id = cursor.fetchone()[0]

            return JsonResponse({
                "success": True,
                "message": "Producto actualizado correctamente.",
                "id": updated_id,
                "imagen": ruta_imagen
            }, status=200)

        except Exception as e:
            return JsonResponse({"detail": str(e)}, status=500)

    return JsonResponse({"detail": "Método no permitido."}, status=405)

@csrf_exempt
def ObtenerCategoriasView(request):
    if request.method == "GET":
        try:
            with connection.cursor() as cursor:
                cursor.execute('SELECT * FROM obtener_categorias()')
                cols = [col[0] for col in cursor.description]
                resultados_categorias = [dict(zip(cols, row)) for row in cursor.fetchall()]

                return JsonResponse({'exito': resultados_categorias}, status=200)

        except DatabaseError as e:
            return HttpResponse(f"<h1>Error en la BD: {str(e)}</h1>", status=400)
