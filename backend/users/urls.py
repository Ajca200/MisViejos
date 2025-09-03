from django.urls import path
from .views import LoginView, LoginPage, ResumenPage, RegisterPage, RegisterView, ConfigurationPage, ActualizarDatosView, ProductsPage, PedidosPage, UsuariosPage, DomiciliosPage, ObtenerDatosActualizables, HomePage, RegistrarProductoView, ObtenerCategoriasView

urlpatterns = [
path('login/auth', LoginView, name='login-user'),
path('login', LoginPage, name='page-login'),
path('register', RegisterPage, name='page-register'),
path('register/user', RegisterView, name='register-user'),
path('resumen', ResumenPage, name='page-resumen'),
path('configuracion', ConfigurationPage, name='page-config'),
path('update-data', ActualizarDatosView, name='actualizar-datos-usuario'),
path('products', ProductsPage, name='productos_page'),
path('pedidos', PedidosPage, name='pedidos_page'),
path('usuarios', UsuariosPage, name='usuarios_page'),
path('domicilios', DomiciliosPage, name='domicilios_page'),
path('datos/usuario/actualizar', ObtenerDatosActualizables, name='datos-actualizables-usuario'),
path('home', HomePage, name='home-page'),
path('products/register', RegistrarProductoView, name='registrar-producto'),
path('categorias', ObtenerCategoriasView, name='obtener-categorias')

]