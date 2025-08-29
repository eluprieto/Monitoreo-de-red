# Monitoreo-de-redes-automatizado
Este proyecto implementa un sistema de monitoreo de red y alerta para detectar IP no permitidas, realizar diagnósticos de conectividad (ping) y enviar notificaciones por correo electrónico sobre incidentes.

# Descripción
El código está diseñado para:
-Monitorear tráfico de red en tiempo real y registrar eventos sospechosos.
-Realizar pings a una lista de hosts y verificar su conectividad.
-Enviar alertas por correo electrónico en caso de errores de conexión o detección de IPs no permitidas.
-Generar un archivo de log con eventos relevantes y resultados en formato Excel.

# Bibliotecas Utilizadas
El proyecto utiliza las siguientes bibliotecas y módulos:
-subprocess: Para ejecutar comandos del sistema, como el comando ping.
-time: Para manejar intervalos de tiempo entre operaciones.
-smtplib: Para enviar correos electrónicos usando el protocolo SMTP.
-email: Para crear y manejar el contenido de los correos (texto, adjuntos).
-datetime: Para manejar fechas y horas.
-pandas: Para estructurar datos y exportarlos a formato Excel.
-scapy: Para capturar y analizar paquetes de red.
-logging: Para registrar eventos en un archivo de log.
-os: Para interactuar con el sistema operativo (archivos y rutas).
-threading: Para manejar múltiples hilos de ejecución.

# Requisitos Previos
Python: Versión 3.7 o superior.
Bibliotecas adicionales: Instalar las dependencias con y en el CMD:
-pip install "y el nombre de la librerias"
-Archivo de configuración: Crear un archivo IPS.txt con las IPs permitidas (una por línea).
-Correo SMTP: Configura las credenciales de un correo de Gmail para el envío de notificaciones:
-Usuario: tucorreo@gmail.com
-Contraseña: (Utiliza una clave de aplicación para mayor seguridad).
