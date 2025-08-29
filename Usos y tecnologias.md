Monitoreo-de-redes-automatizado

Sistema ligero de detección y alerta para redes.
Hace ping a una lista de hosts, sniffea tráfico en tiempo real y envía alertas por email cuando detecta conexiones hacia IPs maliciosas según una lista de reputación.

Funcionalidades

Ping programado a hosts definidos en IPS.txt, con exportación a Excel.

Sniffer (Scapy) con filtro BPF: ignora privadas, loopback, link-local, multicast y broadcast.

Correlación con reputación: alerta solo si el destino está en FireHOL level1.

Whitelist flexible: admite IP, CIDR y hostname (resuelve a IPs).

Rate-limit de alertas por IP (cooldown) para evitar spam.

Alertas por correo (SMTP) y logging a archivo.

Tecnologías / Módulos

Red: scapy, ipaddress, socket, subprocess

Reputación/HTTP: requests

Email: smtplib, email.* (MIME)

Datos: pandas + openpyxl (Excel)

Utilidades: logging, datetime, os, time

Requisitos

Windows con Npcap instalado.

PowerShell ejecutado como Administrador (necesario para captura).

Python 3.8+

Cuenta de correo SMTP (ej. Gmail con App Password de 16 caracteres).
