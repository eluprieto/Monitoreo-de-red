# -*- coding: utf-8 -*-
import os
import time
import socket
import ipaddress
import subprocess
import smtplib
import logging
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.header import Header
from email import encoders

import requests
import pandas as pd
from scapy.all import sniff, IP

# =============== CONFIG =================
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "TU_GMAIL@gmail.com"          # <-- tu Gmail
SENDER_APP_PASSWORD = "TU_APP_PASSWORD_16"   # <-- App Password (16 chars, sin espacios)
RECEIVER_EMAIL = "destinatario@ejemplo.com"  # a dónde llegan las alertas
SEND_MAIL = True                             # poné False para probar sin enviar

# Ruido mínimo / modo estricto:
USE_FIREHOL = True          # SOLO alerta si la IP destino está en FireHOL level1
FIREHOL_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"

PING_INTERVAL_S = 3
CICLO_ESPERA_S = 10
SNIFF_DURACION_S = 15
COOLDOWN_ALERTA_S = 3600    # 1h por IP para no spamear
# ========================================

# Permitir credenciales por variables de entorno (opcional)
SENDER_EMAIL = os.getenv("SENDER_EMAIL", SENDER_EMAIL)
SENDER_APP_PASSWORD = os.getenv("SENDER_APP_PASSWORD", SENDER_APP_PASSWORD)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
IPS_PATH = os.path.join(BASE_DIR, "IPS.txt")
LOG_EXCEL = os.path.join(BASE_DIR, "resultados_ping.xlsx")
LOG_FILE = os.path.join(BASE_DIR, "network_security.log")

logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

# Estado
whitelist_ips = set()    # IPs sueltas
whitelist_nets = []      # Redes (CIDR)
ultimo_envio_por_ip = {} # cooldown por IP
firehol_nets = []        # lista de redes maliciosas

# ----------------- UTILIDADES -----------------
def _send_mail(subject, body, attachment_path=None):
    if not SEND_MAIL:
        print(f"(EMAIL OFF) {subject}\n{body}\n")
        return
    msg = MIMEMultipart()
    msg["Subject"] = str(Header(subject, "utf-8"))
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECEIVER_EMAIL
    msg.attach(MIMEText(body, "plain", "utf-8"))

    if attachment_path and os.path.exists(attachment_path):
        with open(attachment_path, "rb") as f:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f'attachment; filename="{os.path.basename(attachment_path)}"')
        msg.attach(part)

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_APP_PASSWORD)
            server.sendmail(SENDER_EMAIL, [RECEIVER_EMAIL], msg.as_string())
    except smtplib.SMTPAuthenticationError as e:
        print(f"SMTP 535 (BadCredentials). Revisá SENDER_EMAIL y SENDER_APP_PASSWORD. Detalle: {e}")
    except Exception as e:
        print(f"Error SMTP: {e}")

def send_error_email(host, results):
    subject = f"Error de conexión con {host}"
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    body = f"El host {host} no responde. Fecha y hora: {ts}."
    try:
        pd.DataFrame(results).to_excel(LOG_EXCEL, index=False)
    except Exception as e:
        print(f"No pude escribir Excel: {e}")
    _send_mail(subject, body, LOG_EXCEL)

def send_ip_alert_email(ip_address, alert_message):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    subject = "Alerta de seguridad: IP maliciosa detectada"
    body = f"{alert_message}\nFecha y hora: {ts}."
    _send_mail(subject, body, None)

def permitido_enviar(ip, ventana=COOLDOWN_ALERTA_S):
    ahora = time.time()
    if ahora - ultimo_envio_por_ip.get(ip, 0) < ventana:
        return False
    ultimo_envio_por_ip[ip] = ahora
    return True

def es_publica(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global  # excluye privadas, loopback, link-local, multicast, broadcast
    except ValueError:
        return False

def en_whitelist(ip_str):
    if ip_str in whitelist_ips:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in whitelist_nets)
    except ValueError:
        return False

# ----------------- CARGA DE LISTAS -----------------
def load_whitelist():
    """Lee IPS.txt (IP, CIDR o hostname). Resuelve hostnames a IPs."""
    if not os.path.exists(IPS_PATH):
        print("No existe IPS.txt. Creándolo con ejemplos...")
        with open(IPS_PATH, "w", encoding="utf-8") as f:
            f.write("# Una entrada por línea. IP, CIDR o hostname.\n")
            f.write("8.8.8.8\n")
            f.write("1.1.1.0/24\n")
            f.write("github.com\n")
        print(f"Editá {IPS_PATH} y volvé a ejecutar.")
        raise SystemExit(0)

    with open(IPS_PATH, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # IP/CIDR
            try:
                net = ipaddress.ip_network(line, strict=False)
                if (net.version == 4 and net.prefixlen == 32) or (net.version == 6 and net.prefixlen == 128):
                    whitelist_ips.add(str(net.network_address))
                else:
                    whitelist_nets.append(net)
                continue
            except ValueError:
                pass
            # hostname
            try:
                _, _, ips = socket.gethostbyname_ex(line)
                whitelist_ips.update(ips)
            except Exception:
                print(f"Advertencia: no pude resolver '{line}'")

    print(f"Whitelist cargada -> IPs: {len(whitelist_ips)} | Redes: {len(whitelist_nets)}")

def get_ping_hosts():
    """Entradas crudas del IPS.txt (IP o hostname) para ping."""
    hosts = []
    with open(IPS_PATH, "r", encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if line and not line.startswith("#"):
                hosts.append(line)
    return hosts

def cargar_firehol():
    """Descarga FireHOL level1 (CIDR) si USE_FIREHOL=True."""
    if not USE_FIREHOL:
        return
    try:
        r = requests.get(FIREHOL_URL, timeout=20)
        r.raise_for_status()
        for line in r.text.splitlines():
            if line and not line.startswith("#"):
                try:
                    firehol_nets.append(ipaddress.ip_network(line.strip()))
                except ValueError:
                    pass
        print(f"FireHOL cargado: {len(firehol_nets)} redes")
    except Exception as e:
        print(f"No pude cargar FireHOL: {e}")

def es_maliciosa(ip_str):
    """Modo estricto: SOLO alertar si la IP está en FireHOL."""
    if not USE_FIREHOL:
        return True  # fallback (no recomendado)
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in firehol_nets)

# ----------------- PING + SNIFF -----------------
def ping_host(host, failed_hosts, results):
    try:
        cmd = ["ping", "-n", "1", "-w", "1000", host]  # Windows
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        status = "Activo" if p.returncode == 0 else "Con error"
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        results.append({"Host": host, "Estado": status, "Fecha y hora": ts})
        if status == "Activo":
            print(f"{host} está disponible.")
            failed_hosts.discard(host)
            return True
        else:
            print(f"{host} no responde.")
            if host not in failed_hosts:
                try:
                    send_error_email(host, results)
                except Exception as e:
                    print(f"No pude enviar correo: {e}")
                failed_hosts.add(host)
            return False
    except Exception as e:
        print(f"Error al hacer ping a {host}: {e}")
        if host not in failed_hosts:
            try:
                send_error_email(host, results)
            except Exception as e2:
                print(f"No pude enviar correo: {e2}")
            failed_hosts.add(host)
        return False

def ping_hosts(hosts, failed_hosts, results):
    for h in hosts:
        ping_host(h, failed_hosts, results)
        time.sleep(PING_INTERVAL_S)

# Filtro BPF: ignora privadas, loopback, link-local, multicast y broadcast
BPF_FILTER = (
    "ip and not ("
    "dst net 10.0.0.0/8 or "
    "dst net 172.16.0.0/12 or "
    "dst net 192.168.0.0/16 or "
    "dst net 127.0.0.0/8 or "
    "dst net 169.254.0.0/16 or "
    "dst net 224.0.0.0/4 or "        # multicast (incluye 239.0.0.0/8)
    "dst host 255.255.255.255"
    ")"
)

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # 1) ignorar no públicas (por si algo pasó el BPF)
        if not es_publica(dst_ip):
            return

        # 2) SOLO si está en FireHOL alertamos (modo estricto)
        if not es_maliciosa(dst_ip):
            return

        # 3) whitelist (IP o red) puede anular
        if en_whitelist(dst_ip):
            return

        # 4) alertar
        msg = f"Conexión bloqueada para IP no permitida: {src_ip} -> {dst_ip}."
        logging.info(msg)
        if permitido_enviar(dst_ip):
            print("Alerta de Seguridad:", msg)
            try:
                send_ip_alert_email(dst_ip, msg)
            except Exception as e:
                print(f"Error al enviar correo: {e}")

def monitor_network(duration=SNIFF_DURACION_S):
    print("Iniciando monitoreo de tráfico de red...")
    sniff(filter=BPF_FILTER, prn=packet_callback, timeout=duration, store=0)

# ----------------- MAIN -----------------
def main():
    load_whitelist()
    cargar_firehol()  # debe imprimir "FireHOL cargado: N redes"
    hosts = get_ping_hosts()

    failed = set()
    results = []

    while True:
        print("Esperando 10 segundos antes de iniciar pings...")
        time.sleep(CICLO_ESPERA_S)

        print("Realizando pings a los hosts...")
        ping_hosts(hosts, failed, results)

        print("Esperando 10 segundos antes de iniciar monitoreo de red...")
        time.sleep(CICLO_ESPERA_S)

        monitor_network()

if __name__ == "__main__":
    main()
