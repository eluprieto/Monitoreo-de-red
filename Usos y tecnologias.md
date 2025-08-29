# Monitoreo-de-redes-automatizado

Sistema ligero de **detección y alerta** para redes.  
Hace **ping** a una lista de hosts, **sniffea** tráfico en tiempo real y **envía alertas por email** cuando el **destino** coincide con IPs maliciosas (lista **FireHOL level1**). Soporta whitelist por **IP / CIDR / hostname**.

## Funcionalidades
- Ping programado a hosts de `IPS.txt` con exportación a **Excel**.
- Sniffer (Scapy) con **filtro BPF**: ignora privadas, loopback, link-local, multicast y broadcast.
- Correlación de reputación: alerta **solo** si el **destino** ∈ FireHOL level1.
- Whitelist flexible: IP, CIDR o hostname (resuelve a IPs).
- **Cooldown** por IP para evitar spam.
- Alertas SMTP y **logging** a archivo.

## Requisitos
- Windows con **Npcap**.
- **PowerShell como Administrador**.
- **Python 3.8+**.
- Cuenta SMTP (Gmail con **App Password** de 16 caracteres).

## Instalación
```bash
python -m pip install --upgrade pip
pip install pandas openpyxl scapy requests


