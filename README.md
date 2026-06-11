<div align="center">

# 🌐 DNS Spoofing / DNS Poisoning Attack
### Lab EGALDITO_LAB — Ciberseguridad Ofensiva en Redes






</div>

***

## 📋 Objetivo del Laboratorio

Demostrar cómo un atacante posicionado en la misma red puede interceptar consultas DNS de una víctima mediante **ARP Poisoning**, respondiendo con una IP falsa para redirigirla a un servidor web controlado por el atacante que suplanta el dominio **`itla.edu.do`**.

***

## 🗺️ Topología de Red

<div align="center">



</div>

### Tabla de Direccionamiento

| Dispositivo | Interfaz | Modo | VLAN | IP |
|:---:|:---:|:---:|:---:|:---:|
| R1 | G0/0.10 | Subinterfaz trunk | 10 | `192.168.10.1/24` |
| SW1 | G0/0 | Trunk | All | — |
| SW2 | G0/0 | Trunk | All | — |
| SW2 | G0/1 | Access | 10 | — |
| SW2 | G0/2 | Access | 10 | — |
| Kali Atacante | eth0.10 | VLAN tag 802.1Q | 10 | DHCP (`192.168.10.X`) |
| Kali Víctima | eth0 | Access | 10 | DHCP (`192.168.10.Y`) |

### Imagen topologia
![Topología](Topologia/Topologia.png)

***

## 🎯 Objetivo del Script

El script `dns_spoof.py` ejecuta un ataque completo de DNS Spoofing en 5 etapas encadenadas:

1. 🔧 Crear subinterfaz VLAN 10 (`eth0.10`)
2. 🌐 Obtener IP legítima por DHCP
3. 🔍 Descubrir víctima y gateway mediante ARP scan
4. ☠️ Realizar ARP Poisoning (posicionarse como MITM)
5. 🎭 Interceptar y falsificar respuestas DNS

***

## ⚙️ Requisitos

- 🐧 Kali Linux **atacante y víctima** con permisos `root`
- 🐍 Python 3 instalado
- 📦 Scapy: `sudo pip3 install scapy`
- ✅ Script DTP corrido previamente (para acceso a VLAN 10)
- 🌍 Servidor web activo antes de correr el script:
  ```bash
  cd ~/fake_site && sudo python3 -m http.server 80
  ```

***

## 🔧 Parámetros del Script

| Parámetro | Valor | Descripción |
|:---|:---:|:---|
| `IFACE` | `eth0` | Interfaz física de Kali |
| `SUBIF` | `eth0.10` | Subinterfaz VLAN 10 |
| `VLAN` | `10` | ID de la VLAN objetivo |
| `state["my_ip"]` | DHCP dinámico | IP del atacante → destino del spoofing |
| `state["vic_ip"]` | Auto-detectado | IP de la víctima (ARP scan) |
| `state["gw_ip"]` | Auto-detectado | IP del gateway (R1) |

***

## 📖 Funcionamiento del Script

```
┌──────────────────────────────────────────────────────────────────────┐
│                      FLUJO DEL ATAQUE DNS SPOOFING                   │
├──────────┬───────────────────────────────────────────────────────────┤
│ Paso 1   │ Crea eth0.10 → VLAN 10 con etiquetado 802.1Q             │
│ Paso 2   │ DHCP completo → obtiene IP y gateway legítimos            │
│ Paso 3   │ ARP scan /24 → detecta víctima y MAC del gateway          │
│ Paso 4   │ ARP Poison cada 2s → Kali se hace pasar por el gateway    │
│ Paso 5   │ Intercepta UDP/53 → responde con IP de Kali antes que DNS │
│ Paso 6   │ Ctrl+C → restaura tablas ARP y desactiva ip_forward       │
└──────────┴───────────────────────────────────────────────────────────┘
```

### ¿Por qué funciona?

El ARP Poisoning engaña a la víctima para que envíe **todo su tráfico a Kali** en lugar del gateway. Con el tráfico pasando por Kali, el script intercepta las consultas DNS (UDP 53) y **responde primero** con su propia IP antes de que llegue la respuesta del servidor DNS legítimo.

***

## ▶️ Ejecución

```bash
# Terminal 1 — Servidor web falso
cd ~/fake_site
sudo python3 -m http.server 80

# Terminal 2 — Ataque DNS Spoofing
sudo python3 dns_spoof.py
```

**En la Kali víctima:**
```bash
nslookup itla.edu.do
# Resultado esperado: Address: 192.168.10.X (IP de Kali atacante)

curl http://itla.edu.do
# Resultado esperado: HTML de la página falsa
```

**Salida esperada en el atacante:**
```
[+] IP obtenida: 192.168.10.4   GW: 192.168.10.1
[+] Víctima: 192.168.10.5   aa:bb:cc:dd:ee:ff
[+] ARP Poison activo: 192.168.10.5 ↔ 192.168.10.1
[+] Escuchando DNS de 192.168.10.5...

[DNS] 192.168.10.5 pregunta: itla.edu.do → 192.168.10.4 ✔
```

***

## 🛡️ Contramedidas y Mitigación

> 📄 Ver comandos completos en: [`Mitigacion/SW2.ios`](Mitigacion/SW2.ios)

| # | Medida | Dónde | Efecto |
|:---:|:---|:---:|:---|
| 1 | DHCP Snooping | SW1 | Construye tabla legítima IP↔MAC↔Puerto |
| 2 | Dynamic ARP Inspection | SW1 | Descarta ARPs falsos de Kali |
| 3 | Puerto `trust` hacia R1 | SW1 G0/0 | Solo R1 puede responder DHCP y ARP válidos |
| 4 | DNS sobre HTTPS (DoH) | Víctima | Cifra consultas DNS, imposible de modificar |

***

<div align="center">

**EGALDITO_LAB** -  Ciberseguridad Ofensiva en Redes -  2025-0704

</div>
