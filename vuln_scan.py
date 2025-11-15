#!/usr/bin/env python3
"""
Vulnerability Scanner - Herramienta de Escaneo de Vulnerabilidades
Autor: [Tu Nombre]
Versión: 1.0.0
"""

import argparse
import logging
import sys
import yaml
from pathlib import Path
from colorama import init, Fore, Style

# Inicializar colorama
init(autoreset=True)

# Importar módulos propios
from scanner.core import Host, ScanRegistry
from scanner.port_scanner import PortScanner
from scanner.vuln_detector import VulnerabilityDetector
from scanner.report_generator import ReportGenerator

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/scanner.log'),
        logging.StreamHandler()
    ]
)

def load_config(config_file: str = 'config/config.yaml'):
    """Cargar configuración desde archivo YAML"""
    try:
        with open(config_file, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logging.error(f"Error cargando configuración: {e}")
        return {}

def print_banner():
    """Mostrar banner de la herramienta"""
    banner = f"""
{Fore.RED}
╦  ╦╦ ╦╦  ╔╗╔  ╔═╗╔═╗╔═╗╔╗╔╔╗╔╔═╗╦═╗
╚╗╔╝║ ║║  ║║║  ╚═╗║  ╠═╣║║║║║║║╣ ╠╦╝
 ╚╝ ╚═╝╩═╝╝╚╝  ╚═╝╚═╝╩ ╩╝╚╝╝╚╝╚═╝╩╚═
{Style.RESET_ALL}
{Fore.CYAN}Vulnerability Scanner v1.0.0{Style.RESET_ALL}
{Fore.YELLOW}Por [Tu Nombre]{Style.RESET_ALL}
{'─' * 50}
"""
    print(banner)

def scan_single_host(ip: str
, config: dict, registry: ScanRegistry):
    """Escanear un único host"""
    print(f"\n{Fore.CYAN}[*] Iniciando escaneo de host: {ip}{Style.RESET_ALL}\n")
    
    # Inicializar componentes
    port_scanner = PortScanner(
        timeout=config['scanner']['timeout'],
        max_threads=config['scanner']['max_threads']
    )
    vuln_detector = VulnerabilityDetector()
    
    # Verificar si el host está activo
    if not port_scanner.quick_scan(ip):
        print(f"{Fore.RED}[-] Host {ip} no responde{Style.RESET_ALL}")
        return None
    
    print(f"{Fore.GREEN}[+] Host {ip} está activo{Style.RESET_ALL}")
    
    # Crear objeto Host
    host = Host(ip)
    registry.register_host(host)
    
    # Escanear puertos
    scan_results = port_scanner.scan_host(ip, config['ports']['common'])
    registry.increment_attempts()
    
    if not scan_results:
        return host
    
    # Analizar vulnerabilidades por cada puerto abierto
    print(f"\n{Fore.YELLOW}[*] Analizando vulnerabilidades...{Style.RESET_ALL}\n")
    
    for port_info in scan_results.get('ports', []):
        if port_info['state'] == 'open':
            host.add_port(
                port_info['port'],
                port_info['state'],
                port_info['service']
            )
            
            # Detectar vulnerabilidades
            vulnerabilities = vuln_detector.analyze_service(
                port_info['service'],
                port_info['port'],
                port_info.get('version')
            )
            
            for vuln in vulnerabilities:
                host.add_vulnerability(vuln)
    
    return host

def scan_network(network: str, config: dict, registry: ScanRegistry):
    """Escanear un rango de red"""
    print(f"\n{Fore.CYAN}[*] Iniciando escaneo de red: {network}{Style.RESET_ALL}\n")
    
    port_scanner = PortScanner()
    
    # Descubrir hosts activos
    active_hosts = port_scanner.scan_network_range(network)
    
    if not active_hosts:
        print(f"{Fore.RED}[-] No se encontraron hosts activos{Style.RESET_ALL}")
        return
    
    # Escanear cada host encontrado
    for ip in active_hosts:
        scan_single_host(ip, config, registry)
        print(f"\n{Fore.CYAN}{'─' * 50}{Style.RESET_ALL}\n")

def main():
    """Función principal"""
    parser = argparse.ArgumentParser(
        description='Vulnerability Scanner - Herramienta de escaneo de vulnerabilidades',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  %(prog)s -t 192.168.1.1                    # Escanear un solo host
  %(prog)s -t 192.168.1.0/24                 # Escanear red completa
  %(prog)s -t 192.168.1.1 -p 80,443,8080     # Escanear puertos específicos
  %(prog)s -l targets.txt                    # Escanear desde archivo
  %(prog)s -t 192.168.1.1 -o json,html       # Especificar formato de reporte
        """
    )
    
    parser.add_argument(
        '-t', '--target',
        help='IP objetivo o rango de red (ej: 192.168.1.1 o 192.168.1.0/24)'
    )
    
    parser.add_argument(
        '-l', '--list',
        help='Archivo con lista de IPs (una por línea)'
    )
    
    parser.add_argument(
        '-p', '--ports',
        help='Puertos a escanear separados por comas (ej: 80,443,8080)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='html,json,txt',
        help='Formatos de reporte (html,json,txt) - Default: todos'
    )
    
    parser.add_argument(
        '-c', '--config',
        default='config/config.yaml',
        help='Archivo de configuración - Default: config/config.yaml'
    )
    
    parser.add_argument(
        '--full-scan',
        action='store_true',
        help='Escaneo completo de todos los puertos (1-65535)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Modo verbose (más detalles)'
    )
    
    args = parser.parse_args()
    
    # Verificar que se proporcione al menos un objetivo
    if not args.target and not args.list:
        parser.print_help()
        sys.exit(1)
    
    # Mostrar banner
    print_banner()
    
    # Configurar nivel de logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Cargar configuración
    config = load_config(args.config)
    
    # Modificar puertos si se especificaron
    if args.ports:
        config['ports']['common'] = [int(p) for p in args.ports.split(',')]
    elif args.full_scan:
        config['ports']['common'] = list(range(1, 65536))
    
    # Crear registro de escaneo
    registry = ScanRegistry()
    
    try:
        # Escanear desde archivo
        if args.list:
            with open(args.list, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            
            for target in targets:
                if '/' in target:
                    scan_network(target, config, registry)
                else:
                    scan_single_host(target, config, registry)
        
        # Escanear objetivo único o red
        elif args.target:
            if '/' in args.target:
                scan_network(args.target, config, registry)
            else:
                scan_single_host(args.target, config, registry)
        
        # Generar reportes
        print(f"\n{Fore.CYAN}[*] Generando reportes...{Style.RESET_ALL}\n")
        
        # Preparar datos para el reporte
        report_data = {
            'statistics': registry.get_statistics(),
            'hosts': []
        }
        
        for host in registry.hosts:
            report_data['hosts'].append({
                'ip': host.ip,
                'hostname': host.hostname,
                'risk_score': host.get_risk_score(),
                'open_ports': len(host.ports),
                'vulnerabilities': host.vulnerabilities
            })
        
        # Generar reportes
        report_gen = ReportGenerator()
        output_formats = args.output.split(',')
        report_gen.generate_report(report_data, output_formats)
        
        # Mostrar reporte en consola
        report_gen.display_console_report(report_data)
        
        print(f"\n{Fore.GREEN}[+] Escaneo completado exitosamente{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Revisa la carpeta 'reports/' para los reportes detallados{Style.RESET_ALL}\n")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Escaneo interrumpido por el usuario{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Error durante el escaneo: {str(e)}")
        print(f"{Fore.RED}[-] Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()