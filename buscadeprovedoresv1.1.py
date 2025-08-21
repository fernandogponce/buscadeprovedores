#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Analisador de IPs - Detector de VPN e Tipo de Conexão
Versão com Mapa Interativo Otimizado

Este script analisa endereços IP e gera um relatório HTML interativo
com mapa de geolocalização, pop-ups informativos e geração de ofícios
"""

import requests
import time
import re
import socket
import os
import sys
import json
from datetime import datetime
from urllib.parse import urlparse

def check_ipapi(ip_address):
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,regionName,city,isp,org,as,mobile,proxy,hosting,lat,lon', timeout=10)
        data = response.json()
        if data['status'] == 'success':
            return data
        else:
            return {"error": data.get('message', 'Erro desconhecido na consulta à ip-api.com')}
    except Exception as e:
        return {"error": f"Falha na consulta à ip-api.com: {str(e)}"}

def check_vpnapi(ip_address):
    try:
        response = requests.get(f'https://vpnapi.io/api/{ip_address}?key=787022fae0c04f6dbb8945bbf824ad96', timeout=10)
        data = response.json()
        if 'security' in data:
            return data['security']
        else:
            return {"error": data.get('message', 'Erro desconhecido na consulta à vpnapi.io')}
    except Exception as e:
        return {"error": f"Falha na consulta à vpnapi.io: {str(e)}"}

def is_valid_ipv4(ip):
    if not ip or not isinstance(ip, str):
        return False
    ip = ip.strip()
    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
        return False
    octets = ip.split('.')
    for octet in octets:
        try:
            num = int(octet)
            if num < 0 or num > 255:
                return False
        except ValueError:
            return False
    return True

def is_valid_ipv6(ip):
    if not ip or not isinstance(ip, str):
        return False
    ip = ip.strip()
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except:
        return False

def is_valid_ip(ip):
    return is_valid_ipv4(ip) or is_valid_ipv6(ip)

def get_ip_version(ip):
    if is_valid_ipv4(ip):
        return 'IPv4'
    elif is_valid_ipv6(ip):
        return 'IPv6'
    else:
        return None

def parse_ip_entry(entry):
    """
    Analisa entrada que pode conter IP, porta, data e hora
    Formatos aceitos:
    - IP
    - IP:porta
    - IP:porta em DD/MM/AAAA às HH:MM:SS (UTC-X)
    - IP:porta DD/MM/AAAA HH:MM (UTC-X)
    - IP porta data hora
    """
    entry = entry.strip()
    
    # Inicializar variáveis
    ip = None
    porta = None
    data = None
    hora = None
    utc = None
    
    # Padrão 1: IP:porta em DD/MM/AAAA às HH:MM:SS (UTC-X)
    pattern1 = r'(\d+\.\d+\.\d+\.\d+):(\d+)\s+em\s+(\d{2}/\d{2}/\d{4})\s+às\s+(\d{2}:\d{2}:\d{2})\s+\((UTC[+-]?\d+)\)'
    match1 = re.match(pattern1, entry)
    if match1:
        ip, porta, data, hora, utc = match1.groups()
        return {'ip': ip, 'porta': porta, 'data': data, 'hora': hora, 'utc': utc}
    
    # Padrão 2: IP:porta MM/DD/AAAA HH:MM (UTC-X)
    pattern2 = r'(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\d{2}/\d{2}/\d{4})\s+(\d{2}:\d{2})\s+\((UTC[+-]?\d+)\)'
    match2 = re.match(pattern2, entry)
    if match2:
        ip, porta, data_us, hora, utc = match2.groups()
        # Converter data americana (MM/DD/AAAA) para brasileira (DD/MM/AAAA)
        month, day, year = data_us.split('/')
        data = f"{day}/{month}/{year}"
        return {'ip': ip, 'porta': porta, 'data': data, 'hora': hora, 'utc': utc}
    
    # Padrão 3: IP:porta (formato básico)
    pattern3 = r'(\d+\.\d+\.\d+\.\d+):(\d+)'
    match3 = re.match(pattern3, entry)
    if match3:
        ip, porta = match3.groups()
        return {'ip': ip, 'porta': porta, 'data': None, 'hora': None, 'utc': None}
    
    # Padrão 4: Separado por espaços
    parts = entry.split()
    
    if len(parts) >= 1:
        # Primeiro elemento: IP ou IP:porta
        ip_part = parts[0]
        if ':' in ip_part and not is_valid_ipv6(ip_part):
            # Formato IP:porta
            ip_port = ip_part.split(':')
            ip = ip_port[0]
            porta = ip_port[1] if len(ip_port) > 1 else None
        else:
            ip = ip_part
    
    # Processar elementos restantes
    remaining_parts = parts[1:] if len(parts) > 1 else []
    
    for i, part in enumerate(remaining_parts):
        # Se porta ainda não foi definida e é um número
        if porta is None and part.isdigit():
            porta = part
            continue
        
        # Verificar se é uma data (DD/MM/AAAA ou MM/DD/AAAA)
        if re.match(r'\d{2}/\d{2}/\d{4}', part):
            data = part
            continue
        
        # Verificar se é um horário (HH:MM ou HH:MM:SS)
        if re.match(r'\d{2}:\d{2}(:\d{2})?', part):
            hora = part
            continue
        
        # Verificar se é UTC
        if part.startswith('(UTC') and part.endswith(')'):
            utc = part[1:-1]  # Remove parênteses
            continue
        
        # UTC sem parênteses
        if part.startswith('UTC'):
            utc = part
            continue
    
    return {
        'ip': ip or '',
        'porta': porta,
        'data': data,
        'hora': hora,
        'utc': utc
    }

def analyze_ip(ip_data):
    ip_address = ip_data['ip']
    ip_version = get_ip_version(ip_address)
    
    if not ip_version:
        return {"error": "IP inválido. Forneça um endereço IP válido (IPv4 ou IPv6)."}

    results = {
        "ip_version": ip_version,
        "ip": ip_address,
        "porta": ip_data.get('porta', ''),
        "data": ip_data.get('data', ''),
        "hora": ip_data.get('hora', ''),
        "utc": ip_data.get('utc', ''),
        "latitude": None,
        "longitude": None
    }
    
    if ip_version == 'IPv6':
        results["aviso"] = "Análise de IPv6 pode ter funcionalidade limitada em algumas APIs."

    print(f"Consultando APIs para {ip_address}...")

    # Consulta ip-api.com
    ipapi_data = check_ipapi(ip_address)
    if "error" not in ipapi_data:
        results["país"] = ipapi_data.get('country', 'Desconhecido')
        results["código_país"] = ipapi_data.get('countryCode', 'XX')
        results["região"] = ipapi_data.get('regionName', 'Desconhecido')
        results["cidade"] = ipapi_data.get('city', 'Desconhecido')
        results["provedor"] = ipapi_data.get('isp', 'Desconhecido')
        results["organização"] = ipapi_data.get('org', 'Desconhecido')
        results["AS"] = ipapi_data.get('as', 'Desconhecido')
        results["conexão_móvel"] = "Sim" if ipapi_data.get('mobile', False) else "Não"
        results["proxy_detectado"] = "Sim" if ipapi_data.get('proxy', False) else "Não"
        results["hospedagem"] = "Sim" if ipapi_data.get('hosting', False) else "Não"
        results["latitude"] = ipapi_data.get('lat')
        results["longitude"] = ipapi_data.get('lon')
    else:
        results["erro_ipapi"] = ipapi_data.get("error", "Erro desconhecido")
        results["país"] = 'Erro na consulta'
        results["código_país"] = 'XX'
        results["região"] = 'Erro na consulta'
        results["cidade"] = 'Erro na consulta'
        results["provedor"] = 'Erro na consulta'
        results["organização"] = 'Erro na consulta'
        results["AS"] = 'Erro na consulta'
        results["conexão_móvel"] = 'Indeterminado'
        results["proxy_detectado"] = 'Indeterminado'
        results["hospedagem"] = 'Indeterminado'

    # Consulta vpnapi.io
    if ip_version == 'IPv4':
        vpnapi_data = check_vpnapi(ip_address)
        if "error" not in vpnapi_data:
            results["vpn"] = "Sim" if vpnapi_data.get('vpn', False) else "Não"
            results["proxy"] = "Sim" if vpnapi_data.get('proxy', False) else "Não"
            results["tor"] = "Sim" if vpnapi_data.get('tor', False) else "Não"
            results["relay"] = "Sim" if vpnapi_data.get('relay', False) else "Não"
        else:
            results["erro_vpnapi"] = vpnapi_data.get("error", "Erro desconhecido")
            results["vpn"] = 'Indeterminado'
            results["proxy"] = 'Indeterminado'
            results["tor"] = 'Indeterminado'
            results["relay"] = 'Indeterminado'
    else:
        results["vpn"] = 'N/A (IPv6)'
        results["proxy"] = 'N/A (IPv6)'
        results["tor"] = 'N/A (IPv6)'
        results["relay"] = 'N/A (IPv6)'

    # Determinação final
    if results["conexão_móvel"] == "Sim":
        results["tipo_conexão"] = "Móvel"
    elif results["conexão_móvel"] == "Não":
        results["tipo_conexão"] = "Fixa"
    else:
        results["tipo_conexão"] = "Indeterminado"

    vpn_indicators = []
    if results.get("proxy_detectado") == "Sim":
        vpn_indicators.append("proxy detectado (ip-api)")
    if results.get("vpn") == "Sim":
        vpn_indicators.append("VPN detectada (vpnapi)")
    if results.get("proxy") == "Sim":
        vpn_indicators.append("proxy detectado (vpnapi)")
    if results.get("tor") == "Sim":
        vpn_indicators.append("nó Tor detectado")
    if results.get("relay") == "Sim":
        vpn_indicators.append("relay detectado")
    if results.get("hospedagem") == "Sim":
        vpn_indicators.append("serviço de hospedagem detectado")

    if vpn_indicators:
        results["uso_vpn_proxy"] = f"Sim ({', '.join(vpn_indicators)})"
        results["status_vpn"] = "Detectado"
    else:
        results["uso_vpn_proxy"] = "Não detectado"
        results["status_vpn"] = "Não detectado"

    return results

def check_batch_ips(ip_entries):
    results = []
    total = len(ip_entries)

    for i, entry in enumerate(ip_entries):
        print(f"\nAnalisando entrada {i+1} de {total}: {entry}")
        
        # PARSER DIRETO AQUI - sem chamar função externa
        entry = entry.strip()
        ip_data = {
            'ip': '',
            'porta': None,
            'data': None,
            'hora': None,
            'utc': None
        }
        
        # IP
        import re
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', entry)
        if ip_match:
            ip_data['ip'] = ip_match.group(1)
        
        # Porta (apenas se houver : imediatamente após o IP)
        if ':' in entry:
            porta_match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+)', entry)
            if porta_match:
                ip_data['porta'] = porta_match.group(2)
        
        # Data
        date_match = re.search(r'(\d{2}/\d{2}/\d{4})', entry)
        if date_match:
            ip_data['data'] = date_match.group(1)
        
        # Hora (HH:MM ou HH:MM:SS) - só após espaço ou vírgula
        time_match = re.search(r'[\s,](\d{1,2}:\d{2}(?::\d{2})?)', entry)
        if time_match:
            ip_data['hora'] = time_match.group(1)
        
        # UTC
        utc_match = re.search(r'UTC[+-]?\d+', entry)
        if utc_match:
            ip_data['utc'] = utc_match.group(0)
        
        print(f"DADOS EXTRAÍDOS: {ip_data}")
        
        result = analyze_ip(ip_data)
        results.append(result)
        
        if i < total - 1:
            time.sleep(1.5)

    return results

def generate_html_dashboard(results, output_file="dashboard_ips.html"):
    total_ips = len(results)
    vpn_detected = sum(1 for r in results if r.get('status_vpn') == 'Detectado')
    mobile_connections = sum(1 for r in results if r.get('conexão_móvel') == 'Sim')
    fixed_connections = sum(1 for r in results if r.get('conexão_móvel') == 'Não')
    
    countries = [r.get('país', 'Desconhecido') for r in results if r.get('país', 'Desconhecido') != 'Erro na consulta']
    unique_countries = len(set(countries))
    
    providers = [r.get('provedor', 'Desconhecido') for r in results if r.get('provedor', 'Desconhecido') != 'Erro na consulta']
    unique_providers = len(set(providers))

    results_json = json.dumps(results, ensure_ascii=False, indent=2)

    html_content = f'''<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Análise de IPs com Mapa</title>
    
    <!-- Leaflet CSS -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css" />
    
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; color: #333; }}
        .container {{ max-width: 1800px; margin: 0 auto; padding: 20px; }}
        .header {{ background: white; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); padding: 30px; margin-bottom: 30px; text-align: center; }}
        .header h1 {{ color: #667eea; font-size: 2.5rem; margin-bottom: 10px; font-weight: 700; }}
        .header p {{ color: #666; font-size: 1.1rem; margin-bottom: 5px; }}
        
        /* Estatísticas básicas */
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }}
        .stat-card {{ background: linear-gradient(135deg, #667eea, #764ba2); color: white; border-radius: 12px; padding: 20px; text-align: center; transition: transform 0.3s ease; }}
        .stat-card:hover {{ transform: translateY(-5px); }}
        .stat-number {{ font-size: 2rem; font-weight: bold; margin-bottom: 8px; }}
        .stat-label {{ font-size: 0.9rem; font-weight: 500; opacity: 0.9; }}
        
        /* Mapa - MAIOR E MAIS VISÍVEL */
        .map-section {{ background: white; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); padding: 25px; margin-bottom: 30px; }}
        .section-title {{ color: #667eea; font-size: 1.8rem; margin-bottom: 20px; font-weight: 600; border-bottom: 3px solid #667eea; padding-bottom: 10px; }}
        #map {{ height: 600px; width: 100%; border-radius: 12px; box-shadow: 0 6px 20px rgba(0,0,0,0.15); }}
        .map-legend {{ margin-top: 15px; padding: 15px; background: #f8f9fa; border-radius: 8px; font-size: 0.95rem; color: #666; text-align: center; }}
        .legend-item {{ display: inline-block; margin: 0 15px; }}
        .legend-dot {{ display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 5px; }}
        
        /* Tabela e controles */
        .main-content {{ background: white; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); padding: 30px; }}
        .form-section {{ background: #f8f9fa; padding: 20px; border-radius: 10px; margin-bottom: 25px; }}
        .form-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; }}
        .form-group {{ display: flex; flex-direction: column; }}
        .form-group label {{ font-weight: 600; color: #667eea; margin-bottom: 5px; }}
        .form-group input {{ padding: 8px 12px; border: 2px solid #e9ecef; border-radius: 6px; font-size: 0.9rem; }}
        .controls {{ margin-bottom: 25px; display: flex; flex-wrap: wrap; gap: 15px; align-items: center; }}
        .filter-group {{ display: flex; align-items: center; gap: 10px; }}
        .filter-group label {{ font-weight: 600; color: #667eea; }}
        select, input {{ padding: 8px 12px; border: 2px solid #e9ecef; border-radius: 6px; font-size: 0.9rem; }}
        select:focus, input:focus {{ outline: none; border-color: #667eea; }}
        .btn {{ background: #667eea; color: white; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-size: 0.9rem; font-weight: 600; transition: background 0.3s ease; margin: 5px; }}
        .btn:hover {{ background: #5a6fd8; }}
        .btn-export {{ background: #27ae60; }}
        .btn-export:hover {{ background: #219a52; }}
        .btn-copy {{ background: #17a2b8; }}
        .btn-copy:hover {{ background: #138496; }}
        .btn-oficio {{ background: #ffc107; color: #212529; }}
        .btn-oficio:hover {{ background: #e0a800; }}
        .table-container {{ overflow-x: auto; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
        table {{ width: 100%; border-collapse: collapse; background: white; }}
        th {{ background: #667eea; color: white; padding: 12px 8px; text-align: left; font-weight: 600; position: sticky; top: 0; z-index: 10; font-size: 0.85rem; }}
        td {{ padding: 8px; border-bottom: 1px solid #e9ecef; vertical-align: middle; font-size: 0.85rem; }}
        tr:hover {{ background: #f8f9fa; }}
        .status-badge {{ display: inline-block; padding: 3px 6px; border-radius: 8px; font-size: 0.75rem; font-weight: 600; text-align: center; min-width: 60px; }}
        .status-safe {{ background: #d4edda; color: #155724; }}
        .status-warning {{ background: #fff3cd; color: #856404; }}
        .status-danger {{ background: #f8d7da; color: #721c24; }}
        .status-info {{ background: #d1ecf1; color: #0c5460; }}
        .ip-version {{ font-family: monospace; font-weight: bold; color: #667eea; }}
        .no-results {{ text-align: center; padding: 40px; color: #666; font-size: 1.1rem; }}
        .export-section {{ margin-top: 20px; padding: 20px; background: #f8f9fa; border-radius: 10px; text-align: center; }}
        .oficios-section {{ margin-top: 20px; padding: 20px; background: #fff3cd; border-radius: 10px; }}
        .oficios-buttons {{ margin-bottom: 15px; }}
        .copy-success {{ background: #d4edda; color: #155724; padding: 10px; border-radius: 6px; margin: 10px 0; display: none; }}
        .oficio-generated {{ background: white; border: 2px solid #667eea; border-radius: 10px; padding: 20px; margin-top: 15px; max-height: 400px; overflow-y: auto; }}
        .oficio-text {{ white-space: pre-line; font-family: 'Times New Roman', serif; line-height: 1.6; }}
        
        /* Pop-up customizado */
        .leaflet-popup-content-wrapper {{ border-radius: 8px; }}
        .leaflet-popup-content {{ margin: 15px; min-width: 300px; }}
        .popup-header {{ background: #667eea; color: white; padding: 10px; margin: -15px -15px 15px -15px; border-radius: 8px 8px 0 0; font-weight: bold; text-align: center; font-size: 1.1rem; }}
        .popup-section {{ margin-bottom: 12px; padding: 8px 0; border-bottom: 1px solid #eee; }}
        .popup-section:last-child {{ border-bottom: none; }}
        .popup-label {{ font-weight: bold; color: #333; margin-bottom: 4px; font-size: 0.9rem; }}
        .popup-value {{ color: #666; font-size: 0.85rem; line-height: 1.4; }}
        .popup-ip {{ font-family: monospace; font-weight: bold; color: #667eea; font-size: 1.1rem; }}
        .popup-country {{ font-size: 1rem; font-weight: 600; }}
        .popup-alert {{ color: #dc3545; font-weight: bold; }}
        .popup-safe {{ color: #28a745; font-weight: bold; }}
        
        @media (max-width: 768px) {{ 
            .container {{ padding: 10px; }} 
            .stats-grid {{ grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }} 
            .controls {{ flex-direction: column; align-items: stretch; }} 
            .filter-group {{ justify-content: space-between; }}
            #map {{ height: 400px; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Dashboard - Análise de IPs com Mapa Interativo</h1>
            <p><strong>Relatório gerado em:</strong> {datetime.now().strftime("%d/%m/%Y às %H:%M:%S")}</p>
            <p>Análise completa com mapa de geolocalização e detecção de VPN/Proxy</p>
        </div>

        <!-- Estatísticas Resumidas -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{total_ips}</div>
                <div class="stat-label">Total de IPs Analisados</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{vpn_detected}</div>
                <div class="stat-label">VPN/Proxy Detectados</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{mobile_connections}</div>
                <div class="stat-label">Conexões Móveis</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{fixed_connections}</div>
                <div class="stat-label">Conexões Fixas</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{unique_countries}</div>
                <div class="stat-label">Países Únicos</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{unique_providers}</div>
                <div class="stat-label">Provedores Únicos</div>
            </div>
        </div>

        <!-- Mapa Interativo - MAIOR E MAIS VISÍVEL -->
        <div class="map-section">
            <h3 class="section-title">🗺️ Mapa de Geolocalização dos IPs</h3>
            <div id="map"></div>
            <div class="map-legend">
                <strong>Legenda:</strong>
                <span class="legend-item">
                    <span class="legend-dot" style="background: #28a745;"></span>
                    Conexão Segura
                </span>
                <span class="legend-item">
                    <span class="legend-dot" style="background: #dc3545;"></span>
                    VPN/Proxy Detectado
                </span>
                <span class="legend-item">
                    <span class="legend-dot" style="background: #ffc107;"></span>
                    Conexão Móvel
                </span>
                <span class="legend-item">
                    <span class="legend-dot" style="background: #17a2b8;"></span>
                    Indeterminado
                </span>
            </div>
        </div>

        <!-- Controles e Tabela -->
        <div class="main-content">
            <div class="form-section">
                <h3>📋 Dados do Procedimento</h3>
                <div class="form-grid">
                    <div class="form-group">
                        <label for="tipo-procedimento">Tipo de Procedimento:</label>
                        <input type="text" id="tipo-procedimento" placeholder="Ex: Inquérito Policial">
                    </div>
                    <div class="form-group">
                        <label for="numero-procedimento">Número do Procedimento:</label>
                        <input type="text" id="numero-procedimento" placeholder="Ex: 001/2025">
                    </div>
                    <div class="form-group">
                        <label for="prazo-resposta">Prazo (dias):</label>
                        <input type="text" id="prazo-resposta" placeholder="Ex: 30 (trinta) dias">
                    </div>
                    <div class="form-group">
                        <label for="email-resposta">E-mail de Resposta:</label>
                        <input type="email" id="email-resposta" placeholder="Ex: delegado@pc.go.gov.br">
                    </div>
                </div>
            </div>

            <div class="controls">
                <div class="filter-group"><label for="vpn-filter">Filtrar VPN:</label><select id="vpn-filter"><option value="">Todos</option><option value="Detectado">Detectado</option><option value="Não detectado">Não detectado</option></select></div>
                <div class="filter-group"><label for="connection-filter">Tipo Conexão:</label><select id="connection-filter"><option value="">Todos</option><option value="Móvel">Móvel</option><option value="Fixa">Fixa</option><option value="Indeterminado">Indeterminado</option></select></div>
                <div class="filter-group"><label for="country-filter">País:</label><select id="country-filter"><option value="">Todos</option></select></div>
                <div class="filter-group"><label for="provider-filter">Provedor:</label><select id="provider-filter"><option value="">Todos</option></select></div>
                <div class="filter-group"><label for="search-ip">Buscar IP:</label><input type="text" id="search-ip" placeholder="Digite um IP..."></div>
                <button class="btn" onclick="applyFilters()">Aplicar Filtros</button>
                <button class="btn" onclick="clearFilters()">Limpar</button>
            </div>

            <div id="copy-success" class="copy-success">✅ Dados copiados com sucesso!</div>

            <div class="table-container">
                <table id="results-table">
                    <thead><tr><th>IP</th><th>Porta</th><th>Data</th><th>Hora</th><th>UTC</th><th>Versão</th><th>VPN/Proxy</th><th>Tipo Conexão</th><th>País</th><th>Cidade</th><th>Provedor</th><th>Organização</th><th>AS</th></tr></thead>
                    <tbody id="results-tbody"></tbody>
                </table>
            </div>

            <div id="no-results" class="no-results" style="display: none;">Nenhum resultado encontrado com os filtros aplicados.</div>

            <div class="export-section">
                <h3>📤 Exportar/Copiar Resultados</h3>
                <button class="btn btn-copy" onclick="copiarApenas6Colunas()">📋 Copiar TABELA para Word</button>
                <button class="btn btn-export" onclick="exportToCSV()">📊 Exportar CSV</button>
                <button class="btn btn-export" onclick="exportToJSON()">📄 Exportar JSON</button>
            </div>

            <div class="oficios-section">
                <h3>📄 Geração de Ofícios por Provedor</h3>
                <div id="oficios-buttons" class="oficios-buttons"></div>
                <div id="oficio-generated" class="oficio-generated" style="display: none;">
                    <h4>📋 Ofício Gerado:</h4>
                    <div id="oficio-text" class="oficio-text"></div>
                    <button class="btn btn-copy" onclick="copyOficioToClipboard()">📋 Copiar Ofício</button>
                    <button class="btn btn-export" onclick="downloadOficio()">💾 Download Ofício</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Scripts -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script>
    
    <script>
        const allResults = {results_json};
        let filteredResults = allResults;
        let currentOficio = '';
        let map, markers = [];

        document.addEventListener('DOMContentLoaded', function() {{
            initializeMap();
            populateFilters();
            displayResults(allResults);
            generateOficioButtons();
        }});

        // FUNÇÃO NOVA E ISOLADA - APENAS 6 COLUNAS
        function copiarApenas6Colunas() {{
            console.log('Iniciando cópia das 6 colunas específicas...');
            
            // String que será copiada - começar do zero
            let textoFinal = 'IP\\tPorta\\tData\\tHora\\tUTC\\tAS\\n';
            
            // Debug: verificar quantos resultados temos
            console.log('Número de resultados filtrados:', filteredResults.length);
            
            // Processar cada resultado individualmente
            for (let i = 0; i < filteredResults.length; i++) {{
                const item = filteredResults[i];
                
                // Extrair EXATAMENTE os 6 campos
                const coluna1 = item.ip || '';
                const coluna2 = item.porta || '-';
                const coluna3 = item.data || '-';
                const coluna4 = item.hora || '-';
                const coluna5 = item.utc || '-';
                const coluna6 = item.AS || 'N/A';
                
                // Montar linha com TAB entre cada coluna
                const linha = coluna1 + '\\t' + coluna2 + '\\t' + coluna3 + '\\t' + coluna4 + '\\t' + coluna5 + '\\t' + coluna6 + '\\n';
                
                textoFinal += linha;
                
                // Debug: mostrar primeira linha
                if (i === 0) {{
                    console.log('Primeira linha:', linha);
                }}
            }}
            
            console.log('Texto final a ser copiado:', textoFinal.substring(0, 100) + '...');
            
            // Copiar para clipboard de forma mais robusta
            if (navigator.clipboard) {{
                navigator.clipboard.writeText(textoFinal).then(() => {{
                    console.log('Copiado com sucesso via navigator.clipboard');
                    mostrarMensagemSucesso('✅ APENAS 6 colunas copiadas! Cole no Word agora');
                }}).catch((erro) => {{
                    console.log('Erro navigator.clipboard:', erro);
                    usarMetodoAlternativo(textoFinal);
                }});
            }} else {{
                usarMetodoAlternativo(textoFinal);
            }}
        }}
        
        function usarMetodoAlternativo(texto) {{
            console.log('Usando método alternativo de cópia...');
            
            // Criar elemento textarea temporário
            const elementoTemp = document.createElement('textarea');
            elementoTemp.value = texto;
            elementoTemp.style.position = 'fixed';
            elementoTemp.style.left = '-9999px';
            elementoTemp.style.top = '-9999px';
            
            document.body.appendChild(elementoTemp);
            elementoTemp.focus();
            elementoTemp.select();
            
            try {{
                const sucesso = document.execCommand('copy');
                if (sucesso) {{
                    console.log('Copiado com sucesso via execCommand');
                    mostrarMensagemSucesso('✅ APENAS 6 colunas copiadas! Cole no Word agora');
                }} else {{
                    console.log('Falha no execCommand');
                    mostrarMensagemSucesso('❌ Erro ao copiar. Tente novamente.');
                }}
            }} catch (erro) {{
                console.log('Erro no execCommand:', erro);
                mostrarMensagemSucesso('❌ Erro ao copiar. Tente novamente.');
            }}
            
            document.body.removeChild(elementoTemp);
        }}
        
        function mostrarMensagemSucesso(mensagem) {{
            const elementoMensagem = document.getElementById('copy-success');
            elementoMensagem.innerHTML = mensagem;
            elementoMensagem.style.display = 'block';
            
            setTimeout(() => {{
                elementoMensagem.style.display = 'none';
            }}, 5000);
        }}

        function initializeMap() {{
            map = L.map('map').setView([-15.7801, -47.9292], 2);
            
            L.tileLayer('https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
                attribution: '© OpenStreetMap contributors',
                maxZoom: 18
            }}).addTo(map);
            
            updateMapMarkers(allResults);
        }}

        function updateMapMarkers(results) {{
            markers.forEach(marker => map.removeLayer(marker));
            markers = [];
            
            results.forEach(result => {{
                if (result.latitude && result.longitude) {{
                    const lat = parseFloat(result.latitude);
                    const lng = parseFloat(result.longitude);
                    
                    if (!isNaN(lat) && !isNaN(lng)) {{
                        let color = '#28a745';
                        let fillColor = '#28a745';
                        
                        if (result.status_vpn === 'Detectado') {{
                            color = '#dc3545';
                            fillColor = '#dc3545';
                        }}
                        else if (result.tipo_conexão === 'Móvel') {{
                            color = '#ffc107';
                            fillColor = '#ffc107';
                        }}
                        else if (result.status_vpn === 'Indeterminado' || result.tipo_conexão === 'Indeterminado') {{
                            color = '#17a2b8';
                            fillColor = '#17a2b8';
                        }}
                        
                        const marker = L.circleMarker([lat, lng], {{
                            color: color,
                            fillColor: fillColor,
                            fillOpacity: 0.8,
                            radius: 8,
                            weight: 2
                        }});
                        
                        const popupContent = createPopupContent(result);
                        marker.bindPopup(popupContent, {{
                            maxWidth: 400,
                            className: 'custom-popup'
                        }});
                        
                        marker.addTo(map);
                        markers.push(marker);
                    }}
                }}
            }});
        }}

        function createPopupContent(result) {{
            const flagEmoji = getFlagEmoji(result.código_país);
            const isSuspicious = result.status_vpn === 'Detectado' || 
                               result.tor === 'Sim' || 
                               result.hospedagem === 'Sim';
            
            return `
                <div class="popup-header">
                    ${{isSuspicious ? '⚠️ IP SUSPEITO' : '🔍 ANÁLISE DO IP'}}
                </div>
                
                <div class="popup-section">
                    <div class="popup-label">📍 Endereço IP:</div>
                    <div class="popup-value popup-ip">${{result.ip}}${{result.porta ? ':' + result.porta : ''}}</div>
                </div>
                
                ${{result.data || result.hora || result.utc ? `
                <div class="popup-section">
                    <div class="popup-label">🕐 Data/Hora:</div>
                    <div class="popup-value">
                        ${{result.data ? result.data + ' ' : ''}}${{result.hora ? 'às ' + result.hora + ' ' : ''}}${{result.utc ? '(' + result.utc + ')' : ''}}
                    </div>
                </div>
                ` : ''}}
                
                <div class="popup-section">
                    <div class="popup-label">🌍 Localização:</div>
                    <div class="popup-value popup-country">${{flagEmoji}} ${{result.país || 'Desconhecido'}}</div>
                    ${{result.cidade && result.cidade !== 'Desconhecido' ? `<div class="popup-value">📍 ${{result.cidade}}</div>` : ''}}
                </div>
                
                <div class="popup-section">
                    <div class="popup-label">🏢 Provedor de Internet:</div>
                    <div class="popup-value"><strong>${{result.provedor || 'Desconhecido'}}</strong></div>
                    ${{result.organização && result.organização !== result.provedor ? `<div class="popup-value" style="font-size: 0.8em; color: #888;">Org: ${{result.organização}}</div>` : ''}}
                </div>
                
                <div class="popup-section">
                    <div class="popup-label">🔒 Análise de Segurança:</div>
                    <div class="popup-value">
                        <strong>VPN/Proxy:</strong> <span class="${{result.status_vpn === 'Detectado' ? 'popup-alert' : 'popup-safe'}}">${{result.status_vpn || 'Indeterminado'}}</span><br>
                        <strong>Tipo de Conexão:</strong> ${{result.tipo_conexão || 'Indeterminado'}}<br>
                        ${{result.tor === 'Sim' ? '<span class="popup-alert">🚨 <strong>Rede Tor Detectada!</strong></span><br>' : ''}}
                        ${{result.hospedagem === 'Sim' ? '<span class="popup-alert">🏢 <strong>Datacenter/Hospedagem</strong></span><br>' : ''}}
                        ${{result.conexão_móvel === 'Sim' ? '📱 <strong>Conexão Móvel</strong><br>' : ''}}
                    </div>
                </div>
                
                <div class="popup-section" style="border-bottom: none;">
                    <div class="popup-label">📊 Detalhes Técnicos:</div>
                    <div class="popup-value">
                        <strong>Versão IP:</strong> ${{result.ip_version}}<br>
                        <strong>AS Number:</strong> ${{result.AS || 'N/A'}}<br>
                        ${{result.região && result.região !== 'Desconhecido' ? '<strong>Região:</strong> ' + result.região : ''}}
                    </div>
                </div>
                
                ${{isSuspicious ? `
                <div style="margin-top: 10px; padding: 8px; background: #f8d7da; border-radius: 5px; border-left: 4px solid #dc3545;">
                    <strong style="color: #721c24;">⚠️ Recomendação:</strong><br>
                    <span style="color: #721c24; font-size: 0.85em;">Este IP requer investigação adicional devido aos indicadores de risco detectados.</span>
                </div>
                ` : ''}}
            `;
        }}

        function getFlagEmoji(countryCode) {{
            const flags = {{
                'BR': '🇧🇷', 'US': '🇺🇸', 'CN': '🇨🇳', 'RU': '🇷🇺', 'DE': '🇩🇪',
                'FR': '🇫🇷', 'GB': '🇬🇧', 'JP': '🇯🇵', 'KR': '🇰🇷', 'IN': '🇮🇳',
                'CA': '🇨🇦', 'AU': '🇦🇺', 'IT': '🇮🇹', 'ES': '🇪🇸', 'NL': '🇳🇱',
                'SE': '🇸🇪', 'NO': '🇳🇴', 'CH': '🇨🇭', 'SG': '🇸🇬', 'HK': '🇭🇰'
            }};
            return flags[countryCode] || '🌍';
        }}

        function populateFilters() {{
            populateCountryFilter();
            populateProviderFilter();
        }}

        function populateCountryFilter() {{
            const countryFilter = document.getElementById('country-filter');
            const countries = [...new Set(allResults.map(r => r.país))].sort();
            countries.forEach(country => {{
                if (country && country !== 'Erro na consulta') {{
                    const option = document.createElement('option');
                    option.value = country;
                    option.textContent = country;
                    countryFilter.appendChild(option);
                }}
            }});
        }}

        function populateProviderFilter() {{
            const providerFilter = document.getElementById('provider-filter');
            const providers = [...new Set(allResults.map(r => r.provedor))].sort();
            providers.forEach(provider => {{
                if (provider && provider !== 'Erro na consulta') {{
                    const option = document.createElement('option');
                    option.value = provider;
                    option.textContent = provider;
                    providerFilter.appendChild(option);
                }}
            }});
        }}

        function displayResults(results) {{
            const tbody = document.getElementById('results-tbody');
            const noResults = document.getElementById('no-results');
            
            if (results.length === 0) {{
                tbody.innerHTML = '';
                noResults.style.display = 'block';
                return;
            }}
            
            noResults.style.display = 'none';
            
            tbody.innerHTML = results.map(result => {{
                const vpnStatus = getVPNStatus(result);
                const connectionStatus = getConnectionStatus(result);
                
                return `
                    <tr>
                        <td><span class="ip-version">${{result.ip}}</span></td>
                        <td>${{result.porta || '-'}}</td>
                        <td>${{result.data || '-'}}</td>
                        <td>${{result.hora || '-'}}</td>
                        <td>${{result.utc || '-'}}</td>
                        <td><span class="status-badge status-info">${{result.ip_version}}</span></td>
                        <td><span class="status-badge ${{vpnStatus.class}}">${{vpnStatus.text}}</span></td>
                        <td><span class="status-badge ${{connectionStatus.class}}">${{connectionStatus.text}}</span></td>
                        <td>${{result.país || 'N/A'}}</td>
                        <td>${{result.cidade || 'N/A'}}</td>
                        <td>${{result.provedor || 'N/A'}}</td>
                        <td>${{result.organização || 'N/A'}}</td>
                        <td>${{result.AS || 'N/A'}}</td>
                    </tr>
                `;
            }}).join('');
        }}

        function getVPNStatus(result) {{
            if (result.status_vpn === 'Detectado') {{
                return {{ class: 'status-danger', text: 'Detectado' }};
            }} else if (result.status_vpn === 'Não detectado') {{
                return {{ class: 'status-safe', text: 'Não detectado' }};
            }} else {{
                return {{ class: 'status-warning', text: 'Indeterminado' }};
            }}
        }}

        function getConnectionStatus(result) {{
            if (result.tipo_conexão === 'Móvel') {{
                return {{ class: 'status-warning', text: 'Móvel' }};
            }} else if (result.tipo_conexão === 'Fixa') {{
                return {{ class: 'status-safe', text: 'Fixa' }};
            }} else {{
                return {{ class: 'status-info', text: 'Indeterminado' }};
            }}
        }}

        function applyFilters() {{
            const vpnFilter = document.getElementById('vpn-filter').value;
            const connectionFilter = document.getElementById('connection-filter').value;
            const countryFilter = document.getElementById('country-filter').value;
            const providerFilter = document.getElementById('provider-filter').value;
            const searchIP = document.getElementById('search-ip').value.toLowerCase();

            filteredResults = allResults.filter(result => {{
                const matchVPN = !vpnFilter || result.status_vpn === vpnFilter;
                const matchConnection = !connectionFilter || result.tipo_conexão === connectionFilter;
                const matchCountry = !countryFilter || result.país === countryFilter;
                const matchProvider = !providerFilter || result.provedor === providerFilter;
                const matchIP = !searchIP || result.ip.toLowerCase().includes(searchIP);

                return matchVPN && matchConnection && matchCountry && matchProvider && matchIP;
            }});

            displayResults(filteredResults);
            updateMapMarkers(filteredResults);
            generateOficioButtons();
        }}

        function clearFilters() {{
            document.getElementById('vpn-filter').value = '';
            document.getElementById('connection-filter').value = '';
            document.getElementById('country-filter').value = '';
            document.getElementById('provider-filter').value = '';
            document.getElementById('search-ip').value = '';
            
            filteredResults = allResults;
            displayResults(allResults);
            updateMapMarkers(allResults);
            generateOficioButtons();
        }}

        function generateOficioButtons() {{
            const oficiosContainer = document.getElementById('oficios-buttons');
            
            const groupedByProvider = {{}};
            filteredResults.forEach(result => {{
                const provider = result.provedor || 'Provedor Desconhecido';
                if (!groupedByProvider[provider]) {{
                    groupedByProvider[provider] = [];
                }}
                groupedByProvider[provider].push(result);
            }});

            oficiosContainer.innerHTML = '';
            Object.keys(groupedByProvider).forEach(provider => {{
                if (provider !== 'Erro na consulta') {{
                    const button = document.createElement('button');
                    button.className = 'btn btn-oficio';
                    button.textContent = `📄 Gerar Ofício - ${{provider}} (${{groupedByProvider[provider].length}} IPs)`;
                    button.onclick = () => generateOficio(provider, groupedByProvider[provider]);
                    oficiosContainer.appendChild(button);
                }}
            }});
        }}

        function generateOficio(provider, ips) {{
            const tipoProcedimento = document.getElementById('tipo-procedimento').value || '[TIPO DE PROCEDIMENTO]';
            const numeroProcedimento = document.getElementById('numero-procedimento').value || '[NÚMERO DO PROCEDIMENTO]';
            const prazo = document.getElementById('prazo-resposta').value || '[PRAZO]';
            const email = document.getElementById('email-resposta').value || '[EMAIL DE RESPOSTA]';

            let ipsText = '';
            ips.forEach((ip, index) => {{
                let linha = `${{index + 1}}. IP: ${{ip.ip}}`;
                
                if (ip.porta && ip.porta.trim() !== '') {{
                    linha += `, Porta: ${{ip.porta}}`;
                }}
                
                if (ip.data && ip.data.trim() !== '') {{
                    linha += `, Data: ${{ip.data}}`;
                }}
                
                if (ip.hora && ip.hora.trim() !== '') {{
                    linha += `, Horário: ${{ip.hora}}`;
                }}
                
                if (ip.utc && ip.utc.trim() !== '') {{
                    linha += ` (${{ip.utc}})`;
                }}
                
                ipsText += linha + '\\n';
            }});

            const oficioText = `Senhor Diretor da ${{provider}},

Visando instruir o ${{tipoProcedimento}} nº ${{numeroProcedimento}}, na qualidade de Delegado(a) de Polícia Civil, no exercício das atribuições que me conferem os art. 144, § 4º, da CF c/c art. 2º, §2º, da Lei 12.830/2013, e com fundamento nos arts. 10, §3º e 15, da Lei 12.965/2014 c/c art. 17-B da Lei 9.613/98 e art. 15 da Lei 12.850/2013, requisito, no prazo de ${{prazo}}, os dados cadastrais vinculados ao(s) IP(s):

${{ipsText}}
Adicionalmente, requisito, com base no art. 15, § 1º, da Lei nº 12.965/2014, a preservação do conteúdo das comunicações privadas e de todos os registros de conexão e de acesso a aplicações de internet relacionados ao(s) identificador(es) acima mencionado(s), pelo período de 1 (um) ano, a partir da data desta comunicação, a fim de viabilizar futura ordem judicial para acesso ao seu conteúdo.

A investigação policial é sigilosa (art. 20 CPP) e, por isso, o usuário não deve ser notificado acerca das requisições policiais.

Por fim, solicito que a resposta seja encaminhada para o e-mail ${{email}}.

Atenciosamente,`;

            document.getElementById('oficio-text').textContent = oficioText;
            document.getElementById('oficio-generated').style.display = 'block';
            currentOficio = oficioText;

            document.getElementById('oficio-generated').scrollIntoView({{ behavior: 'smooth' }});
        }}

        function copyOficioToClipboard() {{
            navigator.clipboard.writeText(currentOficio).then(function() {{
                const successMsg = document.getElementById('copy-success');
                successMsg.innerHTML = '✅ Ofício copiado com sucesso!';
                successMsg.style.display = 'block';
                setTimeout(() => {{
                    successMsg.style.display = 'none';
                }}, 3000);
            }});
        }}

        function downloadOficio() {{
            const provider = 'Oficio_' + new Date().toISOString().slice(0,10);
            const filename = `${{provider}}.txt`;
            downloadFile(currentOficio, filename, 'text/plain');
        }}

        function copyTableToClipboard() {{
            let htmlTable = `
            <table border="1" style="border-collapse: collapse; width: 100%; font-family: Arial, sans-serif;">
                <thead>
                    <tr style="background-color: #667eea; color: white;">
                        <th style="padding: 8px; text-align: left;">IP</th>
                        <th style="padding: 8px; text-align: left;">Porta</th>
                        <th style="padding: 8px; text-align: left;">Data</th>
                        <th style="padding: 8px; text-align: left;">Hora</th>
                        <th style="padding: 8px; text-align: left;">UTC</th>
                        <th style="padding: 8px; text-align: left;">Versão</th>
                        <th style="padding: 8px; text-align: left;">VPN/Proxy</th>
                        <th style="padding: 8px; text-align: left;">Tipo Conexão</th>
                        <th style="padding: 8px; text-align: left;">País</th>
                        <th style="padding: 8px; text-align: left;">Cidade</th>
                        <th style="padding: 8px; text-align: left;">Provedor</th>
                        <th style="padding: 8px; text-align: left;">Organização</th>
                        <th style="padding: 8px; text-align: left;">AS</th>
                    </tr>
                </thead>
                <tbody>`;
            
            filteredResults.forEach((result, index) => {{
                const vpnText = result.status_vpn || 'N/A';
                const connectionText = result.tipo_conexão || 'N/A';
                const rowStyle = index % 2 === 0 ? 'background-color: #f8f9fa;' : 'background-color: white;';
                
                htmlTable += `
                    <tr style="${{rowStyle}}">
                        <td style="padding: 6px; border: 1px solid #ddd;">${{result.ip}}</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${{result.porta || '-'}}</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${{result.data || '-'}}</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${{result.hora || '-'}}</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${{result.utc || '-'}}</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${{result.ip_version}}</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${{vpnText}}</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${{connectionText}}</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${{result.país || 'N/A'}}</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${{result.cidade || 'N/A'}}</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${{result.provedor || 'N/A'}}</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${{result.organização || 'N/A'}}</td>
                        <td style="padding: 6px; border: 1px solid #ddd;">${{result.AS || 'N/A'}}</td>
                    </tr>`;
            }});
            
            htmlTable += `
                </tbody>
            </table>`;

            const blob = new Blob([htmlTable], {{ type: 'text/html' }});
            const clipboardItem = new ClipboardItem({{ 'text/html': blob }});
            
            navigator.clipboard.write([clipboardItem]).then(function() {{
                const successMsg = document.getElementById('copy-success');
                successMsg.innerHTML = '✅ Tabela copiada como HTML! Cole no Word para obter formatação perfeita';
                successMsg.style.display = 'block';
                setTimeout(() => {{
                    successMsg.style.display = 'none';
                }}, 4000);
            }}).catch(function(err) {{
                let tableText = 'IP\\tPorta\\tData\\tHora\\tUTC\\tVersão\\tVPN/Proxy\\tTipo Conexão\\tPaís\\tCidade\\tProvedor\\tOrganização\\tAS\\n';
                
                filteredResults.forEach(result => {{
                    const vpnText = result.status_vpn || 'N/A';
                    const connectionText = result.tipo_conexão || 'N/A';
                    
                    tableText += `${{result.ip}}\\t${{result.porta || '-'}}\\t${{result.data || '-'}}\\t${{result.hora || '-'}}\\t${{result.utc || '-'}}\\t${{result.ip_version}}\\t${{vpnText}}\\t${{connectionText}}\\t${{result.país || 'N/A'}}\\t${{result.cidade || 'N/A'}}\\t${{result.provedor || 'N/A'}}\\t${{result.organização || 'N/A'}}\\t${{result.AS || 'N/A'}}\\n`;
                }});

                const textArea = document.createElement('textarea');
                textArea.value = tableText;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                
                const successMsg = document.getElementById('copy-success');
                successMsg.innerHTML = '✅ Tabela copiada! No Word: Cole > Inserir > Tabela > Converter texto em tabela';
                successMsg.style.display = 'block';
                setTimeout(() => {{
                    successMsg.style.display = 'none';
                }}, 5000);
            }});
        }}

        function exportToCSV() {{
            const headers = ['IP', 'Porta', 'Data', 'Hora', 'UTC', 'Versão', 'VPN_Proxy', 'Tipo_Conexão', 'País', 'Cidade', 'Provedor', 'Organização', 'AS'];
            
            let csvContent = headers.join(',') + '\\n';
            
            filteredResults.forEach(result => {{
                const row = [
                    result.ip,
                    result.porta || '',
                    result.data || '',
                    result.hora || '',
                    result.utc || '',
                    result.ip_version,
                    `"${{result.status_vpn}}"`,
                    `"${{result.tipo_conexão}}"`,
                    `"${{result.país}}"`,
                    `"${{result.cidade}}"`,
                    `"${{result.provedor}}"`,
                    `"${{result.organização}}"`,
                    `"${{result.AS}}"`
                ];
                csvContent += row.join(',') + '\\n';
            }});

            downloadFile(csvContent, 'analise_ips_filtrada.csv', 'text/csv');
        }}

        function exportToJSON() {{
            const jsonData = JSON.stringify(filteredResults, null, 2);
            downloadFile(jsonData, 'analise_ips_filtrada.json', 'application/json');
        }}

        function downloadFile(content, fileName, contentType) {{
            const blob = new Blob([content], {{ type: contentType }});
            const url = window.URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = fileName;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            window.URL.revokeObjectURL(url);
        }}

        document.getElementById('search-ip').addEventListener('input', function() {{
            applyFilters();
        }});

        window.addEventListener('resize', function() {{
            setTimeout(function() {{
                map.invalidateSize();
            }}, 100);
        }});
    </script>
</body>
</html>'''
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    return output_file

def analyze_and_generate_dashboard():
    print("="*60)
    print("ANALISADOR DE IPs COM MAPA INTERATIVO OTIMIZADO")
    print("="*60)
    print("Este script analisa IPs e gera um dashboard HTML com:")
    print("• Mapa interativo de geolocalização (tela grande)")
    print("• Pop-ups informativos detalhados")
    print("• Sistema de cores por tipo de ameaça")
    print("• Tabela completa com todos os IPs por padrão")
    print("• Geração automática de ofícios por provedor")
    print("="*60)
    
    print("\nOpções de entrada:")
    print("1. Digitar IPs manualmente")
    print("2. Carregar de arquivo (um IP por linha)")
    print("\nFormatos aceitos:")
    print("- IP simples: 8.8.8.8")
    print("- IP com porta: 8.8.8.8:80")
    print("- IP com dados completos: 8.8.8.8 80 01/01/2025 10:30:00 UTC-3")
    
    choice = input("\nEscolha uma opção (1-2): ").strip()
    
    ip_list = []
    
    if choice == '1':
        print("\nDigite os IPs a serem analisados:")
        print("- Um IP por linha")
        print("- Digite 'fim' para finalizar")
        print("\nExemplos:")
        print("8.8.8.8")
        print("1.1.1.1:443")
        print("8.8.4.4 53 02/08/2025 14:30:00 UTC-3")
        print("\nDigite os IPs:")
        
        while True:
            line = input().strip()
            if line.lower() == 'fim':
                break
            if line:
                ip_data = parse_ip_entry(line)
                if is_valid_ip(ip_data['ip']):
                    ip_list.append(line)
                else:
                    print(f"IP inválido ignorado: {line}")
    
    elif choice == '2':
        filename = input("Digite o nome do arquivo: ").strip()
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line:
                        ip_data = parse_ip_entry(line)
                        if is_valid_ip(ip_data['ip']):
                            ip_list.append(line)
                        else:
                            print(f"Linha {line_num} - IP inválido ignorado: {line}")
        except FileNotFoundError:
            print(f"Arquivo '{filename}' não encontrado.")
            return
        except Exception as e:
            print(f"Erro ao ler arquivo: {e}")
            return
    
    else:
        print("Opção inválida.")
        return
    
    if not ip_list:
        print("Nenhum IP válido fornecido.")
        return
    
    print(f"\n{len(ip_list)} entradas válidas encontradas.")
    
    confirm = input("Deseja prosseguir com a análise? (s/n): ").strip().lower()
    if confirm not in ['s', 'sim', 'y', 'yes']:
        print("Análise cancelada.")
        return
    
    print(f"\nIniciando análise de {len(ip_list)} IPs...")
    print("Este processo pode levar alguns minutos...")
    
    # Executar análise
    results = check_batch_ips(ip_list)
    
    # Gerar dashboard
    print("\nGerando dashboard HTML otimizado...")
    dashboard_file = generate_html_dashboard(results)
    
    print(f"\n✅ Dashboard otimizado gerado com sucesso!")
    print(f"📄 Arquivo: {dashboard_file}")
    print(f"\n🎯 RECURSOS IMPLEMENTADOS:")
    print(f"🗺️  Mapa interativo grande e visível")
    print(f"💬  Pop-ups informativos detalhados")
    print(f"🎨  Sistema de cores por tipo de ameaça")
    print(f"📋  Tabela mostra todos os IPs por padrão")
    print(f"📄  Geração de ofícios por provedor")
    print(f"📤  Exportação para Word/CSV/JSON")
    
    # Perguntar se deseja abrir automaticamente
    open_choice = input("\nDeseja abrir o dashboard automaticamente? (s/n): ").strip().lower()
    if open_choice in ['s', 'sim', 'y', 'yes']:
        try:
            import webbrowser
            webbrowser.open(f'file://{os.path.abspath(dashboard_file)}')
            print("Dashboard aberto no navegador padrão.")
        except Exception as e:
            print(f"Erro ao abrir automaticamente: {e}")
            print("Abra manualmente o arquivo no navegador.")

def main():
    """
    Função principal
    """
    try:
        # Verificar se as bibliotecas necessárias estão instaladas
        required_modules = ['requests']
        missing_modules = []
        
        for module in required_modules:
            try:
                __import__(module)
            except ImportError:
                missing_modules.append(module)
        
        if missing_modules:
            print("Módulos necessários não encontrados:")
            for module in missing_modules:
                print(f"- {module}")
            print("\nInstale os módulos com: pip install " + " ".join(missing_modules))
            sys.exit(1)
        
        analyze_and_generate_dashboard()
        
    except KeyboardInterrupt:
        print("\n\nPrograma interrompido pelo usuário. Até logo!")
        sys.exit(0)
    except Exception as e:
        print(f"\nErro inesperado: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()