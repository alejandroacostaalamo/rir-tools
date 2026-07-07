import requests
import ipaddress
import time

'''
Validador RPKI de prefijos IPv4 e IPv6 apoyado en info publica de Cloudflare
Julio 2026

¿Cómo usar? En la lista lote_trabajo debes poner los prefijos / asn que deseas validar.

VALID para las firmas exactas (tanto IPv4 como IPv6).
VALID para el sub-prefijo /24 gracias a la validación dinámica de maxLength en el bloque /23.
INVALID cuando el prefijo existe pero el ASN (99999) no está autorizado.
UNKNOWN para redes de prueba que no tienen registros criptográficos creados en los RIRs.

'''

def descargar_base_roas() -> list:
    """
    Descarga el volcado completo de Cloudflare una única vez.
    """
    # IMPORTANTE: Reemplaza esta cadena por la URL real de Cloudflare rpki.json
    url_cloudflare = "https://rpki.cloudflare.com/rpki.json"

    cabeceras = {'User-Agent': 'ProcesadorMasivoRPKI/1.0'}
    
    try:
        print("📥 Descargando base de datos global de Cloudflare (esto puede tardar unos segundos)...")
        response = requests.get(url_cloudflare, headers=cabeceras, timeout=30)
        if response.status_code == 200:
            print(" Base de datos descargada con éxito.")
            return response.json().get('roas', [])
    except Exception as e:
        print(f" Error crítico al descargar la base de datos: {e}")
    return []

def optimizar_roas_con_rangos(roas: list) -> list:
    """
    Procesa la lista de Cloudflare convirtiendo las cadenas en objetos de red reales.
    Guarda el objeto de red, el ASN y el maxLength permitido.
    """
    print("⚡ Analizando y estructurando redes IP en memoria...")
    lista_objetos_roa = []
    
    for roa in roas:
        prefijo_txt = roa.get('prefix')
        asn_txt = roa.get('asn')
        max_len = roa.get('maxLength')
        
        try:
            # Convertimos a objeto matemático de Python (soporta IPv4 e IPv6)
            red_objeto = ipaddress.ip_network(prefijo_txt)
            asn = int(str(asn_txt).upper().replace("AS", ""))
            
            # Si no hay maxLength especificado en el ROA, por estándar es igual a la máscara base
            if max_len is None:
                max_len = red_objeto.prefixlen
            else:
                max_len = int(max_len)
                
            lista_objetos_roa.append({
                'red': red_objeto,
                'asn': asn,
                'max_length': max_len
            })
        except Exception:
            continue # Salta registros malformados o vacíos
            
    return lista_objetos_roa

def verificar_lista_con_rangos(lista_objetivos: list, lista_roas_objeto: list) -> list:
    """
    Evalúa si el prefijo anunciado está contenido matemáticamente en un ROA
    y si cumple con la restricción de longitud máxima (maxLength) y ASN.
    Evita mezclar versiones IPv4/IPv6 durante la validación.
    """
    resultados = []
    print(f"🔍 Evaluando {len(lista_objetivos)} objetivos de red...")
    
    for item in lista_objetivos:
        prefijo_usuario = item.get('prefijo')
        asn_usuario = item.get('asn')
        descripcion = item.get('descripcion', 'Sin descripción')
        
        try:
            red_usuario = ipaddress.ip_network(prefijo_usuario)
            asn_buscado = int(str(asn_usuario).upper().replace("AS", ""))
        except Exception:
            resultados.append({
                'prefijo': prefijo_usuario, 
                'asn': asn_usuario, 
                'status': 'ERROR_FORMATO',
                'desc': descripcion
            })
            continue

        coincide_red_base = False
        prefijo_es_valido = False
        
        for roa in lista_roas_objeto:
            # FILTRO CRÍTICO: Solo comparar si ambas redes son IPv4 o ambas son IPv6
            if red_usuario.version != roa['red'].version:
                continue
                
            # Ahora la comparación matemática es 100% segura
            if red_usuario.subnet_of(roa['red']):
                coincide_red_base = True
                
                # Reglas RPKI: 1) Máscara dentro del maxLength permitido y 2) ASN correcto
                if red_usuario.prefixlen <= roa['max_length'] and asn_buscado == roa['asn']:
                    prefijo_es_valido = True
                    break # Encontró el ROA autorizado, no necesita seguir buscando

        if prefijo_es_valido:
            status = "VALID"
        elif coincide_red_base:
            status = "INVALID"
        else:
            status = "UNKNOWN"
            
        resultados.append({
            'prefijo': prefijo_usuario,
            'asn': asn_buscado,
            'status': status,
            'desc': descripcion
        })
        
    return resultados

# --- BLOQUE DE EJECUCIÓN PRINCIPAL CON EJEMPLOS REALES ---
if __name__ == "__main__":
    # 1. Cargar la base de datos global una sola vez
    lista_roas_global = descargar_base_roas()
    
    if not lista_roas_global:
        print(" No se puede continuar sin la base de datos de origen.")
        exit()
        
    # 2. Convertir los datos a objetos de red indexables
    lista_roas_procesada = optimizar_roas_con_rangos(lista_roas_global)
    
    # 3. Lote de ejemplos cubriendo los escenarios más importantes (incluyendo MaxLength e IPv6)
    lote_trabajo = [
        {
            "prefijo": "1.1.1.0/24", 
            "asn": 13335, 
            "descripcion": "Caso Base IPv4 (DNS Cloudflare)"
        },
        {
            "prefijo": "1.0.0.0/24", 
            "asn": 13335, 
            "descripcion": "Sub-prefijo /24 contenido en un ROA /23 con MaxLength /24"
        },
        {
            "prefijo": "2606:4700:4700::/48", 
            "asn": 13335, 
            "descripcion": "Caso Base IPv6 (DNS Cloudflare IPv6)"
        },
        {
            "prefijo": "1.1.1.0/24", 
            "asn": 99999, 
            "descripcion": "Mismo prefijo válido pero anunciado por un ASN pirata/incorrecto"
        },
        {
            "prefijo": "192.0.2.0/24", 
            "asn": 64496, 
            "descripcion": "Prefijo de prueba/documentación sin registro ROA en internet"
        }
    ]
    
    # 4. Procesar la auditoría masiva midiendo el tiempo de ejecución
    tiempo_inicio = time.time()
    auditoria = verificar_lista_con_rangos(lote_trabajo, lista_roas_procesada)
    tiempo_fin = time.time()
    
    # 5. Mostrar el reporte estructurado en consola
    print("\n📊 --- REPORTE DE AUDITORÍA RPKI MASIVA ---")
    print(f"{'PREFIJO':<25} | {'ASN':<6} | {'ESTADO RPKI':<12} | {'ESCENARIO EVALUADO'}")
    print("-" * 90)
    
    for res in auditoria:
        print(f"{res['prefijo']:<25} | {res['asn']:<6} | {res['status']:<12} | {res['desc']}")
        
    print(f"\n⏱️ Procesamiento masivo completado en {tiempo_fin - tiempo_inicio:.4f} segundos.")


