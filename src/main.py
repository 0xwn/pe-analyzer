#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import re
import pefile
import math
import os
from datetime import datetime, timezone

# --- Constantes e Configurações ---

# Tamanho mínimo padrão para extração de strings
DEFAULT_MIN_STRING_LEN = 4

# Regex para strings ASCII (caracteres imprimíveis + espaço)
ASCII_STRING_RE = re.compile(b'([\x20-\x7E]{' + str(DEFAULT_MIN_STRING_LEN).encode() + b',})')

# Regex para strings Unicode (UTF-16LE - comum no Windows)
# Busca por caracteres ASCII imprimíveis seguidos por um byte nulo
UNICODE_STRING_RE = re.compile(b'((?:[\x20-\x7E]\x00){' + str(DEFAULT_MIN_STRING_LEN).encode() + b',})')

# --- Categorias de Strings e Palavras-chave ---

# Referências de Rede (Regex simplificado para demonstração)
NETWORK_PATTERNS = {
    "URL": re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', re.IGNORECASE),
    "Domain": re.compile(r'([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}', re.IGNORECASE),
    "IPv4": re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
    "UserAgent": re.compile(r'User-Agent:', re.IGNORECASE)
}

# Funções/APIs Suspeitas (Case-Insensitive)
SUSPICIOUS_APIS = {
    # Alocação/Execução de Memória
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "HeapAlloc", "HeapCreate",
    "CreateThread", "CreateRemoteThread", "ResumeThread", "SetThreadContext",
    "QueueUserAPC", "NtQueueApcThread",
    "ShellExecute", "ShellExecuteEx", "WinExec", "CreateProcess",
    # Carregamento de DLLs/Funções
    "LoadLibrary", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetProcAddress", "LdrLoadDll", "LdrGetProcedureAddress",
    # Injeção/Hooking
    "SetWindowsHookEx", "SetWindowsHookExA", "SetWindowsHookExW",
    "WriteProcessMemory", "ReadProcessMemory",
    # Rede
    "socket", "connect", "bind", "listen", "accept", "send", "recv",
    "InternetOpen", "InternetOpenA", "InternetOpenW",
    "InternetConnect", "InternetConnectA", "InternetConnectW",
    "HttpOpenRequest", "HttpOpenRequestA", "HttpOpenRequestW",
    "HttpSendRequest", "HttpSendRequestA", "HttpSendRequestW",
    "InternetReadFile", "URLDownloadToFile", "URLDownloadToFileA", "URLDownloadToFileW",
    # Persistência
    "RegCreateKey", "RegCreateKeyEx", "RegSetValue", "RegSetValueEx",
    "CreateService", "OpenService", "StartService",
    # Keylogging/Screen Capture
    "GetAsyncKeyState", "GetKeyState", "GetKeyboardState",
    "SetClipboardData", "GetClipboardData",
    "BitBlt", "GetDC", "CreateCompatibleDC", "CreateCompatibleBitmap",
    # Criptografia (Pode ser legítimo, mas comum em ransomware)
    "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContext",
    # Anti-Debug/Anti-VM
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "GetTickCount",
    "OutputDebugString", "FindWindow", "FindWindowA", "FindWindowW",
    # File System
    "CreateFile", "WriteFile", "ReadFile", "DeleteFile", "CopyFile", "MoveFile",
    "GetTempPath", "GetTempFileName"
}
# Regex para encontrar APIs exatas (considerando A/W sufixos e case-insensitivity)
SUSPICIOUS_API_RE = re.compile(r'\b(' + '|'.join(re.escape(api) for api in SUSPICIOUS_APIS) + r')\b', re.IGNORECASE)


# Comandos Maliciosos (Case-Insensitive)
MALICIOUS_COMMANDS = {
    "cmd.exe", "powershell.exe", "powershell", "pwsh", "bash.exe", "wsl.exe",
    "net user", "net group", "net localgroup", "netsh",
    "schtasks", "at", "reg add", "reg delete", "regsvr32",
    "bitsadmin", "certutil", "wget", "curl", "ftp", "tftp",
    "taskkill", "sc create", "sc delete", "sc start", "sc stop",
    "rundll32", "mshta", "nc"
}
MALICIOUS_COMMAND_RE = re.compile(r'\b(' + '|'.join(re.escape(cmd) for cmd in MALICIOUS_COMMANDS) + r')\b', re.IGNORECASE)


# Indicadores de Packing/Ofuscação (Case-Insensitive)
PACKER_INDICATORS = {
    # Nomes de Packers Comuns
    "UPX", "ASPack", "ASProtect", "FSG", "PECompact", "PEShield",
    "Themida", "WinLicense", "VMProtect", "Enigma Protector", "Obsidium",
    "MPRESS", "NSPack", ".petite",
    # Strings Comuns em Seções de Packers ou Stubs
    "packed", "compressed", "encrypted", "stub", "loader",
    "virtual machine", "debugger", "disassembler",
    # Nomes de Seções Comuns de Packers
    ".upx", ".aspack", ".themida", ".vmp", ".nsp", ".petite"
}
PACKER_INDICATOR_RE = re.compile(r'(' + '|'.join(re.escape(ind) for ind in PACKER_INDICATORS) + r')', re.IGNORECASE)


# --- Funções Auxiliares ---

def calculate_entropy(data):
    """Calcula a entropia de Shannon para um bloco de dados."""
    if not data:
        return 0.0
    entropy = 0.0
    data_len = len(data)
    byte_counts = {}
    for byte in data:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1

    for count in byte_counts.values():
        p_x = count / data_len
        entropy -= p_x * math.log2(p_x)
    return entropy

def is_valid_ip(ip_str):
    """Valida se uma string parece ser um endereço IPv4 válido."""
    parts = ip_str.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        num = int(part)
        if not 0 <= num <= 255:
            return False
        # Evitar IPs privados ou reservados se necessário (opcional)
        # if ip_str.startswith(('10.', '172.16.', '192.168.', '127.')):
        #     return False
    return True

# --- Funções Principais ---

def parse_pe_file(file_path):
    """
    Analisa o arquivo PE e extrai informações básicas.
    Retorna o objeto PE e um dicionário com informações, ou None em caso de erro.
    """
    pe_info = {}
    try:
        pe = pefile.PE(file_path, fast_load=True) # fast_load pode ser útil

        # Validar assinatura PE
        if not pe.is_exe() and not pe.is_dll():
             print(f"[-] Aviso: Arquivo '{file_path}' não parece ser um EXE ou DLL válido.")
             # Pode não ser um erro fatal, continuar a análise se possível

        pe_info['file_path'] = file_path
        pe_info['file_size'] = os.path.getsize(file_path)

        # Detectar Arquitetura
        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            pe_info['architecture'] = '32-bit'
        elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            pe_info['architecture'] = '64-bit'
        else:
            pe_info['architecture'] = 'Desconhecida'

        pe_info['timestamp'] = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        pe_info['entry_point'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        pe_info['image_base'] = hex(pe.OPTIONAL_HEADER.ImageBase)
        pe_info['num_sections'] = pe.FILE_HEADER.NumberOfSections

        # Extrair informações das seções
        pe_info['sections'] = []
        for section in pe.sections:
            try:
                name = section.Name.decode().rstrip('\x00')
            except UnicodeDecodeError:
                name = repr(section.Name) # Representação se não for decodificável

            section_data = section.get_data()
            entropy = calculate_entropy(section_data)
            pe_info['sections'].append({
                'name': name,
                'virtual_address': hex(section.VirtualAddress),
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'characteristics': hex(section.Characteristics),
                'entropy': round(entropy, 3)
            })

        # Carregar Imports (necessário para heurísticas)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        pe_info['imports'] = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                functions = []
                for imp in entry.imports:
                    func_name = None
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                    elif imp.ordinal:
                         func_name = f"Ordinal_{imp.ordinal}" # Import por ordinal
                    if func_name:
                        functions.append(func_name)
                if dll_name and functions:
                    pe_info['imports'].append({'dll': dll_name, 'functions': functions})

        return pe, pe_info

    except pefile.PEFormatError as e:
        print(f"[!] Erro: Arquivo '{file_path}' não é um PE válido ou está corrompido: {e}")
        return None, None
    except Exception as e:
        print(f"[!] Erro inesperado ao analisar '{file_path}': {e}")
        return None, None

def extract_strings_from_data(data, base_offset=0, min_len=DEFAULT_MIN_STRING_LEN):
    """Extrai strings ASCII e Unicode de um bloco de dados."""
    strings = []

    # Recriar regex com o min_len correto se for diferente do padrão
    if min_len != DEFAULT_MIN_STRING_LEN:
        ascii_re = re.compile(b'([\x20-\x7E]{' + str(min_len).encode() + b',})')
        unicode_re = re.compile(b'((?:[\x20-\x7E]\x00){' + str(min_len).encode() + b',})')
    else:
        ascii_re = ASCII_STRING_RE
        unicode_re = UNICODE_STRING_RE

    # Extrair ASCII
    for match in ascii_re.finditer(data):
        offset = base_offset + match.start()
        try:
            string = match.group(0).decode('ascii')
            strings.append({'offset': offset, 'string': string, 'type': 'ASCII', 'length': len(string)})
        except UnicodeDecodeError:
            pass # Ignorar se não for ASCII válido (raro com essa regex)

    # Extrair Unicode (UTF-16LE)
    for match in unicode_re.finditer(data):
        offset = base_offset + match.start()
        try:
            # Remove o byte nulo final se existir (pode acontecer com a regex)
            raw_unicode = match.group(1)
            string = raw_unicode.decode('utf-16le')
            strings.append({'offset': offset, 'string': string, 'type': 'Unicode', 'length': len(string)})
        except UnicodeDecodeError:
            pass # Ignorar sequências mal formadas

    # Ordenar por offset
    strings.sort(key=lambda x: x['offset'])
    return strings

def analyze_strings(file_path, pe, min_len=DEFAULT_MIN_STRING_LEN, analyze_section=None):
    """
    Extrai e classifica strings do arquivo PE inteiro ou de uma seção específica.
    """
    all_strings = []
    strings_by_section = {}

    if analyze_section:
        found_section = False
        for section in pe.sections:
            try:
                name = section.Name.decode().rstrip('\x00')
            except UnicodeDecodeError:
                name = None

            if name and name.lower() == analyze_section.lower():
                print(f"[*] Analisando strings apenas na seção: {name}")
                section_data = section.get_data()
                section_offset = section.PointerToRawData
                all_strings = extract_strings_from_data(section_data, section_offset, min_len)
                strings_by_section[name] = all_strings
                found_section = True
                break
        if not found_section:
            print(f"[!] Aviso: Seção '{analyze_section}' não encontrada. Analisando o arquivo inteiro.")
            analyze_section = None # Reseta para analisar tudo

    if not analyze_section: # Analisa o arquivo inteiro se nenhuma seção específica foi pedida ou encontrada
        print(f"[*] Extraindo strings (min_len={min_len}) do arquivo inteiro...")
        # Opção 1: Ler o arquivo inteiro (mais simples, pode usar mais memória)
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            all_strings = extract_strings_from_data(file_data, 0, min_len)
        except MemoryError:
             print("[!] Erro de Memória ao ler o arquivo inteiro. Tente analisar por seção.")
             return [], {}, {} # Retorna vazio em caso de erro grave
        except Exception as e:
            print(f"[!] Erro ao ler o arquivo para extração de strings: {e}")
            return [], {}, {}

        # Mapear strings para seções (para cálculo de densidade)
        for s in all_strings:
            found_in_section = False
            for section in pe.sections:
                 start = section.PointerToRawData
                 end = start + section.SizeOfRawData
                 if start <= s['offset'] < end:
                    try:
                        name = section.Name.decode().rstrip('\x00')
                    except UnicodeDecodeError:
                        name = repr(section.Name)
                    if name not in strings_by_section:
                        strings_by_section[name] = []
                    strings_by_section[name].append(s)
                    found_in_section = True
                    break
            #if not found_in_section:
                # String pode estar no cabeçalho ou overlay

    print(f"[*] Total de strings extraídas: {len(all_strings)}")

    # --- Classificação ---
    print("[*] Classificando strings...")
    classified_strings = {
        "network_references": [],
        "suspicious_apis": [],
        "malicious_commands": [],
        "packer_indicators": [],
        "potential_encoded": [], # Heurística simples para hex
        "other": [] # Não classificadas
    }
    classified_count = 0

    # Regex para strings hexadecimais longas (potencialmente codificadas)
    hex_re = re.compile(r'^[0-9a-fA-F]{10,}$') # Ex: 10+ caracteres hex

    for s_info in all_strings:
        s = s_info['string']
        classified = False

        # 1. Referências de Rede
        for category, pattern in NETWORK_PATTERNS.items():
            if pattern.search(s):
                # Validação extra para IPs
                if category == "IPv4":
                    potential_ips = pattern.findall(s)
                    for ip in potential_ips:
                        if is_valid_ip(ip):
                             classified_strings["network_references"].append(s_info)
                             classified = True
                             break # Classifica uma vez por string
                else:
                    classified_strings["network_references"].append(s_info)
                    classified = True
                    break # Classifica uma vez por string
        if classified:
            classified_count += 1
            continue

        # 2. APIs Suspeitas (verifica a string exata ou como parte de outra)
        if SUSPICIOUS_API_RE.search(s):
             classified_strings["suspicious_apis"].append(s_info)
             classified = True
             classified_count += 1
             continue

        # 3. Comandos Maliciosos
        if MALICIOUS_COMMAND_RE.search(s):
            classified_strings["malicious_commands"].append(s_info)
            classified = True
            classified_count += 1
            continue

        # 4. Indicadores de Packing/Ofuscação
        if PACKER_INDICATOR_RE.search(s):
             # Verifica se a string é *exatamente* um nome de seção comum de packer para evitar falso positivo
             is_section_name = False
             for section_name in PACKER_INDICATORS:
                 if section_name.startswith('.') and s.lower() == section_name.lower():
                     is_section_name = True
                     break
             if not is_section_name: # Evita classificar ".upx" como packer se não for o nome da seção
                 classified_strings["packer_indicators"].append(s_info)
                 classified = True
                 classified_count += 1
                 continue

        # 5. Potencialmente Codificadas (Hex)
        # Verifica se a string *contém* uma longa sequência hexadecimal
        # Isso é propenso a falsos positivos (GUIDs, etc.), usar com cautela
        if len(s) > 10 and any(len(part) >= 10 and hex_re.match(part) for part in re.findall(r'[0-9a-fA-F]+', s)):
             classified_strings["potential_encoded"].append(s_info)
             # Não contamos como "classificada" para não poluir muito
             # classified = True
             # classified_count += 1
             # continue # Pode ser classificada em outras categorias também

        # 6. Outras
        if not classified:
            classified_strings["other"].append(s_info)

    print(f"[*] Strings classificadas em categorias de interesse: {classified_count}")
    return all_strings, strings_by_section, classified_strings


def run_heuristics(pe, pe_info, strings_by_section, classified_strings, all_strings):
    """
    Executa heurísticas para detectar empacotamento, ofuscação ou malware.
    """
    print("[*] Executando heurísticas...")
    heuristics = {
        "alerts": [],
        "score": 0, # Pontuação simples: quanto maior, mais suspeito
        "summary": "Normal"
    }
    high_entropy_threshold = 7.0
    suspicious_section_names = {'.text', '.data', '.rdata', '.idata', '.rsrc'} # Nomes comuns esperados
    packer_section_names = {ind.lower() for ind in PACKER_INDICATORS if ind.startswith('.')}

    # --- Heurísticas Baseadas nas Seções ---
    if not pe_info['sections']:
        heuristics['alerts'].append("ALERTA: Nenhuma seção encontrada no cabeçalho PE. Altamente suspeito (possível packing/corrupção).")
        heuristics['score'] += 10
    else:
        num_executable_sections = 0
        high_entropy_sections = []
        unnamed_sections = 0
        non_standard_names = []
        total_section_size = 0
        packer_sections_found = []

        for section in pe_info['sections']:
            total_section_size += section['raw_size']
            name_lower = section['name'].lower()

            # Entropia alta
            if section['entropy'] >= high_entropy_threshold:
                high_entropy_sections.append(f"{section['name']} ({section['entropy']})")
                heuristics['score'] += 3 # Pontuação maior para entropia alta

            # Verificação de nome
            if not section['name'] or section['name'] == '        ': # Ver seção sem nome
                 unnamed_sections += 1
            elif name_lower not in suspicious_section_names and name_lower not in packer_section_names:
                 # Se não for nome padrão nem de packer conhecido, é não-padrão
                 if not all(c in 'abcdefghijklmnopqrstuvwxyz.' for c in name_lower): # Ignora nomes como .tls, .reloc etc
                    non_standard_names.append(section['name'])

            # Nomes de seção de packer
            if name_lower in packer_section_names:
                packer_sections_found.append(section['name'])
                heuristics['score'] += 5 # Pontuação alta para seção de packer

            # Seção executável? (IMAGE_SCN_MEM_EXECUTE = 0x20000000)
            if int(section['characteristics'], 16) & 0x20000000:
                num_executable_sections += 1
                # Alerta se seção de dados/recursos for executável
                if name_lower in ['.data', '.rdata', '.rsrc'] or 'resource' in name_lower:
                    heuristics['alerts'].append(f"ALERTA: Seção '{section['name']}' marcada como executável, o que é incomum para dados/recursos.")
                    heuristics['score'] += 3

        if high_entropy_sections:
            heuristics['alerts'].append(f"INFO: Seções com alta entropia (>= {high_entropy_threshold}), sugerindo dados comprimidos/criptografados: {', '.join(high_entropy_sections)}")
            heuristics['score'] += 2 # Score adicional por ter *alguma* seção de alta entropia

        if unnamed_sections > 0:
            heuristics['alerts'].append(f"AVISO: Encontrada(s) {unnamed_sections} seção(ões) sem nome. Pode indicar packing.")
            heuristics['score'] += 2 * unnamed_sections

        if non_standard_names:
            heuristics['alerts'].append(f"AVISO: Seções com nomes não padrão detectadas: {', '.join(non_standard_names)}. Pode indicar packing/ofuscação.")
            heuristics['score'] += 1 * len(non_standard_names)

        if packer_sections_found:
            heuristics['alerts'].append(f"ALERTA: Nomes de seção associados a packers detectados: {', '.join(packer_sections_found)}.")
            # Score já adicionado no loop

        if num_executable_sections == 0 and pe.is_exe():
             heuristics['alerts'].append("ALERTA: Nenhum seção marcada como executável encontrada em um arquivo EXE. Muito suspeito.")
             heuristics['score'] += 5
        elif num_executable_sections > 1:
             # Múltiplas seções executáveis podem ser normais, mas também usadas por packers
             heuristics['alerts'].append(f"INFO: Múltiplas ({num_executable_sections}) seções executáveis encontradas.")
             # heuristics['score'] += 1 # Score baixo, pois pode ser normal

        # Densidade de Strings (heurística geral)
        total_string_bytes = sum(s_info['length'] * (2 if s_info['type'] == 'Unicode' else 1) for s_info in all_strings)
        if total_section_size > 0:
            string_density = (total_string_bytes / total_section_size) * 100 if total_section_size > 0 else 0
            heuristics['string_density_percent'] = round(string_density, 2)
            if len(all_strings) > 10 and string_density < 1.0: # Limiar baixo arbitrário
                 heuristics['alerts'].append(f"AVISO: Baixa densidade de strings legíveis ({string_density:.2f}%) no total das seções. Pode indicar packing ou dados criptografados.")
                 heuristics['score'] += 2
            elif len(all_strings) < 10 and pe_info['file_size'] > 1024: # Pouquíssimas strings em arquivo não trivial
                 heuristics['alerts'].append("AVISO: Número muito baixo de strings legíveis encontrado. Pode indicar packing/ofuscação severa.")
                 heuristics['score'] += 3
        else:
             if len(all_strings) < 10 and pe_info['file_size'] > 1024:
                 heuristics['alerts'].append("AVISO: Número muito baixo de strings legíveis e nenhuma seção com dados. Suspeito.")
                 heuristics['score'] += 4


    # --- Heurísticas Baseadas em Imports ---
    if not pe_info['imports']:
        heuristics['alerts'].append("AVISO: Nenhuma tabela de importação (IAT) encontrada ou está vazia. Comum em arquivos empacotados que resolvem imports dinamicamente.")
        heuristics['score'] += 4
    else:
        found_loadlibrary = False
        found_getprocaddress = False
        suspicious_import_count = 0
        for imp_dll in pe_info['imports']:
             for func in imp_dll['functions']:
                 if func in SUSPICIOUS_APIS:
                     suspicious_import_count += 1
                 if func.lower().startswith("loadlibrary"):
                     found_loadlibrary = True
                 if func.lower().startswith("getprocaddress"):
                     found_getprocaddress = True

        if found_loadlibrary and found_getprocaddress:
            heuristics['alerts'].append("INFO: Funções LoadLibrary e GetProcAddress importadas. Podem ser usadas para carregar APIs dinamicamente (comum em packers/malware, mas também legítimo).")
            heuristics['score'] += 1
        elif suspicious_import_count > 5: # Limiar arbitrário
            heuristics['alerts'].append(f"INFO: Detectado número significativo ({suspicious_import_count}) de APIs potencialmente suspeitas na tabela de importação.")
            heuristics['score'] += 2

    # --- Heurísticas Baseadas nas Strings Classificadas ---
    if classified_strings["network_references"]:
        heuristics['alerts'].append(f"INFO: Encontradas {len(classified_strings['network_references'])} strings relacionadas à rede (URLs, IPs, etc.).")
        heuristics['score'] += 1
    if classified_strings["suspicious_apis"]:
        heuristics['alerts'].append(f"AVISO: Encontradas {len(classified_strings['suspicious_apis'])} strings que correspondem a nomes de APIs frequentemente usadas por malware.")
        heuristics['score'] += 2 * len(classified_strings["suspicious_apis"]) # Dar mais peso
    if classified_strings["malicious_commands"]:
        heuristics['alerts'].append(f"ALERTA: Encontradas {len(classified_strings['malicious_commands'])} strings que correspondem a comandos potencialmente maliciosos (cmd, powershell, etc.).")
        heuristics['score'] += 3 * len(classified_strings["malicious_commands"]) # Dar peso ainda maior
    if classified_strings["packer_indicators"]:
        heuristics['alerts'].append(f"ALERTA: Encontradas {len(classified_strings['packer_indicators'])} strings indicativas de packers/ofuscadores.")
        heuristics['score'] += 4 * len(classified_strings["packer_indicators"]) # Peso alto

    # --- Heurísticas Gerais ---
    # Ponto de Entrada fora de seções comuns (simplificado)
    entry_point_addr = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    entry_section = None
    for section in pe.sections:
        if section.VirtualAddress <= entry_point_addr < (section.VirtualAddress + section.Misc_VirtualSize):
            try:
                entry_section = section.Name.decode().rstrip('\x00')
            except:
                entry_section = repr(section.Name)
            break

    if entry_section and entry_section.lower() not in ['.text', 'code']:
         heuristics['alerts'].append(f"AVISO: O ponto de entrada ({hex(entry_point_addr)}) está na seção '{entry_section}', que não é a seção de código usual (.text). Pode indicar packing.")
         heuristics['score'] += 3
    elif not entry_section and pe_info['num_sections'] > 0:
         heuristics['alerts'].append(f"AVISO: O ponto de entrada ({hex(entry_point_addr)}) parece estar fora de qualquer seção definida. Suspeito.")
         heuristics['score'] += 3


    # --- Conclusão Heurística ---
    if heuristics['score'] >= 15:
        heuristics['summary'] = "ALTO RISCO (Múltiplos indicadores fortes de packing/malware)"
    elif heuristics['score'] >= 8:
        heuristics['summary'] = "RISCO MÉDIO (Indicadores suspeitos detectados)"
    elif heuristics['score'] >= 3:
        heuristics['summary'] = "RISCO BAIXO (Alguns indicadores leves ou informativos)"
    else:
        heuristics['summary'] = "Normal (Nenhum indicador significativo encontrado)"


    print(f"[*] Análise heurística concluída. Score: {heuristics['score']}")
    return heuristics


def generate_markdown_report(file_path, pe_info, all_strings, classified_strings, heuristics_results, output_file):
    """Gera o relatório final em formato Markdown."""
    print(f"[*] Gerando relatório Markdown para: {output_file}")
    report = []

    # --- Cabeçalho ---
    report.append(f"# Relatório de Análise Estática PE: `{os.path.basename(file_path)}`")
    report.append(f"Data da Análise: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    report.append("\n---\n")

    # --- Resumo da Análise Heurística ---
    report.append("## 1. Resumo da Análise Heurística")
    report.append(f"**Conclusão:** {heuristics_results['summary']}")
    report.append(f"**Score Heurístico:** {heuristics_results['score']}")
    if 'string_density_percent' in heuristics_results:
        report.append(f"**Densidade de Strings (total seções):** {heuristics_results['string_density_percent']}%")
    report.append("\n**Alertas Gerados:**")
    if heuristics_results['alerts']:
        for alert in heuristics_results['alerts']:
            report.append(f"- {alert}")
    else:
        report.append("* Nenhum alerta significativo.")
    report.append("\n---\n")

    # --- Informações do Binário ---
    report.append("## 2. Informações do Binário")
    report.append(f"- **Arquivo:** `{pe_info['file_path']}`")
    report.append(f"- **Tamanho:** {pe_info['file_size']} bytes")
    report.append(f"- **Arquitetura:** {pe_info['architecture']}")
    report.append(f"- **Timestamp Cabeçalho PE:** {pe_info['timestamp']}")
    report.append(f"- **Ponto de Entrada (VA):** {pe_info['entry_point']}")
    report.append(f"- **Base da Imagem (VA):** {pe_info['image_base']}")
    report.append(f"- **Número de Seções:** {pe_info['num_sections']}")
    report.append("\n### Seções")
    if pe_info['sections']:
        report.append("| Nome      | End. Virtual | Tam. Virtual | Tam. Raw | Entropia | Características |")
        report.append("|-----------|--------------|--------------|----------|----------|-----------------|")
        for s in pe_info['sections']:
            report.append(f"| `{s['name']:<9}` | `{s['virtual_address']:<12}` | {s['virtual_size']:<12} | {s['raw_size']:<8} | {s['entropy']:<8} | `{s['characteristics']:<15}` |")
    else:
        report.append("* Nenhuma seção encontrada.")
    report.append("\n---\n")

    # --- Strings Classificadas ---
    report.append("## 3. Strings Classificadas por Categoria")
    for category, strings in classified_strings.items():
        title = category.replace("_", " ").title()
        report.append(f"\n### {title} ({len(strings)})")
        if strings:
            report.append("| Offset (Hex) | Tipo    | Comprimento | String (início)                 |")
            report.append("|--------------|---------|-------------|---------------------------------|")
            for s in strings[:50]: # Limitar para não poluir muito o relatório
                 preview = s['string'][:100].replace('\n', '\\n').replace('\r', '\\r') # Preview curto
                 report.append(f"| `{hex(s['offset']):<12}` | {s['type']:<7} | {s['length']:<11} | `{preview}` |")
            if len(strings) > 50:
                report.append(f"| *... (e mais {len(strings) - 50} strings)* |")
        else:
            report.append("* Nenhuma string encontrada nesta categoria.")
    report.append("\n---\n")

     # --- Tabela de Imports (Opcional, pode ser longa) ---
    report.append("## 4. Tabela de Importação (IAT)")
    if pe_info['imports']:
        report.append("| DLL Importada          | Funções Importadas (amostra) |")
        report.append("|------------------------|------------------------------|")
        max_funcs_display = 10 # Limitar funções por DLL no relatório
        for imp in pe_info['imports']:
            funcs_str = ", ".join(f"`{f}`" for f in imp['functions'][:max_funcs_display])
            if len(imp['functions']) > max_funcs_display:
                funcs_str += f", *... (e mais {len(imp['functions']) - max_funcs_display})*"
            report.append(f"| `{imp['dll']:<22}` | {funcs_str} |")
    else:
        report.append("* Nenhuma importação encontrada ou IAT vazia.")
    report.append("\n---\n")

    # --- Lista Completa de Strings (Opcional, pode ser muito longa) ---
    report.append("## 5. Todas as Strings Extraídas")
    report.append(f"Total de strings extraídas (min_len={DEFAULT_MIN_STRING_LEN}): {len(all_strings)}") # TODO: Usar min_len real
    if all_strings:
        report.append("| Offset (Hex) | Tipo    | Comprimento | String (início)                 |")
        report.append("|--------------|---------|-------------|---------------------------------|")
        max_strings_full_list = 200 # Limitar a lista completa
        for s in all_strings[:max_strings_full_list]:
            preview = s['string'][:100].replace('\n', '\\n').replace('\r', '\\r')
            report.append(f"| `{hex(s['offset']):<12}` | {s['type']:<7} | {s['length']:<11} | `{preview}` |")
        if len(all_strings) > max_strings_full_list:
             report.append(f"| *... (e mais {len(all_strings) - max_strings_full_list} strings)* |")
    else:
        report.append("* Nenhuma string encontrada com os critérios definidos.")

    # --- Salvar Relatório ---
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(report))
        print(f"[+] Relatório salvo com sucesso em: {output_file}")
    except Exception as e:
        print(f"[!] Erro ao salvar o relatório em '{output_file}': {e}")

# --- Função Principal (main) ---

def main():
    parser = argparse.ArgumentParser(description="Analisa estaticamente executáveis PE (32/64-bit) para extrair strings e detectar sinais de packing, ofuscação ou malware.")
    parser.add_argument("file_path", help="Caminho para o arquivo PE a ser analisado.")
    parser.add_argument("-m", "--min-len", type=int, default=DEFAULT_MIN_STRING_LEN,
                        help=f"Tamanho mínimo das strings a serem extraídas (padrão: {DEFAULT_MIN_STRING_LEN}).")
    parser.add_argument("-s", "--section", type=str, default=None,
                        help="Analisar strings apenas na seção especificada (ex: .text, .data).")
    parser.add_argument("-o", "--output", type=str, default=None,
                        help="Nome do arquivo de saída para o relatório Markdown (padrão: <nome_arquivo>_report.md).")
    # parser.add_argument("--ioc-list", type=str, default=None, help="Caminho para um arquivo de lista negra de IOCs (strings, hashes) para comparação (NÃO IMPLEMENTADO).") # Funcionalidade futura

    args = parser.parse_args()

    if not os.path.exists(args.file_path):
        print(f"[!] Erro: Arquivo não encontrado: {args.file_path}")
        return

    if args.min_len < 2:
        print("[!] Aviso: Tamanho mínimo da string muito baixo, pode gerar muito ruído. Usando min_len=2.")
        args.min_len = 2

    # Definir nome do arquivo de saída
    if args.output is None:
        base_name = os.path.basename(args.file_path)
        output_file = os.path.splitext(base_name)[0] + "_report.md"
    else:
        output_file = args.output

    print(f"[*] Iniciando análise de: {args.file_path}")

    # 1. Parse PE
    pe, pe_info = parse_pe_file(args.file_path)
    if not pe:
        return # Erro já foi impresso

    # 2. Extração e Classificação de Strings
    all_strings, strings_by_section, classified_strings = analyze_strings(
        args.file_path, pe, args.min_len, args.section
    )

    # 3. Heurísticas
    heuristics_results = run_heuristics(pe, pe_info, strings_by_section, classified_strings, all_strings)

    # 4. Geração de Relatório
    generate_markdown_report(args.file_path, pe_info, all_strings, classified_strings, heuristics_results, output_file)

    print("[*] Análise concluída.")

if __name__ == "__main__":
    main()