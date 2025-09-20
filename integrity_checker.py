# -*- coding: utf-8 -*-
import os
import hashlib
import json
import sys
from datetime import datetime

# Define o tamanho do bloco para ler os arquivos (para não sobrecarregar a memória com arquivos grandes)
BUFFER_SIZE = 65536 

def calculate_hash(filepath):
    """Calcula o hash SHA256 de um arquivo."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            while True:
                data = f.read(BUFFER_SIZE)
                if not data:
                    break
                sha256.update(data)
        return sha256.hexdigest()
    except IOError:
        return None

def generate_baseline(directory):
    """Gera a linha de base (baseline) de hashes para todos os arquivos em um diretório."""
    print(f"[*] Gerando baseline para o diretório: {directory}")
    baseline = {}
    for dirpath, _, filenames in os.walk(directory):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            file_hash = calculate_hash(filepath)
            if file_hash:
                # Usamos caminhos relativos para a baseline ser mais portável
                relative_path = os.path.relpath(filepath, directory)
                baseline[relative_path] = file_hash
    
    with open('baseline.json', 'w') as f:
        json.dump(baseline, f, indent=4)
        
    print("[+] Baseline salva com sucesso em 'baseline.json'")

def check_integrity(directory):
    """Verifica a integridade dos arquivos comparando com a baseline."""
    print(f"[*] Verificando integridade do diretório: {directory}")
    
    try:
        with open('baseline.json', 'r') as f:
            baseline = json.load(f)
    except FileNotFoundError:
        print("[ERRO] Arquivo 'baseline.json' não encontrado. Gere uma baseline primeiro.")
        return

    current_state = {}
    for dirpath, _, filenames in os.walk(directory):
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            file_hash = calculate_hash(filepath)
            if file_hash:
                relative_path = os.path.relpath(filepath, directory)
                current_state[relative_path] = file_hash
    
    # Comparação
    modified_files = []
    new_files = []
    deleted_files = list(baseline.keys()) # Começa com todos os arquivos da baseline

    for filepath, file_hash in current_state.items():
        if filepath in baseline:
            # Arquivo existe na baseline, verificar se o hash mudou
            if baseline[filepath] != file_hash:
                modified_files.append(filepath)
            deleted_files.remove(filepath)
        else:
            # Arquivo não existe na baseline, é novo
            new_files.append(filepath)

    # Relatório
    print("\n--- Relatório de Integridade ---")
    print(f"Verificação concluída em: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}\n")

    if modified_files:
        print(f"[!] ARQUIVOS MODIFICADOS ({len(modified_files)}):")
        for f in modified_files:
            print(f"  - {f}")
    
    if new_files:
        print(f"\n[+] ARQUIVOS NOVOS ({len(new_files)}):")
        for f in new_files:
            print(f"  - {f}")

    if deleted_files:
        print(f"\n[-] ARQUIVOS DELETADOS ({len(deleted_files)}):")
        for f in deleted_files:
            print(f"  - {f}")

    if not modified_files and not new_files and not deleted_files:
        print("[OK] Nenhuma alteração detectada. A integridade dos arquivos foi mantida.")
    
    print("\n--- Fim do Relatório ---")

def main():
    """Função principal que interpreta os argumentos da linha de comando."""
    if len(sys.argv) != 3:
        print("Uso inválido!")
        print("Sintaxe: python integrity_checker.py [generate|check] <diretório>")
        print("Exemplo (gerar): python integrity_checker.py generate ./pasta_de_teste")
        print("Exemplo (verificar): python integrity_checker.py check ./pasta_de_teste")
        sys.exit(1)
        
    mode = sys.argv[1]
    target_directory = sys.argv[2]
    
    if not os.path.isdir(target_directory):
        print(f"[ERRO] O diretório '{target_directory}' não existe.")
        sys.exit(1)

    if mode == 'generate':
        generate_baseline(target_directory)
    elif mode == 'check':
        check_integrity(target_directory)
    else:
        print(f"[ERRO] Modo '{mode}' inválido. Use 'generate' ou 'check'.")
        sys.exit(1)

if __name__ == "__main__":
    main()