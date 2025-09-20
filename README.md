# Verificador de Integridade de Arquivos em Python

Uma ferramenta de segurança defensiva (Blue Team) que monitora diretórios em busca de alterações não autorizadas. O script gera uma "baseline" de hashes SHA256 para todos os arquivos e, posteriormente, compara o estado atual com essa baseline, reportando quaisquer arquivos modificados, adicionados ou deletados.

## Funcionalidades

- Geração de uma baseline segura de hashes (SHA256) em um arquivo `baseline.json`.
- Verificação do estado atual de um diretório contra a baseline.
- Identificação de arquivos modificados, novos e deletados.
- Leitura de arquivos otimizada para lidar com arquivos grandes sem consumir muita memória.

## Como Usar

A ferramenta opera com dois modos: `generate` e `check`.

### 1. Gerar a Baseline

Para criar o registro inicial de hashes para um diretório, use o modo `generate`.

```bash
python integrity_checker.py generate <caminho_do_diretorio>