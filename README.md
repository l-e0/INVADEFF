# INVADEFF
Monitor de Processos e Arquivos Suspeitos
Este é um projeto de monitoramento de processos e arquivos suspeitos em Python, que utiliza a biblioteca psutil para monitorar os processos em execução e a biblioteca watchdog para observar modificações em arquivos na pasta especificada.

Pré-requisitos
Antes de começar, certifique-se de ter o Python instalado no seu sistema. Além disso, você precisará instalar as seguintes bibliotecas Python:

import os
import sys
import psutil
import logging
import threading
from cryptography.hazmat.primitives import hashes
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import tkinter as tk
from tkinter import ttk, scrolledtext


Como Usar:
Clone este repositório no seu computador com este comando:

git clone <https://github.com/l-e0/INVADEFF>


Acessando o código:

Substitua <caminho_para_a_pasta_a_ser_monitorada> pelo caminho da pasta que você deseja monitorar. Por exemplo: C:\Financas.

Dê play no código ou crie um .exe com o seguinte comando: pyinstaller --noconsole --onefile --noupx invadeff.py

Entre na pasta dist que será criada na pasta do código e clique no invadeff.exe

Para obter privilégio execute como administrador no .exe

O aplicativo de interface gráfica será iniciado. Clique no botão "Iniciar Monitoramento" para começar a monitorar processos e arquivos suspeitos.


Funcionalidades:

Monitoramento de Processos: O programa verifica regularmente os processos em execução e exibe uma mensagem se detectar um processo suspeito.

Monitoramento de Arquivos: Qualquer alteração em arquivos na pasta monitorada será registrada, e se uma modificação suspeita for detectada, uma mensagem será exibida.

Encerramento de Processos Suspeitos: O programa tentará encerrar os processos suspeitos que estão interagindo com os arquivos monitorados.
