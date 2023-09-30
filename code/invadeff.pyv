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

processing_suspicious_file = False

def get_current_process_pid():
    return os.getpid()

def is_suspicious_process(process_name, process_exe):
    if "suspeito" in process_name.lower():
        return True
    return False

def monitor_processes(log_text):
    global monitoring_started
    while monitoring_started:
        for proc in psutil.process_iter(attrs=['pid', 'name', 'exe']):
            try:
                process_pid = proc.info['pid']
                process_name = proc.info['name']
                process_exe = proc.info['exe']
                if is_suspicious_process(process_name, process_exe):
                    log_text.insert(tk.END, f"Processo suspeito detectado: {process_name} (PID: {process_pid})\n")
                    log_text.tag_configure("red", foreground="red")
                    log_text.tag_add("red", "end-2c", "end-1c")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
            except psutil.Error as e:
                log_text.insert(tk.END, f"Erro ao verificar processo: {str(e)}\n")
                log_text.tag_configure("red", foreground="red")
                log_text.tag_add("red", "end-2c", "end-1c")

class MyHandler(FileSystemEventHandler):
    def on_modified(self, event):
        global processing_suspicious_file
        if processing_suspicious_file:
            return
        file_path = event.src_path
        if os.path.isfile(file_path):
            file_name = os.path.basename(file_path)
            file_hash = hash_file(file_path)
            if file_path in file_hashes and file_hash != file_hashes[file_path]:
                current_process_pid = get_current_process_pid()
                log_text.insert(tk.END, f"Alteração suspeita no arquivo: {file_path} (Alterado pelo processo: python.exe, PID: {current_process_pid})\n")
                log_text.tag_configure("red", foreground="red")
                log_text.tag_add("red", "end-2c", "end-1c")
                processing_suspicious_file = True
                terminated = self.terminate_processes_by_path(file_path)
                if terminated:
                    log_text.insert(tk.END, f"Processo suspeito encerrado.\n")
                    log_text.tag_configure("green", foreground="green")
                    log_text.tag_add("green", "end-2c", "end-1c")
                else:
                    log_text.insert(tk.END, f"Processo suspeito não pôde ser encerrado.\n")
                    log_text.tag_configure("red", foreground="red")
                    log_text.tag_add("red", "end-2c", "end-1c")
                processing_suspicious_file = False
            file_hashes[file_path] = file_hash

    def terminate_processes_by_path(self, file_path):
        terminated = False
        for proc in psutil.process_iter(attrs=['pid', 'name', 'exe']):
            try:
                process_pid = proc.info['pid']
                process_name = proc.info['name']
                process_exe = proc.info['exe']
                if process_exe is not None and file_path in process_exe:
                    log_text.insert(tk.END, f"Tentando encerrar processo suspeito: {process_name} (PID: {process_pid})\n")
                    log_text.tag_configure("blue", foreground="blue")
                    log_text.tag_add("blue", "end-2c", "end-1c")
                    psutil.Process(process_pid).terminate()
                    terminated = True
                    log_text.insert(tk.END, f"Processo suspeito encerrado com sucesso.\n")
                    log_text.tag_configure("green", foreground="green")
                    log_text.tag_add("green", "end-2c", "end-1c")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
            except psutil.Error as e:
                log_text.insert(tk.END, f"Erro ao encerrar processo suspeito: {str(e)}\n")
                log_text.tag_configure("red", foreground="red")
                log_text.tag_add("red", "end-2c", "end-1c")
        return terminated

def hash_file(file_path):
    sha256 = hashes.SHA256()
    hasher = hashes.Hash(sha256)
    with open(file_path, 'rb') as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            hasher.update(data)
    file_hash = hasher.finalize()
    file_hash_hex = file_hash.hex()
    return file_hash_hex

def start_monitoring():
    global process_monitor_thread, monitoring_started
    if not monitoring_started:
        log_text.insert(tk.END, "Iniciando monitoramento de processos...\n")
        log_text.tag_configure("green", foreground="green")
        log_text.tag_add("green", "end-2c", "end-1c")
        process_monitor_thread = threading.Thread(target=monitor_processes, args=(log_text,))
        process_monitor_thread.daemon = True
        process_monitor_thread.start()
        monitoring_started = True
        start_button.config(state=tk.DISABLED)
        stop_button.config(state=tk.NORMAL)
    else:
        log_text.insert(tk.END, "O monitoramento já está em andamento.\n")
        log_text.tag_configure("blue", foreground="blue")
        log_text.tag_add("blue", "end-2c", "end-1c")

def stop_monitoring():
    global monitoring_started, process_monitor_thread
    if monitoring_started:
        log_text.insert(tk.END, "Parando o monitoramento de processos...\n")
        log_text.tag_configure("red", foreground="red")
        log_text.tag_add("red", "end-2c", "end-1c")
        stop_monitoring_event.set()
        process_monitor_thread.join()
        monitoring_started = False
        start_button.config(state=tk.NORMAL)
        stop_button.config(state=tk.DISABLED)
    else:
        log_text.insert(tk.END, "O monitoramento não está em andamento.\n")
        log_text.tag_configure("blue", foreground="blue")
        log_text.tag_add("blue", "end-2c", "end-1c")

def toggle_color_mode():
    global dark_mode
    dark_mode = not dark_mode
    update_color_scheme()

def update_color_scheme():
    global dark_mode
    if dark_mode:
        root.configure(bg="black")
        log_text.configure(bg="black", fg="white")
        start_button.configure(style="TButton", background="gray", foreground="white")
        stop_button.configure(style="TButton", background="gray", foreground="white")
        toggle_mode_button.configure(style="TButton", background="gray", foreground="white")
    else:
        root.configure(bg="white")
        log_text.configure(bg="white", fg="black")
        start_button.configure(style="TButton", background="lightgray", foreground="black")
        stop_button.configure(style="TButton", background="lightgray", foreground="black")
        toggle_mode_button.configure(style="TButton", background="lightgray", foreground="black")

monitoring_started = False
dark_mode = False
stop_monitoring_event = threading.Event()

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Monitor de Processos e Arquivos Suspeitos")
    style = ttk.Style()
    style.configure("TButton", padding=6)
    log_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=40, height=10)
    log_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
    log_text.insert(tk.END, "Aguardando início do monitoramento...\n")
    start_button = ttk.Button(root, text="Iniciar Monitoramento", command=start_monitoring, style="TButton", width=20)
    start_button.pack(padx=10, pady=5)
    stop_button = ttk.Button(root, text="Parar Monitoramento", command=stop_monitoring, style="TButton", width=20)
    stop_button.pack(padx=10, pady=5)
    toggle_mode_button = ttk.Button(root, text="Alternar Modo de Cores", command=toggle_color_mode, style="TButton", width=20)
    toggle_mode_button.pack(padx=10, pady=5)
    stop_button.config(state=tk.DISABLED)
    root.geometry("500x400")
    file_hashes = {}
    path = sys.argv[1] if len(sys.argv) > 1 else r'caminho_para_a_pasta_a_ser_monitorada'
    logging.info(f'start watching directory {path!r}')
    event_handler = MyHandler()
    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()
    try:
        root.mainloop()
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
