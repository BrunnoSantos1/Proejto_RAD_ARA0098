import pyshark
import time
import threading
import tkinter as tk
from tkinter import ttk

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Monitor de Tráfego")
        self.root.minsize(600, 600)

        self.create_ui()
        self.packet_count = 0
        self.previous_time = time.time()

        # Estatísticas
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_count = {}
        self.transmission_rate = 0

        # Dispositivos conectados
        self.devices = set()

        self.interface = 'Ethernet'  # Substitua pela interface de rede desejada
        self.capture = pyshark.LiveCapture(interface=self.interface)


    def create_ui(self):
        # Frame principal
        main_frame = tk.Frame(self.root, width=500, height= 450)
        main_frame.pack(fill=tk.BOTH, expand=1)

        # Canvas para barras de rolagem
        self.canvas = tk.Canvas(main_frame)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=1)

        # Barra de rolagem vertical
        scrollbar_y = tk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.canvas.yview)
        scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)

        # Barra de rolagem horizontal
        scrollbar_x = tk.Scrollbar(main_frame, orient=tk.HORIZONTAL, command=self.canvas.xview)
        scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)

        self.canvas.configure(yscrollcommand=scrollbar_y.set, xscrollcommand=scrollbar_x.set)
        self.canvas.bind('<Configure>', lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

        self.table_frame = tk.Frame(self.canvas)
        self.canvas.create_window((0, 0), window=self.table_frame, anchor="nw")
    

        # Tabela de pacotes
        columns = ("timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "packet_size", "packet_type", "transmission_rate", "flow")
        self.tree = ttk.Treeview(self.table_frame, columns=columns, show='headings')

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, stretch=tk.YES)

        self.tree.pack(fill=tk.BOTH, expand=1)

        # Estatísticas rápidas
        stats_frame = tk.Frame(self.root)
        stats_frame.pack(fill=tk.X)

        self.total_packets_label = tk.Label(stats_frame, text="Total de Pacotes: 0")
        self.total_packets_label.pack(side=tk.LEFT, padx=10)

        self.total_bytes_label = tk.Label(stats_frame, text="Total de Bytes: 0")
        self.total_bytes_label.pack(side=tk.LEFT, padx=10)

        # Largura de Banda Utilizada
        self.bandwidth_label = tk.Label(stats_frame, text="Largura de Banda Utilizada: 0")
        self.bandwidth_label.pack(side=tk.LEFT, padx=10)

        self.transmission_rate_label = tk.Label(stats_frame, text="Taxa de Transmissão: 0")
        self.transmission_rate_label.pack(side=tk.LEFT, padx=10)

        self.alert_label = tk.Label(stats_frame, text="Alertas: Nenhum", fg="red")
        self.alert_label.pack(side=tk.LEFT, padx=10)

        # Tabela de dispositivos conectados
        devices_frame = tk.Frame(self.root)
        devices_frame.pack(fill=tk.BOTH, expand=1)

        self.devices_label = tk.Label(devices_frame, text="Dispositivos Conectados:")
        self.devices_label.pack(side=tk.TOP, padx=10, pady=5)

        self.devices_tree = ttk.Treeview(devices_frame, columns=("IP", "MAC"), show='headings')
        self.devices_tree.heading("IP", text="Endereço IP")
        self.devices_tree.heading("MAC", text="Endereço MAC")
        self.devices_tree.pack(fill=tk.BOTH, expand=1)

        # Botões
        buttons_frame = tk.Frame(self.root)
        buttons_frame.pack(fill=tk.X)

        start_button = tk.Button(buttons_frame, text="Iniciar", command=self.run_sniffer_thread)
        start_button.pack(side=tk.LEFT, padx=10)

        stop_button = tk.Button(buttons_frame, text="Parar", command=self.stop_sniffing)
        stop_button.pack(side=tk.LEFT, padx=10)

        exit_button = tk.Button(buttons_frame, text="Sair", command=self.root.quit)
        exit_button.pack(side=tk.LEFT, padx=10)
            
    def update_bandwidth(self):
        bandwidth = self.total_bytes * 8 / 1024 / 1024  # Convertendo bytes para Megabits
        self.bandwidth_label.config(text=f"Largura de Banda Utilizada: {bandwidth:.2f} Mbps")    
   
    def update_stats(self):
        self.total_packets_label.config(text=f"Total de Pacotes: {self.total_packets}")
        self.total_bytes_label.config(text=f"Total de Bytes: {self.total_bytes}")
        self.transmission_rate_label.config(text=f"Taxa de Transmissão: {self.transmission_rate:.2f} pacotes/s")
        self.update_bandwidth()

    def update_devices_list(self, packet):
        if 'eth' in packet:
            src_mac = packet.eth.src
            src_ip = packet.ip.src
            self.devices_tree.insert("", tk.END, values=(src_ip, src_mac))

    def check_security_alerts(self, packet):
        # Verifica se há algum alerta de segurança
        if packet.highest_layer == "HTTP" and int(packet[packet.transport_layer].dstport) == 80:
            self.alert_label.config(text="Alertas: Tráfego HTTP detectado!", fg="red")

    def start_sniffing(self):
        for packet in self.capture.sniff_continuously():
            try:
                timestamp = packet.sniff_time
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                protocol = packet.highest_layer
                packet_size = int(packet.length)
                packet_type = packet.transport_layer
                flow = f"{src_ip} -> {dst_ip}"

                src_port = packet[packet.transport_layer].srcport
                dst_port = packet[packet.transport_layer].dstport

                current_time = time.time()
                self.packet_count += 1
                elapsed_time = current_time - self.previous_time
                if elapsed_time > 0:
                    self.transmission_rate = self.packet_count / elapsed_time
                else:
                    self.transmission_rate = 0

                self.tree.insert("", tk.END, values=(timestamp, src_ip, src_port, dst_ip, dst_port, protocol, packet_size, packet_type, self.transmission_rate, flow))

                self.total_packets += 1
                self.total_bytes += packet_size

                if protocol in self.protocol_count:
                    self.protocol_count[protocol] += 1
                else:
                    self.protocol_count[protocol] = 1

                self.update_stats()
                self.check_security_alerts(packet)
                self.update_devices_list(packet)

                self.previous_time = current_time


            except AttributeError:
                continue

    def run_sniffer_thread(self):
        sniffer_thread = threading.Thread(target=self.start_sniffing, daemon=True)
        sniffer_thread.start()

    def stop_sniffing(self):
        self.capture.close()

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
