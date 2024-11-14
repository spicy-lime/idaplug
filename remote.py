#!/usr/bin/env python3

from ipykernel.kernelapp import IPKernelApp
import socket

# Get the IP address of the current machine
def start():
    host_ip = socket.gethostbyname(socket.gethostname())
    kernel_port = 8888  # Specify the desired port for the IPython kernel

    # Configure and start the IPython kernel
    app = IPKernelApp.instance()
    app.initialize(['python'])

    print(f"IPython kernel is running")
    app.start()
