from flask import Response, jsonify, request, stream_with_context, Flask , render_template
import ctypes
from os import popen
import subprocess
from flask_sqlalchemy import SQLAlchemy
import threading
import queue


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///packets.db'
db = SQLAlchemy(app)


@app.route('/')
def hello_world():
    return render_template("index.html")

@app.route('/Alerts and Alarms')
def Alerts():
    return render_template('alerts.html')

@app.route('/Log Activity')
def Logs():
    return "Log Activity"

@app.route('/report')
def report():
    return 'hello world'


def check_password(password):
  # Replace this with your actual password check
  return password == "kali"

  
@app.route('/start', methods=['POST'])
def start_packet():
    # Compile the C program
    subprocess.run(['g++', 'packet.cpp', '-o', 'packet'])

    # Get the sudo password from the POST parameter
    password = request.form['password']
    if check_password(password):
    # Run the compiled binary with sudo
        command = ['sudo', '-S', './packet' , 'wlan0']
        p = subprocess.Popen(command, stdin=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        p.communicate(password + '\n')
        return "Started Successfully"
    else:
        return "Incorrect password"
  

@app.route('/stop')
def stop_packet():
    # Terminate the running process
    subprocess.run(['sudo' , 'pkill', '-f', './packet'])
    return 'Stopped packet'


@app.route('/packet_info')
def packet_info():
  # Open the file in read mode
  with open('ips.txt', 'r') as f:
    # Read the lines from the file
    lines = f.readlines()

  # Initialize the list of packet info
  packet_info_list = []

  # Iterate over the lines in the file
  for i in range(0, len(lines), 4):
    # Get the source IP, destination IP, source port, and destination port from the lines
    source_ip = lines[i].split(': ')[1].strip()
    destination_ip = lines[i+1].split(': ')[1].strip()
    source_port = lines[i+2].split(': ')[1].strip()
    destination_port = lines[i+3].split(': ')[1].strip()

    # Append the packet info to the list
    packet_info_list.append({
      "source_ip": source_ip,
      "destination_ip": destination_ip,
      "source_port": source_port,
      "destination_port": destination_port
    })

  # Return the list of packet info as a JSON object
  return render_template('packet_info.html', packets=packet_info_list)

if __name__== "__main__":
    app.run(debug="True" , port=8080)



