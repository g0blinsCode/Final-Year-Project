from flask import Response, request, stream_with_context, Flask , render_template
import ctypes
from os import popen
import subprocess
from flask_sqlalchemy import SQLAlchemy
import threading
import queue


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///packets.db'
db = SQLAlchemy(app)


# Create a global queue to hold the output from the C++ program
output_queue = queue.Queue()

# Load the shared library
cpp_library = ctypes.cdll.LoadLibrary('./my_cpp_library.so')

# Here comes the logic of src ip , dst ip and packet processing
class Packet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    src_ip = db.Column(db.String(50))
    dst_ip = db.Column(db.String(50))
    payload = db.Column(db.Text)

    def __init__(self, src_ip, dst_ip, payload):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.payload = payload

@app.route('/packet', methods=['POST' , 'GET'])
def process_packet():
    src_ip = request.form['src_ip']
    dst_ip = request.form['dst_ip']
    payload = request.form['payload']

    packet = Packet(src_ip, dst_ip, payload)
    db.session.add(packet)
    db.session.commit()

    return 'Packet added to database!'

db.session.close()



@app.route('/')
def hello_world():
    return render_template("index1.html")


@app.route('/Reports')
def Reports():
    return "THis is reports Page"

@app.route('/Alerts and Alarms')
def Alerts():
    return render_template('alerts.html')

def generate_output():
    # Call the C++ program using subprocess.Popen()
    process = subprocess.Popen(["./a.out", "wlan0"], stdout=subprocess.PIPE)

    # Read the output of the C++ program line by line
    for line in process.stdout:
        # Decode the output and put it in the queue
        output_queue.put(line.decode('utf-8'))

    # Continuously yield output as it becomes available in the queue
    while True:
        output = output_queue.get()
        yield f'data: {output}\n\n'

@app.route('/Log Activity')
def Logs():
    headers = {'Content-Type': 'text/event-stream'}
    return Response(stream_with_context(generate_output()), headers=headers)
    
if __name__== "__main__":
    app.run(debug="True" , port=8001)