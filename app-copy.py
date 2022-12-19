pip install flask
pip install flask-sqlalchemy


from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///packets.db'
db = SQLAlchemy(app)

class Packet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    src_ip = db.Column(db.String(50))
    dst_ip = db.Column(db.String(50))
    payload = db.Column(db.Text)

    def __init__(self, src_ip, dst_ip, payload):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.payload = payload


@app.route('/packet', methods=['POST'])
def process_packet():
    src_ip = request.form['src_ip']
    dst_ip = request.form['dst_ip']
    payload = request.form['payload']

    packet = Packet(src_ip, dst_ip, payload)
    db.session.add(packet)
    db.session.commit()

    return 'Packet added to database!'

db.session.close()
