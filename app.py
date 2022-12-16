from os import popen
import subprocess
from flask import Flask , render_template
from flask_sqlalchemy import SQLAlchemy
from ctypes import CDLL



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///ads.db"


@app.route('/')
def hello_world():
    return render_template("index1.html")


@app.route('/Reports')
def Reports():
    return "THis is reports Page"

@app.route('/Alerts and Alarms')
def Alerts():
    return render_template('alerts.html')


@app.route('/Log Activity')
def Logs():
    return "THis is Log Activity Page"

if __name__== "__main__":
    app.run(debug="True" , port=8001)