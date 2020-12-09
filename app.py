from flask import Flask, render_template

# Creating App instance
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')