from flask import Flask, render_template, send_from_directory, send_file
import os
from dotenv import load_dotenv

from config import *
from routes.blog import blog_bp

app = Flask(__name__)
app.config['SECRET_KEY'] = ",jhvzsdkfgwryigvyiyrbaego75gtrfw3758o7f3qryigfo8w3rgfuyrwvtarwgvyruyrgvw3kyrgv3wgviyerwg"

load_dotenv()

# API key defined in .env. Must match key defined in the Discord bot's .env file.
blu_api_key = os.getenv('BLU_API_KEY')
DISCORD_CLIENT_SECRET = os.getenv('DISCORD_CLIENT_SECRET')

# Icon in browser tab
@app.route('/favicon.ico')
def favicon():
    return send_from_directory('static/images', 'favicon.ico', mimetype='image/vnd.microsoft.icon')

# Robots file, SEO baby
@app.route('/robots.txt')
def robots_txt():
    return send_file('static/robots.txt', mimetype='text/plain')


# Landing page
@app.route("/")
def dashboard():

    return render_template("index.html")


@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/resources')
def resources():
    return render_template('resources.html')


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
