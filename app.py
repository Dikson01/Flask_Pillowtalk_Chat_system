from flask import Flask,render_template
app = Flask(__name__)

# @app.route('/')
# def home():
#     return 'yo bro this is my flask page 1'

@app.route('/')
def index():
    return render_template("index.html")





if __name__ == '__main__':
    app.run(debug=True)