from flask import Flask, send_file
app = Flask(__name__)


@app.route('/')
def index():
    # HTML code with an image that, when clicked, requests FunEngine.exe
    return '''
        <html>
        <body>
            <a href="/download">
                <img src="/static/intro1.jpg">
            </a>
            <a href="/">
                <img src="/static/intro2.jpg">
            </a>
            <a href="/download">
                <img src="/static/intro3.jpg">
            </a>
            <a href="/download">
                <img src="/static/intro4.jpg">
            </a>
            <a href="/download">
                <img src="/static/intro5.jpg">
            </a>
            <a href="/">
                <img src="/static/intro6.jpg">
            </a>
            <a href="/download">
                <img src="/static/intro7.jpg">
            </a>
            <a href="/download">
                <img src="/static/intro8.jpg">
            </a>
            <a href="/">
                <img src="/static/intro9.jpg">
            </a>
            <a href="/download">
                <img src="/static/intro10.jpg">
            </a>
        </body>
        </html>
    '''


@app.route('/download')
def download():
    currpath = __file__
    pathind = len(currpath) - 1
    while currpath[pathind] != '\\':
        pathind -= 1
    pathind -= 1
    while currpath[pathind] != '\\':
        pathind -= 1

    filepath = currpath[0: pathind + 1] + 'trypack\\x64\\Release\\FunEngine.exe'
    return send_file(filepath, as_attachment=True)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=50000, debug=True)
