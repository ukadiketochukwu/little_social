from social import app

@app.errorhandler(404)
def page_not_found(e):
    return "<h1>404 Page Not Found</h1>", 404


@app.errorhandler(403)
def page_not_found(e):
    return "<h1>403 You do not have permission to do that.</h1>", 403


