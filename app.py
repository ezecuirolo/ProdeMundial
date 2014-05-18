import handlers
import webapp2

application = webapp2.WSGIApplication([
    ('/login', handlers.LoginHandler),
    ('/logout', handlers.LogoutHandler),
    ('/signup', handlers.SignUpHandler),
    ('/reglas', handlers.ReglasHandler),
    ('/posiciones', handlers.PosicionesHandler),
    ('/', handlers.MainPageHandler),
    ],
    debug = True)
