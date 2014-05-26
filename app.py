import handlers
import webapp2

application = webapp2.WSGIApplication([
    ('/login', handlers.LoginHandler),
    ('/logout', handlers.LogoutHandler),
    ('/signup', handlers.SignUpHandler),
    ('/reglas', handlers.ReglasHandler),
    ('/posiciones', handlers.PosicionesHandler),
    ('/resultados', handlers.ResultadosHandler),
    ('/resultados_por_usuario', handlers.ResultadosPorUsuarioHandler),
    ('/', handlers.MainPageHandler),
    ],
    debug = True)
