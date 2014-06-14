import handlers
import webapp2

application = webapp2.WSGIApplication([
    ('/login', handlers.LoginHandler),
    ('/logout', handlers.LogoutHandler),
    ('/signup', handlers.SignUpHandler),
    ('/reglas', handlers.ReglasHandler),
    ('/posiciones', handlers.PosicionesHandler),
    ('/resultados', handlers.ResultadosHandler),
    ('/usuarios', handlers.UsuariosHandler),
    ('/resultados_por_usuario', handlers.ResultadosPorUsuarioHandler),
    ('/add_users_results', handlers.AddUsersResultsHandler),
    ('/', handlers.MainPageHandler),
    ],
    debug = True)
