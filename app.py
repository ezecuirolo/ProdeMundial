import handlers
import webapp2

application = webapp2.WSGIApplication([
    ('/login', handlers.LoginHandler),
    ('/logout', handlers.LogoutHandler),
    ('/signup', handlers.SignUpHandler),
    ('/', handlers.MainPageHandler),
    ],
    debug = True)
