# -*- coding: utf-8 -*-
import os
import webapp2
import jinja2
import dbmodels
from google.appengine.ext import db
from google.appengine.api import memcache
import logging
import utils
import json
import urllib2

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)


EQUIPOS={
    "teams": [
    {"group": "A", "teams": [
        {"code": "BRA", "key": "bra", "title": "Brasil"},
        {"code": "CRO", "key": "cro", "title": "Croacia"},
        {"code": "MEX", "key": "mex", "title": u'México'},
        {"code": "CMR", "key": "cmr", "title": u'Camerún'}]},
    {"group": "B", "teams": [
        {"code": "ESP", "key": "esp", "title": u'España'},
        {"code": "NED", "key": "ned", "title": "Holanda"},
        {"code": "CHI", "key": "chi", "title": "Chile"},
        {"code": "AUS", "key": "aus", "title": "Australia"}]},
    {"group": "C", "teams": [
        {"code": "COL", "key": "col", "title": "Colombia"},
        {"code": "GRE", "key": "gre", "title": "Grecia"},
        {"code": "CIV", "key": "civ", "title": "Costa de Marfil"},
        {"code": "JPN", "key": "jpn", "title": u'Japón'}]},
    {"group": "D", "teams": [
        {"code": "URU", "key": "uru", "title": "Uruguay"},
        {"code": "CRC", "key": "crc", "title": "Costa Rica"},
        {"code": "ENG", "key": "eng", "title": "Inglaterra"},
        {"code": "ITA", "key": "ita", "title": "Italia"}]},
    {"group": "E", "teams": [
        {"code": "SUI", "key": "sui", "title": "Suiza"},
        {"code": "ECU", "key": "ecu", "title": "Ecuador"},
        {"code": "FRA", "key": "fra", "title": "Francia"},
        {"code": "HON", "key": "hon", "title": "Honduras"}]},
    {"group": "F", "teams": [
        {"code": "ARG", "key": "arg", "title": "Argentina"},
        {"code": "BIH", "key": "bih", "title": "Bosnia"},
        {"code": "IRN", "key": "irn", "title": u'Irán'},
        {"code": "NGA", "key": "nga", "title": "Nigeria"}]},
    {"group": "G", "teams": [
        {"code": "GER", "key": "ger", "title": "Alemania"},
        {"code": "POR", "key": "por", "title": "Portugal"},
        {"code": "GHA", "key": "gha", "title": "Ghana"},
        {"code": "USA", "key": "usa", "title": "EE.UU."}]},
    {"group": "H", "teams": [
        {"code": "RUS", "key": "rus", "title": "Rusia"},
        {"code": "BEL", "key": "bel", "title": u'Bélgica'},
        {"code": "ALG", "key": "alg", "title": "Argelia"},
        {"code": "KOR", "key": "kor", "title": "Corea del sur"}]}]
}

def getGrupoDeEquipo(codigo_equipo):
    for grupo in EQUIPOS["teams"]:
        for equipo in grupo["teams"]:
            if equipo["code"] == codigo_equipo:
                return grupo["group"]

def getNombreEquipo(codigo_equipo):
    for grupo in EQUIPOS["teams"]:
        for equipo in grupo["teams"]:
            if equipo["code"] == codigo_equipo:
                return equipo["title"]



########## BASE HANDLER ##########
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, user = self.user, **kw))

    def not_found(self):
        self.write("Not Found")


    def set_secure_cookie(self, name, val):
        cookie_val = utils.make_secure_value(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/'
                                         % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and utils.check_secure_value(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.delete_cookie('user_id')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        user_id = self.read_secure_cookie('user_id')
        self.user = user_id and dbmodels.User.by_id(int(user_id))


########## SIGN UP HANDLER ##########
class SignUpHandler(Handler):
    def render_page(self, **params):
        self.render("signup.html", **params)
    
    def get(self):
        self.render_page()

    def post(self):
        params = {}
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        params["username"] = username
        params["email"] = email

        error_en_form = False

        if not utils.valid_username_form(username):
            params["error_username"] = "Nombre de usuario invalido"
            error_en_form = True
        else:
            u = dbmodels.User.by_name(username)
            if u:
                params["error_username"] = "Usuario ya existe"
                error_en_form = True
                
        if not utils.valid_password_form(password):
            params["error_password"] = "Contrasena invalida"
            error_en_form = True
        elif password != verify:
            params["error_verify"] = "Las contrasenas son distintas"
            error_en_form = True

        if not utils.valid_email_form(email):
            params["error_email"] = "email invalido"
            error_en_form = True

        if error_en_form:
            self.render_page(**params)
        else:
            user = dbmodels.User.register(username, password, email)
            user.put()

            self.login(user)

            self.redirect("/")


########## LOGIN HANDLER ##########
class LoginHandler(Handler):
    def render_page(self, error = ""):
        self.render("login.html", error_login = error)

    def get(self):
        self.render_page()

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")

        user = dbmodels.User.validate(username, password)
        if user:
            self.login(user)
            self.redirect('/')
        else:
            error = "Invalid user and pass"
            self.render_page(error)



########## LOGOUT HANDLER ##########
class LogoutHandler(Handler):
    def get(self):
        self.response.delete_cookie('user_id')
        self.redirect('/')


########## MAIN PAGE HANDLER ##########
class MainPageHandler(Handler):
    def get(self):
        for round in range(1,20):
            key = str(round)
            ronda = memcache.get(key)
            if ronda is None:
                url = 'http://footballdb.herokuapp.com/api/v1/event/world.2014/round/' + str(round)
                round_data = urllib2.urlopen(url).read()
                round_json = json.loads(round_data)
                memcache.set(key, round_json)

        fixture = {'A': {'tipo': 'grupo', 'permite-modificar': True, 'partidos': []},
                   'B': {'tipo': 'grupo', 'permite-modificar': True, 'partidos': []},
                   'C': {'tipo': 'grupo', 'permite-modificar': True, 'partidos': []},
                   'D': {'tipo': 'grupo', 'permite-modificar': True, 'partidos': []},
                   'E': {'tipo': 'grupo', 'permite-modificar': True, 'partidos': []},
                   'F': {'tipo': 'grupo', 'permite-modificar': True, 'partidos': []},
                   'G': {'tipo': 'grupo', 'permite-modificar': True, 'partidos': []},
                   'H': {'tipo': 'grupo', 'permite-modificar': True, 'partidos': []},
                   }
        
        for round in range(1, 20):
            key = str(round)
            ronda = memcache.get(key)
            for game in ronda["games"]:
                grupo = getGrupoDeEquipo(game["team1_code"])
                equipo1 = getNombreEquipo(game["team1_code"])
                equipo2 = getNombreEquipo(game["team2_code"])
                scoreEquipo1 = game["score1"]
                scoreEquipo2 = game["score2"]

                if scoreEquipo1 is None:
                    scoreEquipo1 = ""

                if scoreEquipo2 is None:
                    scoreEquipo2 = ""


                fecha = game["play_at"]

                partido = {"fecha": fecha,
                           "equipo1": equipo1,
                           "equipo2": equipo2,
                           "scoreEquipo1": scoreEquipo1,
                           "scoreEquipo2": scoreEquipo2}
                fixture[grupo]["partidos"].append(partido)
                


            
        self.render("index.html", fixture = fixture);
