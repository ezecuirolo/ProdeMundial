from google.appengine.ext import db
import utils

class WikiPage(db.Model):
    name = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def by_name(cls, page_name):
        q = cls.all().filter('name =', page_name)
        q.order("-created")
        return q

    @classmethod
    def by_id(cls, page_id, page_name):
        return cls.get_by_id(page_id)


class User(db.Model):
    name = db.StringProperty(required = True)
    password_hash = db.StringProperty(required = True)
    email = db.EmailProperty()
    created = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def by_id(cls, user_id):
        return cls.get_by_id(user_id)

    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, password, email = None):
        pw_hash = utils.make_password_hash(name, password)
        u = cls(name = name, password_hash = pw_hash)
        if email:
            u.email = email
        return u

    @classmethod
    def validate(cls, name, password):
        u = cls.by_name(name)
        if u and utils.valid_password(name, password, u.password_hash):
            return u

