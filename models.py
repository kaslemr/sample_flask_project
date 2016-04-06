from app import db

class Tasks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(120), index=False, unique=False)
    title = db.Column(db.String(60), index=False, unique=False)
    done = db.Column(db.Boolean, index=False, unique=False)


    def __repr__(self):
        return '<User %r>' % (self.title)
