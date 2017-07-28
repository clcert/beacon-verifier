from flask_script import Manager

from app import application

manager = Manager(application)

if __name__ == '__main__':
    manager.run()
