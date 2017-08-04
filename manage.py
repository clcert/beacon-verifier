from flask_script import Manager, Server

from app import application

manager = Manager(application)
manager.add_command("runserver", Server(port=5001))

if __name__ == '__main__':
    manager.run()
