"""O objetivo do código é criar um site que exige autenticação do usuário e guarda suas informações
em um db. A parte de html, css e a configuração inicial já vieram no arquivo pois o foco é a parte da
autenticação. Quando o usuário estiver registrado e logado ele vai ter acesso ao download do cheat_sheet.pdf.
O download será feito usando método do flask, send_file(). A parte de autenticação usando o hash para codificar
a senha usará werkzeug.security.generate_password_hash
Reparar na biblioteca flask_login que lida com as exigências para login no site e
Obs.: O DB viewer que ela fala no curso é o DB Browser que é o programa para visualizar externamente o DB"""

from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
"""aqui a sintaxe de iniciação do flask_login"""
login_manager = LoginManager()
login_manager.init_app(app)

"""essa sintaxe é para criar um 'carregador de usuário', ou seja, ele vai pegar o id do atual usuário da
página e carregar ou None se não houver um. Aqui o id foi transformado em um int. É exigido esse carregador para
que o flask_login funcione"""
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
"""a classe User foi criada para criar o usuário, atribuindo as características id, e-mail, password e name,
mas também usando o UserMixin que é uma classe que herda várias características de outras, conforme explicado
no material em anexo. No caso do UserMixin já estão embutidas as funções is_auhenticated(se está autenticado),
 is_active(se a conta não está suspensa ou qualquer coisa assim),is_anonymous(se é um usuário anônimo) e get_id
 (retorna uma string que idenfica unicamente o usuário, ela pode ser usada para carregar o usuário no 
 user_loader"""
##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
# Line below only required once, when creating DB.
# db.create_all()

"""aqui foi usado o conceito de template inheritance do JINJA/Flask, ou seja, o base.html vai ser modificado
 dependendo da condição aqui imposta. Lá o código é:
  </li>
        {% if not logged_in: %}"""
@app.route('/')
def home():
    # Every render_template has a logged_in variable set.
    return render_template("index.html", logged_in=current_user.is_authenticated)

"""a rota abaixo vai ser acionada quando o usuário clicar no botão Register na página principal, então,
vai levá-lo para a página /register, tratada no register.html, onde há  um formulário com nome, e-mail e senha
e vai guardar as informações digitadas pelos usuário no db (é possível ver as informações salvas no DB Browser),
então, após o preenchimento e quando o botão for clicado, o usuário vai ser redirecionado para a rota secrets.html.
 Reparar na lógica da identação, quando o método POST é selecionado através do clique no botão,
ele renderiza o html e aciona a lógica do DB
Já a parte do hash é a que faz a senha passar por uma function hash, conforme explicação no material em anexo,
mas que, em resumo, vai transformar a informação digitada em um código abstrado de formato e tamanhos diferentes
 do da senha. A sintaxe é generate_password_hash é o nome do método, request.form.get é o local de onde virá
  a informação da senha, method é o método hash que será usado, (é uma sintaxe com texto padrão)
  salt_lenght é o comprimento do "salt" em caracteres
  Também foi usada a função Message Flashing que dá um feedback ao usuário através de mensagens, por isso
  essa função flash que trabalha em conjunto com uma função no html
  Por fim, foi usada a função template inheritance para modificar a home page quando o usuário estiver logado
  e assim não mostrar os botões de login e register. A lógica é aproveitar o template e modificar
  apenas alguns elementos se alguma condição for atingida, também foi usada nas rotas secrets e login"""


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":

        if User.query.filter_by(email=request.form.get('email')).first():
            #User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            request.form.get('password'),
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=request.form.get('email'),
            name=request.form.get('name'),
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("secrets"))

    return render_template("register.html", logged_in=current_user.is_authenticated)

"""o código abaixo desvia para a rota do login.html se o método for o post, ou seja, se for inserida alguma
informação, então ele vai buscar as informações no formulário na sessão de nome e-mail e password, então o
filter_by vai procurar o primeiro e-mail ao digitado e a função check_passwrod_hash vai comparar o password
já na função hash. Aqui também foi usada a função flash para passar uma mensagem como feedback"""


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        # Email doesn't exist or password incorrect.
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('secrets'))

    return render_template("login.html", logged_in=current_user.is_authenticated)

"""a função built-in abaixo vai garantir que rota secrets só seja acessada se o usuário estiver logado. A 
documentação fala: 
flask_login.login_required(func)[source]
If you decorate a view with this, it will ensure that the current user is logged in and authenticated before 
calling the actual view. (If they are not, it calls the LoginManager.unauthorized callback.) For example:

@app.route('/post')
@login_required
def post():
    pass"""
@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)
    return render_template("secrets.html", name=current_user.name, logged_in=True)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


"""a rota abaixo vai lidar com o pedido de download quando o usuário clicar no href na página secrets.html,
o método aqui utilizado é flask.send_from_directory(directory, filename, **options)
Send a file from a given directory with send_file(). This is a secure way to quickly expose static
 files from an upload folder or something similar.

Example usage:

@app.route('/uploads/<path:filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename, as_attachment=True)"""
@app.route('/download')
@login_required
def download():
    return send_from_directory('static', filename="files/cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)
