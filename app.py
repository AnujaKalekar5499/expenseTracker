from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:Welcome!1@localhost/expense_tracker'
app.config['SECRET_KEY'] = 'LEMYJUmtvZX6Gftu2DN6MPPBFxbG6L'
app.config['JWT_SECRET_KEY'] = '0MwS8qtyZX3ZCw1rXTj9W2DgE2Bd6i'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    comments = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/auth/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        data = request.form
        hashed_password = bcrypt.generate_password_hash(data.get('password')).decode('utf-8')
        new_user = User(username=data.get('username'), email=data.get('email'), password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"msg": "Sign up successful!"}), 200
    return render_template('signup.html')

@app.route('/auth/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        user = User.query.filter_by(email=data.get('email')).first()
        if user and bcrypt.check_password_hash(user.password, data.get('password')):
            access_token = create_access_token(identity={'id': user.id, 'username': user.username})
            return jsonify({"access_token": access_token}), 200
        return jsonify({"msg": "Invalid credentials"}), 401
    return render_template('login.html')

@app.route('/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    return render_template('dashboard.html')

@app.route('/expenses', methods=['GET', 'POST'])
@jwt_required()
def handle_expenses():
    current_user = get_jwt_identity()
    user_id = current_user['id']
    
    if request.method == 'POST':
        data = request.form
        new_expense = Expense(
            user_id=user_id,
            category=data.get('category'),
            amount=data.get('amount'),
            comments=data.get('comments')
        )
        db.session.add(new_expense)
        db.session.commit()
        return jsonify({"msg": "Expense added successfully!"}), 200
    
    expenses = Expense.query.filter_by(user_id=user_id).order_by(Expense.created_at.desc()).all()
    return jsonify([{
        "id": expense.id,
        "category": expense.category,
        "amount": expense.amount,
        "created_at": expense.created_at,
        "updated_at": expense.updated_at,
        "comments": expense.comments
    } for expense in expenses]), 200

@app.route('/expenses/<int:id>', methods=['PUT', 'DELETE'])
@jwt_required()
def update_delete_expense(id):
    current_user = get_jwt_identity()
    expense = Expense.query.get_or_404(id)
    
    if expense.user_id != current_user['id']:
        return jsonify({"msg": "Permission denied"}), 403
    
    if request.method == 'PUT':
        data = request.form
        expense.category = data.get('category')
        expense.amount = data.get('amount')
        expense.comments = data.get('comments')
        db.session.commit()
        return jsonify({"msg": "Expense updated successfully!"}), 200
    
    if request.method == 'DELETE':
        db.session.delete(expense)
        db.session.commit()
        return jsonify({"msg": "Expense deleted successfully!"}), 200

if __name__ == '__main__':
    app.run(debug=True)
