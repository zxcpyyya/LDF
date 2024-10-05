import base64
from flask import Flask, render_template, request, flash, url_for, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import random
import smtplib
from email.mime.text import MIMEText
from email.header import Header
from zhipuai import ZhipuAI
from datetime import datetime, timezone, timedelta

app = Flask(__name__)
app.config.from_object('config.Config')


def generate_verification_code():
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])


nickname = "智慧教育平台"
email_address = "206284929@qq.com"

# 对昵称进行Base64编码
encoded_nickname = base64.b64encode(nickname.encode('utf-8')).decode('utf-8')

# 构建完整的'From'头信息
from_header = f'=?utf-8?B?{encoded_nickname}=?= <{email_address}>'

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # 设置会话有效期为30分钟


# 发送邮件的函数
def send_verification_email(email, verification_code):
    smtp_server = 'smtp.qq.com'
    smtp_user = '206284929@qq.com'
    smtp_password = 'ztznowgbfxxnbiei'  # 这是授权码
    msg = MIMEText(f'您的验证码是：{verification_code}。有效期为十分钟，请勿向他人泄露。', 'plain', 'utf-8')
    msg['From'] = from_header
    msg['To'] = Header(email, 'utf-8')
    msg['Subject'] = Header('您的验证码', 'utf-8')
    try:
        server = smtplib.SMTP_SSL(smtp_server, 465)
        server.login(smtp_user, smtp_password)
        server.sendmail(smtp_user, email, msg.as_string())
        server.quit()
        # 记录验证码和时间到会话中
        session['verification_code'] = verification_code
        session['verification_time'] = datetime.now()  # 记录当前时间
        return True
    except Exception as e:
        print(f'邮件发送失败: {e}')
        return False


def get_db_connection():
    conn = sqlite3.connect('students.db')
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
           CREATE TABLE IF NOT EXISTS students (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               student_id TEXT NOT NULL,
               name TEXT NOT NULL,
               password TEXT NOT NULL,
               email TEXT NOT NULL DEFAULT ''  
           );
       ''')
        conn.commit()


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        student_id = request.form['student_id']
        password1 = request.form['password1']
        password2 = request.form['password2']
        email = request.form['email']
        session['student_id'] = student_id
        if password1 != password2:
            flash('两次密码输入不一致，请重新输入', 'danger')
        else:
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM students WHERE student_id=?', (student_id,))
                if cursor.fetchone():
                    flash('该学号已经注册过', 'danger')
                else:
                    hashed_password = generate_password_hash(password1)
                    cursor.execute('''
                       INSERT INTO students (name, student_id, password, email) VALUES (?, ?, ?, ?)
                   ''', (name, student_id, hashed_password, email))
                    conn.commit()
                    return redirect(url_for('register_success'))
            except sqlite3.Error as e:
                flash(f'数据库错误: {e.args[0] if e.args else e}', 'danger')
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        student_id = request.form['student_id']
        password = request.form['password']
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM students WHERE student_id=?', (student_id,))
                user = cursor.fetchone()
                if user and check_password_hash(user['password'], password):
                    session['student_id'] = student_id
                    # 登录成功，可以进行进一步的操作
                    return render_template('index.html', user=user)
                else:
                    flash('学号或密码错误，请检查后重新输入', 'danger')
        except sqlite3.Error as e:
            flash(f'数据库错误: {e.args[0] if e.args else e}', 'danger')
    return render_template('login.html')


@app.route('/')
def index():
    user = None
    if 'student_id' in session:
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM students WHERE student_id=?', (session['student_id'],))
                user = cursor.fetchone()
        except sqlite3.Error as e:
            flash(f'数据库错误: {e.args[0] if e.args else e}', 'danger')
            return redirect(url_for('login'))

    return render_template('index.html', user=user)


@app.route('/forget_password', methods=['GET', 'POST'])
def forget_password():
    if request.method == 'POST':
        student_id = request.form['student_id']
        email = request.form['email']
        session['student_id'] = student_id
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM students WHERE student_id=? AND email=?', (student_id, email))
            user = cursor.fetchone()
            if user:
                # 直接通过键名访问列的值
                print("ID:", user['id'])
                print("Name:", user['name'])
                print("Student ID:", user['student_id'])
                print("Email:", user['email'])
                # 如果找到用户，生成验证码并发送邮件
                verification_code = generate_verification_code()
                if send_verification_email(user['email'], verification_code):
                    session['verification_code'] = verification_code
                    return render_template('verify_code_input.html')
                    # 将验证码和用户ID存储在会话中
                else:
                    flash('验证码发送失败，请稍后再试。', 'danger')
            else:
                flash('该学号或邮箱错误！请检查后重新填写。', 'danger')
        except sqlite3.Error as e:
            flash(f'数据库错误: {e.args[0] if e.args else e}', 'danger')
    return render_template('forget_password.html')


@app.route('/verify_code_input', methods=['GET', 'POST'])
def verify_code():
    if request.method == 'POST':
        entered_code = request.form['verification_code']
        # 获取当前UTC时间
        current_time_utc = datetime.now(timezone.utc)

        # 检查会话中是否有验证码和时间
        if 'verification_code' in session and 'verification_time' in session:
            verification_code_session = session['verification_code']
            verification_time_session = session['verification_time']

            # 确保verification_time_session是时区感知的
            if verification_time_session.tzinfo is None:
                verification_time_session = verification_time_session.replace(tzinfo=timezone.utc)

            # 计算时间差
            time_diff = current_time_utc - verification_time_session

            # 检查是否超过10分钟
            if time_diff.total_seconds() > 600:
                flash('验证码已过期，请重新获取。', 'danger')
            elif entered_code == verification_code_session:
                # 验证码正确，继续后续操作
                return render_template('reset_password.html')
            else:
                flash('验证码错误，请重新输入。', 'danger')
        else:
            flash('验证码无效，请重新获取。', 'danger')
    return render_template('verify_code_input.html')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        new_password = request.form['password1']
        confirm_password = request.form['password2']
        student_id = session.get('student_id')
        # 确保新密码和确认密码相同
        if new_password != confirm_password:
            flash('两次输入的密码不一致，请检查后重新输入', 'danger')
            return redirect(url_for('reset_password'))
        else:
            # 更新数据库中的密码
            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                hashed_password = generate_password_hash(new_password)

                cursor.execute('''
                          UPDATE students SET password=? WHERE student_id=?
                      ''', (hashed_password, student_id))
                conn.commit()
            except sqlite3.Error as e:
                flash(f'数据库错误: {e.args[0] if e.args else e}', 'danger')
            return redirect(url_for('reset_password_success'))
    return render_template('reset_password.html')


@app.route('/reset_password_success', methods=['GET', 'POST'])
def reset_password_success():
    if request.method == 'POST':
        return render_template('login.html')
    return render_template('reset_password_success.html')


@app.route('/register_success')
def register_success():
    return render_template('register_success.html')


client = ZhipuAI(api_key="aefb1b0854138803d342f319d9ca9ff8.mDMe8UQ7P9KZbnTQ")


@app.route('/ai_assistant', methods=['GET', 'POST'])
def ai_assistant():
    if 'student_id' not in session:
        # 如果用户未登录，重定向到登录页面
        return redirect(url_for('login'))

    chat_history = session.get('chat_history', [])
    user_question = ""
    ai_answer = ""

    if request.method == 'POST':
        user_question = request.form['question']
        try:
            response = client.chat.completions.create(
                model="glm-4",  # 确保这是正确的模型名称
                messages=[
                    {"role": "user", "content": user_question}
                ],
            )
            ai_answer = response.choices[0].message.content
            # 将用户问题和AI的回答添加到对话历史中
            chat_history.append((user_question, ai_answer))
        except Exception as e:
            ai_answer = f"AI助手出现错误：{str(e)}"
            flash('AI助手无法回答问题，请稍后再试。', 'danger')

    # 更新会话中的对话历史
    session['chat_history'] = chat_history

    return render_template('ai_assistant.html', question=user_question, answer=ai_answer, chat_history=chat_history)


@app.route('/courses')
def courses():
    return render_template('courses.html')


@app.route('/logout')
def logout():
    session.clear()  # 清除会话中的所有信息
    return redirect(url_for('index'))  # 重定向到首页或登录页面


@app.route('/progress')
def progress():
    return render_template('progress.html')


@app.route('/notifications')
def notifications():
    return render_template('notifications.html')


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
