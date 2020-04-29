import hashlib
import datetime
import jwt
from pymongo import MongoClient
import os
from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from flask_socketio import SocketIO, emit

app = Flask(__name__)

# client = MongoClient('mongodb://test:test@13.124.246.129', 27017)
client = MongoClient('localhost', 27017)
db = client.dbsparta

# JWT 토큰을 만들 때 필요한 비밀문자열입니다. 아무거나 입력해도 괜찮습니다.
# 이 문자열은 서버만 알고있기 때문에, 내 서버에서만 토큰을 인코딩(=만들기)/디코딩(=풀기) 할 수 있습니다.
SECRET_KEY = 'apple'
app.SECRET_KEY = 'apple'
socketio = SocketIO(app)

user_no = 1

# JWT 패키지를 사용합니다. (설치해야할 패키지 이름: PyJWT)

# 토큰에 만료시간을 줘야하기 때문에, datetime 모듈도 사용합니다.

# 회원가입 시엔, 비밀번호를 암호화하여 DB에 저장해두는 게 좋습니다.
# 그렇지 않으면, 개발자(=나)가 회원들의 비밀번호를 볼 수 있으니까요.^^;

#################################
##  HTML을 주는 부분             ##
#################################
@app.route('/')
def home():
    return render_template('index.html')


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/main')
def main():
    return render_template('main.html')


@app.route('/signup')
def signup():
    return render_template('signup.html')

# @app.route('/edit_info')
# def edit_info():
#    return render_template('edit_info.html')

#################################
##  로그인을 위한 API            ##
#################################

# [회원가입 API]
# id, pw, nickname을 받아서, mongoDB에 저장합니다.
# 저장하기 전에, pw를 sha256 방법(=단방향 암호화. 풀어볼 수 없음)으로 암호화해서 저장합니다.
@app.route('/api/signup', methods=['POST'])
def api_signup():
    id_receive = request.form['id_give']
    pw_receive = request.form['pw_give']
    pwcheck_receive = request.form['pwcheck_give']
    nickname_receive = request.form['nickname_give']
    phonenumber_receive = request.form['phonenumber_give']
    birthday_receive = request.form['birthday_give']

    pw_hash = hashlib.sha256(pw_receive.encode('utf-8')).hexdigest()
    pwcheck_hash = hashlib.sha256(pwcheck_receive.encode('utf-8')).hexdigest()

    doc = {'id': id_receive, 'pw': pw_receive, 'pwcheck': pwcheck_receive,
           'nickname': nickname_receive, 'phonenumber': phonenumber_receive, 'birthday': birthday_receive}
    db.user.insert_one(doc)

    return jsonify({'result': 'success', 'msg': '회원가입이 완료되엇습니다.'})

# [이메일중복확인 API]
@app.route('/api/signup/id', methods=['POST'])
def id_overlap_check():
    id_receive = request.form['id_give']

    # 중복 검사 실패
    if db.user.find_one({'id': id_receive}):
        return jsonify({'result': 'fail', 'msg': '이미 사용중인 아이디 입니다.'})

    return jsonify({'result': 'success'})

# [닉네임중복확인 API]
@app.route('/api/signup/nick', methods=['POST'])
def nick_overlap_check():
    nickname_receive = request.form['nickname_give']

    # 중복 검사 실패
    if db.user.find_one({'nickname': nickname_receive}):
        return jsonify({'result': 'fail', 'msg': '이미 사용중인 닉네임 입니다.'})

    return jsonify({'result': 'success'})

# [로그인 API]
# id, pw를 받아서 맞춰보고, 토큰을 만들어 발급합니다.
@app.route('/api/login', methods=['POST'])
def api_login():
    id_receive = request.form['id_give']
    pw_receive = request.form['pw_give']

    # 회원가입 때와 같은 방법으로 pw를 암호화합니다.
    pw_hash = hashlib.sha256(pw_receive.encode('utf-8')).hexdigest()

    # id, 암호화된pw을 가지고 해당 유저를 찾습니다.
    result = db.user.find_one({'id': id_receive, 'pw': pw_receive})

    # 찾으면 JWT 토큰을 만들어 발급합니다.
    if result is not None:
        # JWT 토큰에는, payload와 시크릿키가 필요합니다.
        # 시크릿키가 있어야 토큰을 디코딩(=풀기) 해서 payload 값을 볼 수 있습니다.
        # 아래에선 id와 exp를 담았습니다. 즉, JWT 토큰을 풀면 유저ID 값을 알 수 있습니다.
        # exp에는 만료시간을 넣어줍니다. 만료시간이 지나면, 시크릿키로 토큰을 풀 때 만료되었다고 에러가 납니다.
        payload = {
            'id': id_receive,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=30)
        }
        token = jwt.encode(payload, SECRET_KEY,
                           algorithm='HS256').decode('utf-8')

        # token을 줍니다.
        return jsonify({'result': 'success', 'token': token})
    # 찾지 못하면
    else:
        return jsonify({'result': 'fail', 'msg': '아이디/비밀번호가 일치하지 않습니다.'})

# [유저 정보 확인 API]
# 로그인된 유저만 call 할 수 있는 API입니다.
# 유효한 토큰을 줘야 올바른 결과를 얻어갈 수 있습니다.
# (그렇지 않으면 남의 장바구니라든가, 정보를 누구나 볼 수 있겠죠?)
@app.route('/api/main', methods=['GET'])
def api_main():
    # 토큰을 주고 받을 때는, 주로 header에 저장해서 넘겨주는 경우가 많습니다.
    # header로 넘겨주는 경우, 아래와 같이 받을 수 있습니다.
    token_receive = request.headers['token_give']

    # try / catch 문?
    # try 아래를 실행했다가, 에러가 있으면 except 구분으로 가란 얘기입니다.

    try:
        # token을 시크릿키로 디코딩합니다.
        # 보실 수 있도록 payload를 print 해두었습니다. 우리가 로그인 시 넣은 그 payload와 같은 것이 나옵니다.
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        print(payload)

        # payload 안에 id가 들어있습니다. 이 id로 유저정보를 찾습니다.
        # 여기에선 그 예로 닉네임을 보내주겠습니다.
        userinfo = db.user.find_one({'id': payload['id']}, {'_id': 0})
        return jsonify({'result': 'success', 'nickname': userinfo['nick']})
    except jwt.ExpiredSignatureError:
        # 위를 실행했는데 만료시간이 지났으면 에러가 납니다.
        return jsonify({'result': 'fail', 'msg': '로그인 시간이 만료되었습니다.'})


@app.before_request
def before_request():
    global user_no
    if 'session' in session and 'user-id' in session:
        pass
    else:
        session['session'] = os.urandom(24)
        session['username'] = 'user'+str(user_no)
        user_no += 1


@socketio.on('connect', namespace='/mynamespace')
def connect():
    emit("response", {'data': 'Connected', 'username': session['username']})


@socketio.on('disconnect', namespace='/mynamespace')
def disconnect():
    session.clear()
    print("disconnected")


@socketio.on('request', namespace='/mynamespace')
def request(message):
    emit("response", {
         'data': message['data'], 'username': session['username']}, broadcast=True)


if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)
    socketio.run(app)
