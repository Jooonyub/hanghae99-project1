from pymongo import MongoClient
import jwt
import datetime
import hashlib  #hashlib.sha256(password_receive.encode('utf-8')).hexdigest()
from flask import Flask, render_template, jsonify, request, redirect, url_for
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta

app = Flask(__name__)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config['UPLOAD_FOLDER'] = "./static/profile_pics"
SECRET_KEY = 'SPARTA'

#일단은 로컬로 되는지 파악한 후에 AWS로 연결하기
client = MongoClient('localhost', 27017)
#client = MongoClient('내AWS아이피', 27017, username="아이디", password="비밀번호")
db = client.members

#기본화면
@app.route('/')
def home():
    '''
    쿠키에 로그인 정보가 있으면 payload 작성 후 index.html 렌더링
    정보가 없으면 login창으로 redirect(알맞은 메시지 작성)
    '''
    #발급한 jwt토큰(여기에 토큰이 답겨져서 서버로 온다)
    token_receive = request.cookies.get('mytoken')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        #user_info = db.user.find_one({"id": payload["id"]})
        #return render_template('index.html', user=user_info["username"])
        return render_template('index.html', user=payload["id"])
    except jwt.ExpiredSignatureError:
        return redirect(url_for("login", msg="로그인 시간이 만료되었습니다."))
    except jwt.exceptions.DecodeError:
        return redirect(url_for("login", msg="로그인 정보가 존재하지 않습니다."))

#로그인 창 API
@app.route('/login')
def login():
    msg = request.args.get("msg")
    return render_template('login.html', msg=msg)

#로그인기능 API
@app.route('/sign_in', methods=['POST'])
def sign_in():
    # 로그인
    username_receive = request.form['username_give']
    password_receive = request.form['password_give']

    #입력받은 비밀번호에 대한 암호화 진행(hashlib.sha256())
    pw_hash = hashlib.sha256(password_receive.encode('utf-8')).hexdigest()
    result = db.users.find_one({'username': username_receive, 'password': pw_hash})

    if result is not None:
        payload = {
         'id': username_receive,
         'exp': datetime.utcnow() + timedelta(seconds=60 * 60 * 24)  # 로그인 24시간 유지
        }
        #페이로드에 대한 암호화(jwt)
        #token = jwt.encode(payload, SECRET_KEY, algorithm='HS256').decode('utf-8')
        token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

        return jsonify({'result': 'success', 'token': token})
    # 찾지 못하면
    else:
        return jsonify({'result': 'fail', 'msg': '아이디/비밀번호가 일치하지 않습니다.'})

#회원가입 API
@app.route('/sign_up/save', methods=['POST'])
def sign_up():
    username_receive = request.form['username_give']
    password_receive = request.form['password_give']
    password_hash = hashlib.sha256(password_receive.encode('utf-8')).hexdigest()
    doc = {
        "username": username_receive,                               # 아이디
        "password": password_hash,                                  # 비밀번호
        #"profile_name": username_receive,                           # 프로필 이름 기본값은 아이디
        #"profile_pic": "",                                          # 프로필 사진 파일 이름
        #"profile_pic_real": "profile_pics/profile_placeholder.png", # 프로필 사진 기본 이미지
        #"profile_info": ""                                          # 프로필 한 마디
    }
    db.users.insert_one(doc)
    return jsonify({'result': 'success'})

#회원가입시 중복확인 API
@app.route('/sign_up/check_dup', methods=['POST'])
def check_dup():
    username_receive = request.form['username_give']
    exists = bool(db.users.find_one({"username": username_receive}))
    return jsonify({'result': 'success', 'exists': exists})

#포스트 기능(form:장소이름, 코멘트)
@app.route('/map_list/write', methods=['POST'])
def posting():
    token_receive = request.cookies.get('mytoken')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])

        # 포스팅하기
        place_receive = request.form['placename_give']
        comment_receive = request.form['comment_give']
        user_receive = payload['id']
        #districtname_receive = 지역이름 어떻게 가져올지 생각하

        doc = {
            'user' : user_receive,
            'districtname' : districtname_receive,
            'placename' : place_receive,
            'comment' : comment_receive,
            'datetime' : datetime_receive
        }
        db.placeinfo.insert_one(doc)

        return jsonify({"result": "success", 'msg': '포스팅 성공'})
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for("home"))

#포스트 목록 가져오기(장소이름, 코멘트, 장소 geodata, 사용자 ID)
@app.route("/map_list/<district>", methods=['GET'])
def get_posts(district):
    token_receive = request.cookies.get('mytoken')
    try:
        # 포스팅 목록 받아오기
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        all_lists = list(db.placeinfo.find({'districtname':district}, {'_id': False}))

        return jsonify({"result": "success", "msg": "포스팅을 가져왔습니다.", "user":payload["id"], "all_lists":all_lists, 'datetime':datetime})
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for("home"))

'''
#포스트 기능(form:장소이름, 코멘트)
@app.route('/posting', methods=['POST'])
def posting():
    token_receive = request.cookies.get('mytoken')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        # 포스팅하기
        return jsonify({"result": "success", 'msg': '포스팅 성공'})
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for("home"))

#포스트 목록 가져오기(장소이름, 코멘트, 장소 geodata, 사용자 ID)
@app.route("/get_posts", methods=['GET'])
def get_posts():
    token_receive = request.cookies.get('mytoken')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        # 포스팅 목록 받아오기
        return jsonify({"result": "success", "msg": "포스팅을 가져왔습니다."})
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for("home"))
'''


'''
#좋아요 API(일단 보류) 
@app.route('/update_like', methods=['POST'])
def update_like():
    token_receive = request.cookies.get('mytoken')
    try:
        payload = jwt.decode(token_receive, SECRET_KEY, algorithms=['HS256'])
        # 좋아요 수 변경
        return jsonify({"result": "success", 'msg': 'updated'})
    except (jwt.ExpiredSignatureError, jwt.exceptions.DecodeError):
        return redirect(url_for("home"))
'''

if __name__ == '__main__':
    app.run('0.0.0.0', port=5000, debug=True)