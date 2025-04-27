from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import (
    LoginManager, login_user, logout_user,
    current_user, login_required
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timezone
from sqlalchemy import func
import os, re

from my_models import (
    db, User, Question, Friendship,
    Visit, LetterBlock
)

# ─── 앱 & DB 설정 ───
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///asked.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)
Migrate(app, db)

# ─── Flask-Login 설정 ───
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ─── 유틸 함수 ───
def get_avatar_list():
    folder = os.path.join(app.static_folder, 'avatars')
    return [f for f in os.listdir(folder) if f.endswith('.svg')]

# ─── 인덱스 ───
@app.route('/')
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return redirect(url_for('profile', user_id=current_user.id))

# ─── 회원가입 ───
@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        userid = request.form['userid'].strip()
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        avatar_filename = request.form['selectedAvatar'].replace(" ", "_")
        avatar_color = request.form['avatarColor']

        if not re.match(r'^[A-Za-z0-9]{4,16}$', userid):
            flash('아이디는 영문+숫자 4~16자입니다.', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(userid=userid).first():
            flash('이미 존재하는 아이디입니다.', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('이미 사용 중인 이메일입니다.', 'danger')
            return redirect(url_for('register'))

        new_user = User(
            userid=userid,
            username=username,
            email=email,
            password=generate_password_hash(password),
            avatar_filename=avatar_filename,
            avatar_color=avatar_color
        )
        db.session.add(new_user)
        db.session.commit()
        flash('회원가입 성공! 로그인 해주세요.', 'success')
        return redirect(url_for('login'))

    avatars = get_avatar_list()
    return render_template('register.html', avatars=avatars)

@app.route('/check_userid')
def check_userid():
    userid = request.args.get('userid', '').strip()
    exists = User.query.filter_by(userid=userid).first() is not None
    return jsonify({'exists': exists})


# ─── 로그인 / 로그아웃 ───
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        userid = request.form['userid']
        password = request.form['password']
        user = User.query.filter_by(userid=userid).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('로그인 성공!', 'success')
            return redirect(url_for('profile', user_id=user.id))
        flash('아이디 또는 비밀번호가 올바르지 않습니다.', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('로그아웃 되었습니다.', 'info')
    return redirect(url_for('login'))

# ─── 메인 페이지 ───
@app.route('/main')
@login_required
def main_page():
    users = User.query.all()
    return render_template('main.html', user=current_user, users=users)

# ─── 질문 보내기 ───
@app.route('/ask/<int:friend_id>', methods=['GET','POST'])
@login_required
def ask_question(friend_id):
    friend = User.query.get_or_404(friend_id)
    if request.method == 'POST':
        text = request.form.get('question_text','').strip()
        if text:
            q = Question(
                question_text=text,
                user_id=current_user.id,
                friend_id=friend_id
            )
            db.session.add(q)
            db.session.commit()
            flash('질문이 전송되었습니다!', 'success')
            return redirect(url_for('profile', user_id=friend_id))
    return render_template('ask.html', friend=friend)

# ─── 질문 상세/답변 ───
@app.route('/question/<int:question_id>', methods=['GET','POST'])
@login_required
def question_detail(question_id):
    q = Question.query.get_or_404(question_id)
    me = current_user.id

    if q.is_private and me not in [q.user_id, q.friend_id]:
        flash('비공개 질문에 접근할 수 없습니다.', 'danger')
        return redirect(url_for('profile', user_id=me))

    if me == q.friend_id and not q.is_read:
        q.is_read = True
        db.session.commit()

    if request.method == 'POST':
        if me != q.friend_id:
            flash('답변 권한이 없습니다.', 'danger')
            return redirect(url_for('question_detail', question_id=question_id))
        ans = request.form.get('answer_text','').strip()
        if ans:
            q.answer_text = ans
            db.session.commit()
            flash('답변이 저장되었습니다!', 'success')
            return redirect(url_for('profile', user_id=me))

    return render_template(
        'question_detail.html',
        question=q,
        current_user_id=me
    )

# ─── 공개 토글 (질문) ───
@app.route('/toggle_privacy/<int:question_id>', methods=['POST'])
@login_required
def toggle_privacy(question_id):
    q = Question.query.get_or_404(question_id)
    if current_user.id != q.friend_id:
        return jsonify(success=False, message='권한이 없습니다.'), 403
    q.is_private = not q.is_private
    db.session.commit()
    flash('공개 상태가 변경되었습니다.', 'success')
    return redirect(url_for('question_detail', question_id=question_id))

# ─── 친구 관리 ───
@app.route('/friends')
@login_required
def friends_page():
    user = current_user
    # 받은 요청
    reqs = (
        db.session.query(Friendship.id, User.username, User.userid,
                         User.avatar_filename, User.avatar_color)
        .join(User, Friendship.user_id==User.id)
        .filter(Friendship.friend_id==user.id,
                Friendship.status=='pending')
        .all()
    )
    # 내 친구
    fds = (
        db.session.query(User)
        .join(Friendship, User.id==Friendship.friend_id)
        .filter(Friendship.user_id==user.id,
                Friendship.status=='accepted')
        .all()
    )
    return render_template('friends.html',
                           user=user,
                           friends=fds,
                           friend_requests=reqs)

@app.route('/search_friends')
@login_required
def search_friends():
    q = request.args.get('query','').strip()
    if not q:
        return jsonify(success=False, message='검색어를 입력하세요.')
    me = current_user
    tgt = User.query.filter_by(userid=q).first()
    if not tgt or tgt.id==me.id:
        return jsonify(success=False, message='검색 결과가 없습니다.')
    return jsonify({
        'success': True,
        'friends': [{
            'id': tgt.id,
            'username': tgt.username,
            'userid': tgt.userid,
            'avatar_filename': tgt.avatar_filename,
            'avatar_color': tgt.avatar_color
        }]
    })

@app.route('/add_friend/<int:friend_id>', methods=['POST'])
@login_required
def add_friend(friend_id):
    me = current_user
    other = User.query.get_or_404(friend_id)
    if Friendship.query.filter_by(user_id=me.id,
                                  friend_id=other.id).first():
        return jsonify(success=False,
                       message='이미 요청했거나 친구입니다.')
    fr = Friendship(user_id=me.id,
                    friend_id=other.id,
                    status='pending')
    db.session.add(fr)
    db.session.commit()
    return jsonify(success=True,
                   message=f'{other.username}님에게 요청을 보냈습니다.')

@app.route('/respond_friend_request/<int:req_id>', methods=['POST'])
@login_required
def respond_friend_request(req_id):
    print(f"[요청 수신] 요청 ID: {req_id}")  # ✅ 요청 도달 여부 확인
    data = request.get_json()
    print(f"[받은 데이터] {data}")         # ✅ JSON body 확인

    act  = data.get('action')
    fr   = Friendship.query.get_or_404(req_id)

    if current_user.id != fr.friend_id:
        return jsonify(success=False, message='권한이 없습니다.')

    if act == 'accept':
        fr.status = 'accepted'
        rev = Friendship(
            user_id=fr.friend_id,
            friend_id=fr.user_id,
            status='accepted'
        )
        db.session.add(rev)
        db.session.commit()
        return jsonify(success=True, message='친구 요청을 수락했습니다.')

    elif act == 'reject':
        db.session.delete(fr)
        db.session.commit()
        return jsonify(success=True, message='친구 요청을 거절했습니다.')

    return jsonify(success=False, message='알 수 없는 요청입니다.')


@app.route('/remove_friend/<int:friend_id>', methods=['POST'])
@login_required
def remove_friend(friend_id):
    me = current_user
    other = User.query.get_or_404(friend_id)
    rels = Friendship.query.filter(
        ((Friendship.user_id==me.id)&
         (Friendship.friend_id==other.id))|
        ((Friendship.user_id==other.id)&
         (Friendship.friend_id==me.id))
    ).all()
    for r in rels:
        db.session.delete(r)
    db.session.commit()
    return jsonify(success=True,
                   message=f'{other.username}님이 삭제되었습니다.')

# ─── 편지쓰기 ───
@app.route('/letter/<int:receiver_id>', methods=['GET','POST'])
@login_required
def write_letter(receiver_id):
    receiver = User.query.get_or_404(receiver_id)
    if request.method == 'POST':
        msg         = request.form['message'].strip()
        color       = request.form['color']
        # 전달받은 값은 '1' 또는 '0' 문자열로 전송됨
        is_public   = bool(int(request.form['is_public']))
        is_anon     = bool(int(request.form['is_anonymous']))

        new_letter = LetterBlock(
            sender_id=current_user.id,
            receiver_id=receiver_id,
            message=msg,
            color=color,
            is_public=is_public,
            is_anonymous=is_anon
        )
        db.session.add(new_letter)
        db.session.commit()
        flash('편지가 전송되었습니다!', 'success')
        return redirect(url_for('profile', user_id=receiver_id))

    # 편지 작성 화면은 필요한 추가 데이터(예: 색상 팔레트 등)가 있을 경우 함께 전달
    return render_template('write_letter.html', receiver=receiver)

# 🔥 비회원/회원 모두 접근 가능한 새 편지 작성 라우트
@app.route('/write_letter/<username>', methods=['GET', 'POST'])
def write_letter_page(username):
    receiver = User.query.filter_by(username=username).first_or_404()

    if request.method == 'POST':
        msg = request.form['message'].strip()
        color = request.form.get('color', '#D9D9D9')
        is_anon = True

        if not msg:
            flash('내용을 입력해주세요!', 'danger')
            return redirect(request.url)

        new_letter = LetterBlock(
            sender_id=current_user.id if current_user.is_authenticated else None,
            receiver_id=receiver.id,
            message=msg,
            color=color,
            is_public=False,
            is_anonymous=is_anon
        )
        db.session.add(new_letter)
        db.session.commit()

        flash('편지가 전송되었습니다!', 'success')
        return redirect(url_for('public_profile', username=receiver.username))

    return render_template('write_letter.html', receiver=receiver)


# ─── 편지 상세 보기 ───
@app.route('/letter_detail/<int:letter_id>', methods=['GET', 'POST'])
@login_required
def letter_detail(letter_id):
    letter = LetterBlock.query.get_or_404(letter_id)

    # 접근 권한 확인
    if not (current_user.id in [letter.receiver_id, letter.sender_id] or letter.is_public):
        flash('권한이 없습니다.', 'danger')
        return redirect(url_for('profile', user_id=current_user.id))

    # 읽음 처리
    if current_user.id == letter.receiver_id and not letter.is_read:
        letter.is_read = True
        db.session.commit()

    # ✏️ 댓글 작성 처리
    if request.method == 'POST' and current_user.id == letter.receiver_id and not letter.comment:
        comment = request.form.get('comment', '').strip()
        if comment:
            letter.comment = comment
            db.session.commit()
            flash('댓글이 등록되었습니다!', 'success')
            return redirect(url_for('letter_detail', letter_id=letter.id))

    return render_template('letter_detail.html', letter=letter)


# ─── 편지 공개/비공개 전환 (수신자 전용) ───
@app.route('/toggle_letter_visibility/<int:letter_id>', methods=['POST'])
@login_required
def toggle_letter_visibility(letter_id):
    letter = LetterBlock.query.get_or_404(letter_id)
    if current_user.id != letter.receiver_id:
        flash('권한이 없습니다.', 'danger')
        return redirect(url_for('letter_detail', letter_id=letter_id))

    letter.is_public = not letter.is_public
    db.session.commit()
    flash('편지의 공개 설정이 변경되었습니다.', 'success')
    return redirect(url_for('letter_detail', letter_id=letter_id))

# ─── 프로필 ───
# ─── 비회원용 공개 프로필 ───
@app.route('/profile/username/<username>')
def public_profile(username):
    user = User.query.filter_by(username=username).first_or_404()

    letters = []
    if current_user.is_authenticated and current_user.id == user.id:
        # 로그인한 본인이 자기 프로필을 볼 때만 편지 목록 보여줌
        letters = LetterBlock.query.filter_by(receiver_id=user.id).order_by(LetterBlock.created_at.desc()).all()

    return render_template('profile.html',
                           user=user,
                           letters=letters,
                           friends=[],  # 친구 목록은 비회원에게는 보여줄 필요 없음 (필요 시 추가 가능)
                           received_questions=[],  # 질문 리스트도 필요 없으면 비워둬
                           today_visits=0)  # 방문자 수도 생략하거나 0으로


@app.route('/profile/<int:user_id>', methods=['GET','POST'])
@login_required
def profile(user_id):
    user = User.query.get_or_404(user_id)

    print(f"[user.avatar_filename] {user.avatar_filename}")
    print(f"[user.avatar_color] {user.avatar_color}")

    # 받은 질문
    received_questions = Question.query.filter_by(friend_id=user_id).all()
    # 친구 목록
    friends = User.query.join(
        Friendship, User.id==Friendship.friend_id
    ).filter(
        Friendship.user_id==user.id,
        Friendship.status == 'accepted'  # ✅ 수락된 친구만 필터링
    ).all()
    
    # 편지: 받은 편지는 무조건 전부 보여줘야 하니까
    letters = LetterBlock.query.filter_by(receiver_id=user_id)\
        .order_by(LetterBlock.created_at.desc()).all()

    # 오늘 방문 기록 (필요 시 처리)
    today_str = datetime.now(timezone.utc).strftime('%Y-%m-%d')
    if user.id != current_user.id:
        already = Visit.query.filter_by(
            profile_user_id=user.id,
            visitor_id=current_user.id
        ).filter(func.strftime('%Y-%m-%d', Visit.timestamp)==today_str).first()
        if not already:
            db.session.add(Visit(profile_user_id=user.id, visitor_id=current_user.id))
            db.session.commit()

    today_visits = Visit.query.filter_by(profile_user_id=user.id)\
        .filter(func.strftime('%Y-%m-%d', Visit.timestamp)==today_str).count()

    # (옵션) 프로필에서 질문 작성 기능 등 추가 가능
    if request.method == 'POST':
        txt = request.form.get('question_text','').strip()
        if txt:
            q = Question(
                question_text=txt,
                user_id=current_user.id,
                friend_id=user_id
            )
            db.session.add(q)
            db.session.commit()
            flash('질문이 등록되었습니다!', 'success')
            return redirect(url_for('profile', user_id=user_id))
        
    for letter in letters:
        print(f"편지 ID: {letter.id}, 공개여부: {letter.is_public}, 익명여부: {letter.is_anonymous}, 읽음: {letter.is_read}")


    return render_template('profile.html',
                           user=user,
                           received_questions=received_questions,
                           friends=friends,
                           letters=letters,

                           today_visits=today_visits)


@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    try:
        user_id = current_user.id

        # 1. 로그아웃 먼저
        logout_user()

        # 2. 관련된 데이터 모두 삭제
        Question.query.filter(
            (Question.user_id == user_id) | (Question.friend_id == user_id)
        ).delete(synchronize_session=False)

        Friendship.query.filter(
            (Friendship.user_id == user_id) | (Friendship.friend_id == user_id)
        ).delete(synchronize_session=False)

        Visit.query.filter(
            (Visit.profile_user_id == user_id) | (Visit.visitor_id == user_id)
        ).delete(synchronize_session=False)

        LetterBlock.query.filter(
            (LetterBlock.sender_id == user_id) | (LetterBlock.receiver_id == user_id)
        ).delete(synchronize_session=False)

        # 3. 마지막으로 사용자 삭제
        user = User.query.get(user_id)
        if user:
            db.session.delete(user)

        db.session.commit()

        # 4. 빈 응답으로 성공 반환
        return '', 200

    except Exception as e:
        db.session.rollback()
        print("회원 탈퇴 중 오류 발생:", e)
        return 'Error', 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()