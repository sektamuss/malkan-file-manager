import os
import json
import shutil
import uuid
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import (Flask, render_template, request, redirect, url_for, flash, send_from_directory)
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)

# --- UYGULAMA YAPILANDIRMASI ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'bu-anahtari-mutlaka-degistirin-12345'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['USERS_FILE'] = 'users.json'
app.config['VIEWABLE_EXTENSIONS'] = {'.jpg', '.jpeg', '.png', '.gif', '.pdf', '.txt', '.xml', '.html', '.css', '.js'}
app.config['FOLDER_METADATA_FILE'] = 'folder_metadata.json'
app.config['ICON_UPLOAD_FOLDER'] = 'static/folder_icons'
app.config['ALLOWED_ICON_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

# --- FLASK-LOGIN YAPILANDIRMASI ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Bu sayfayı görüntülemek için lütfen giriş yapın."
login_manager.login_message_category = "info"

# --- YARDIMCI FONKSİYONLAR ---
def get_users():
    if not os.path.exists(app.config['USERS_FILE']):
        admin_pass_hash = generate_password_hash('admin123', method='pbkdf2:sha256')
        users = {"admin": {"password": admin_pass_hash, "role": "admin", "permissions": ["*"]}}
        with open(app.config['USERS_FILE'], 'w') as f: json.dump(users, f, indent=4)
        return users
    with open(app.config['USERS_FILE'], 'r') as f: return json.load(f)

def save_users(users):
    with open(app.config['USERS_FILE'], 'w') as f: json.dump(users, f, indent=4)

def get_folder_metadata():
    if not os.path.exists(app.config['FOLDER_METADATA_FILE']): return {}
    try:
        with open(app.config['FOLDER_METADATA_FILE'], 'r') as f: return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError): return {}

def save_folder_metadata(metadata):
    with open(app.config['FOLDER_METADATA_FILE'], 'w') as f: json.dump(metadata, f, indent=4)

def allowed_icon_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_ICON_EXTENSIONS']

def secure_path(path):
    path = path.replace('\\', '/')
    base_dir = os.path.abspath(app.config['UPLOAD_FOLDER'])
    requested_path = os.path.abspath(os.path.join(base_dir, path))
    if os.path.commonprefix([requested_path, base_dir]) != base_dir: return None
    return requested_path

def get_all_directories(path_to_walk, parent_path=''):
    dir_list = []
    try:
        for item in os.listdir(path_to_walk):
            full_path = os.path.join(path_to_walk, item)
            relative_path = f"{parent_path}/{item}" if parent_path else item
            if os.path.isdir(full_path):
                dir_list.append(relative_path)
                dir_list.extend(get_all_directories(full_path, relative_path))
    except FileNotFoundError:
        pass
    return dir_list

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['ICON_UPLOAD_FOLDER'], exist_ok=True)

# --- KULLANICI MODELİ ve YETKİLENDİRME ---
class User(UserMixin):
    def __init__(self, id, role, permissions):
        self.id = id
        self.role = role
        self.permissions = permissions

@login_manager.user_loader
def load_user(user_id):
    users = get_users()
    if user_id in users:
        user_data = users[user_id]
        # ÖNCEKİ HATANIN DÜZELTİLDİĞİ, DOĞRU KULLANICI YÜKLEME KODU
        return User(
            id=user_id,
            role=user_data.get('role'),
            permissions=user_data.get('permissions', [])
        )
    return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("Bu sayfaya erişim yetkiniz yok.", "danger")
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# --- ANA ROUTE'LAR (SAYFALAR) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        users = get_users()
        user_data = users.get(username)
        if user_data and check_password_hash(user_data['password'], password):
            user_obj = User(
                id=username,
                role=user_data.get('role'),
                permissions=user_data.get('permissions', [])
            )
            login_user(user_obj)
            return redirect(url_for('index'))
        else:
            flash('Geçersiz kullanıcı adı veya şifre.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Başarıyla çıkış yaptınız.', 'success')
    return redirect(url_for('login'))

@app.route('/')
@app.route('/files/')
@app.route('/files/<path:path>')
@login_required
def index(path="."):
    path = path.replace('\\', '/')
    current_path_str = path.strip('/') if path != "." else "."
    abs_path = secure_path(current_path_str)
    if abs_path is None or not os.path.isdir(abs_path):
        flash("Geçersiz veya bulunamayan dizin.", "danger"); return redirect(url_for('index'))
    breadcrumbs = []
    if current_path_str != '.':
        parts = current_path_str.split('/')
        for i, part in enumerate(parts):
            breadcrumbs.append({'name': part, 'path': '/'.join(parts[:i+1])})
    dir_items = os.listdir(abs_path)
    allowed_items = []
    if current_user.role == 'user':
        if current_path_str != '.' and not any(current_path_str.startswith(p) for p in current_user.permissions):
             flash("Bu dizine erişim izniniz yok.", "danger"); return redirect(url_for('index'))
        if current_path_str == '.':
            allowed_items = [item for item in dir_items if os.path.isdir(os.path.join(abs_path, item)) and item in current_user.permissions]
        else: allowed_items = dir_items
    else: allowed_items = dir_items
    folder_metadata = get_folder_metadata()
    items = []
    for name in sorted(allowed_items, key=lambda x: (os.path.isfile(os.path.join(abs_path, x)), x.lower())):
        item_rel_path = f"{current_path_str}/{name}" if current_path_str != '.' else name
        is_dir = os.path.isdir(os.path.join(abs_path, name))
        item_data = {'name': name, 'path': item_rel_path, 'is_dir': is_dir}
        if is_dir and item_rel_path in folder_metadata:
            icon_filename = folder_metadata[item_rel_path].get('icon')
            if icon_filename:
                item_data['custom_icon_url'] = url_for('static', filename=f'folder_icons/{icon_filename}')
        items.append(item_data)
    all_directories = get_all_directories(app.config['UPLOAD_FOLDER'])
    return render_template('index.html', items=items, current_path=current_path_str, breadcrumbs=breadcrumbs, all_directories=all_directories)

@app.route('/download/<path:path>')
@login_required
def download_file(path):
    abs_path = secure_path(path)
    if abs_path is None or not os.path.isfile(abs_path):
        flash("Dosya bulunamadı.", "danger"); return redirect(url_for('index'))
    if current_user.role == 'user':
        dir_name = os.path.dirname(path.replace('\\', '/'))
        if dir_name != '.' and not any(dir_name.startswith(p) for p in current_user.permissions):
            flash("Bu dosyayı indirme yetkiniz yok.", "danger"); return redirect(url_for('index'))
    filename = os.path.basename(abs_path)
    _, extension = os.path.splitext(filename)
    as_attachment = extension.lower() not in app.config['VIEWABLE_EXTENSIONS']
    return send_from_directory(os.path.dirname(abs_path), filename, as_attachment=as_attachment)

# --- ADMİN ROUTE'LARI ---
@app.route('/admin')
@login_required
@admin_required
def admin_panel():
    users_data = get_users()
    users_list = {u: d for u, d in users_data.items() if u != 'admin'}
    top_level_folders = [d for d in os.listdir(app.config['UPLOAD_FOLDER']) if os.path.isdir(os.path.join(app.config['UPLOAD_FOLDER'], d))]
    return render_template('admin.html', users=users_list, folders=top_level_folders)

@app.route('/admin/add_user', methods=['POST'])
@login_required
@admin_required
def add_user():
    username, password = request.form.get('username'), request.form.get('password')
    if not username or not password:
        flash('Kullanıcı adı ve şifre gereklidir.', 'danger'); return redirect(url_for('admin_panel'))
    users = get_users()
    if username in users:
        flash('Bu kullanıcı adı zaten mevcut.', 'danger'); return redirect(url_for('admin_panel'))
    users[username] = {'password': generate_password_hash(password, method='pbkdf2:sha256'), 'role': 'user', 'permissions': []}
    save_users(users)
    flash(f'"{username}" kullanıcısı başarıyla oluşturuldu.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_user/<username>', methods=['POST'])
@login_required
@admin_required
def delete_user(username):
    if username == 'admin': flash('Admin kullanıcısı silinemez.', 'danger')
    else:
        users = get_users()
        if username in users:
            users.pop(username); save_users(users)
            flash(f'"{username}" kullanıcısı silindi.', 'success')
        else: flash('Kullanıcı bulunamadı.', 'warning')
    return redirect(url_for('admin_panel'))

@app.route('/admin/assign_permission', methods=['POST'])
@login_required
@admin_required
def assign_permission():
    username, permissions = request.form.get('username'), request.form.getlist('permissions')
    users = get_users()
    if username in users and users[username]['role'] == 'user':
        users[username]['permissions'] = permissions; save_users(users)
        flash(f'"{username}" kullanıcısının izinleri güncellendi.', 'success')
    else: flash('İzinler güncellenirken bir hata oluştu.', 'danger')
    return redirect(url_for('admin_panel'))

# --- DOSYA/KLASÖR İŞLEM ROUTE'LARI ---
@app.route('/upload', methods=['POST'])
@login_required
@admin_required
def upload_file():
    destination_folder = request.form.get('destination_folder', '.')
    redirect_url = url_for('index', path=destination_folder if destination_folder != '.' else None)
    if 'file' not in request.files or request.files['file'].filename == '':
        flash('Yüklenecek dosya seçilmedi.', 'danger'); return redirect(redirect_url)
    file = request.files['file']
    filename = secure_filename(file.filename)
    upload_path = secure_path(destination_folder)
    if upload_path:
        file.save(os.path.join(upload_path, filename))
        flash(f'"{filename}" dosyası "{destination_folder}" klasörüne başarıyla yüklendi.', 'success')
    else: flash("Geçersiz hedef klasör seçimi.", "danger")
    return redirect(redirect_url)

@app.route('/create_folder', methods=['POST'])
@login_required
@admin_required
def create_folder():
    current_path_str = request.form.get('current_path', '.')
    folder_name = request.form.get('folder_name')
    icon_file = request.files.get('folder_icon')
    redirect_url = url_for('index', path=current_path_str if current_path_str != '.' else None)
    if not folder_name:
        flash('Klasör adı boş olamaz.', 'danger'); return redirect(redirect_url)
    folder_name = secure_filename(folder_name)
    new_folder_rel_path = f"{current_path_str}/{folder_name}" if current_path_str != '.' else folder_name
    path_to_create = secure_path(new_folder_rel_path)
    if path_to_create and not os.path.exists(path_to_create):
        os.makedirs(path_to_create)
        flash(f'"{folder_name}" klasörü oluşturuldu.', 'success')
        if icon_file and icon_file.filename != '' and allowed_icon_file(icon_file.filename):
            metadata = get_folder_metadata()
            filename = f"{uuid.uuid4().hex}_{secure_filename(icon_file.filename)}"
            icon_file.save(os.path.join(app.config['ICON_UPLOAD_FOLDER'], filename))
            metadata[new_folder_rel_path] = {'icon': filename}
            save_folder_metadata(metadata)
            flash('Klasör ikonu başarıyla yüklendi.', 'success')
    else:
        flash(f'Klasör oluşturulamadı veya zaten mevcut.', 'danger')
    return redirect(redirect_url)

@app.route('/delete', methods=['POST'])
@login_required
@admin_required
def delete_item():
    item_path_str = request.form.get('item_path')
    parent_dir = os.path.dirname(item_path_str.replace('\\', '/')) if os.path.dirname(item_path_str) else '.'
    redirect_url = url_for('index', path=parent_dir if parent_dir != '.' else None)
    abs_path = secure_path(item_path_str)
    if not abs_path:
        flash('Geçersiz yol.', 'danger'); return redirect(url_for('index'))
    is_dir = os.path.isdir(abs_path)
    try:
        item_name = os.path.basename(abs_path)
        if is_dir: shutil.rmtree(abs_path)
        else: os.remove(abs_path)
        flash(f'"{item_name}" silindi.', 'success')
        if is_dir:
            metadata = get_folder_metadata()
            keys_to_delete = [key for key in metadata if key == item_path_str or key.startswith(item_path_str + '/')]
            if keys_to_delete:
                for key in keys_to_delete:
                    icon_to_delete = metadata[key].get('icon')
                    if icon_to_delete:
                        try: os.remove(os.path.join(app.config['ICON_UPLOAD_FOLDER'], icon_to_delete))
                        except OSError: pass
                    del metadata[key]
                save_folder_metadata(metadata)
                flash('Klasör metadatası temizlendi.', 'info')
    except Exception as e: flash(f'Hata oluştu: {e}', 'danger')
    return redirect(redirect_url)

@app.route('/rename', methods=['POST'])
@login_required
@admin_required
def rename_item():
    old_path_str, new_name = request.form.get('current_path'), request.form.get('new_name')
    parent_dir = os.path.dirname(old_path_str.replace('\\', '/')) if os.path.dirname(old_path_str) else '.'
    redirect_url = url_for('index', path=parent_dir if parent_dir != '.' else None)
    if not new_name:
        flash('Yeni isim boş olamaz.', 'danger'); return redirect(redirect_url)
    old_abs_path = secure_path(old_path_str)
    if not old_abs_path:
        flash('Geçersiz yol.', 'danger'); return redirect(redirect_url)
    is_dir = os.path.isdir(old_abs_path)
    if not is_dir:
        _, ext = os.path.splitext(os.path.basename(old_abs_path))
        new_name_base, new_ext = os.path.splitext(new_name)
        if not new_ext: new_name += ext
    new_name = secure_filename(new_name)
    new_abs_path = os.path.join(os.path.dirname(old_abs_path), new_name)
    if not os.path.exists(new_abs_path):
        os.rename(old_abs_path, new_abs_path)
        flash('Başarıyla yeniden adlandırıldı.', 'success')
        if is_dir:
            metadata = get_folder_metadata()
            new_rel_path = os.path.join(parent_dir, new_name).replace('\\', '/')
            keys_to_update = {key: val for key, val in metadata.items() if key == old_path_str or key.startswith(old_path_str + '/')}
            if keys_to_update:
                for old_key, val in keys_to_update.items():
                    del metadata[old_key]
                    new_key = old_key.replace(old_path_str, new_rel_path, 1)
                    metadata[new_key] = val
                save_folder_metadata(metadata)
                flash('Klasör metadatası güncellendi.', 'info')
    else:
        flash('Yeniden adlandırılamadı veya yeni isim zaten kullanılıyor.', 'danger')
    return redirect(redirect_url)

@app.route('/operate_item', methods=['POST'])
@login_required
@admin_required
def operate_item():
    action, source_path_str, dest_folder_str = request.form.get('action'), request.form.get('source_path'), request.form.get('destination_folder')
    redirect_url = url_for('index', path=dest_folder_str if dest_folder_str != '.' else None)
    if not all([action, source_path_str, dest_folder_str]):
        flash('Eksik bilgi: İşlem yapılamadı.', 'danger'); return redirect(url_for('index'))
    source_abs_path, dest_abs_path = secure_path(source_path_str), secure_path(dest_folder_str)
    if not source_abs_path or not dest_abs_path or not os.path.exists(source_abs_path):
        flash('Kaynak veya hedef yolu geçersiz.', 'danger'); return redirect(url_for('index'))
    is_dir = os.path.isdir(source_abs_path)
    item_name = os.path.basename(source_abs_path)
    final_dest_path = os.path.join(dest_abs_path, item_name)
    if source_abs_path == final_dest_path:
        parent_dir = os.path.dirname(source_path_str.replace('\\','/'))
        flash('Kaynak ve hedef aynı olamaz.', 'warning'); return redirect(url_for('index', path=parent_dir if parent_dir else None))
    if os.path.exists(final_dest_path):
        flash(f'"{item_name}" hedef klasörde zaten mevcut. İşlem iptal edildi.', 'danger'); return redirect(redirect_url)
    if is_dir and dest_abs_path.startswith(source_abs_path):
        flash('Bir klasörü kendi alt dizinine taşıyamaz veya kopyalayamazsınız.', 'danger'); return redirect(redirect_url)
    try:
        if action == 'move':
            shutil.move(source_abs_path, final_dest_path)
            flash(f'"{item_name}" başarıyla "{dest_folder_str}" klasörüne taşındı.', 'success')
        elif action == 'copy':
            if is_dir: shutil.copytree(source_abs_path, final_dest_path)
            else: shutil.copy2(source_abs_path, final_dest_path)
            flash(f'"{item_name}" başarıyla "{dest_folder_str}" klasörüne kopyalandı.', 'success')
        if is_dir:
            metadata = get_folder_metadata()
            new_rel_path = os.path.join(dest_folder_str, item_name).replace('\\', '/')
            keys_to_process = {key: val for key, val in metadata.items() if key == source_path_str or key.startswith(source_path_str + '/')}
            if keys_to_process:
                for old_key, val in keys_to_process.items():
                    if action == 'move': del metadata[old_key]
                    new_key = old_key.replace(source_path_str, new_rel_path, 1)
                    metadata[new_key] = val
                save_folder_metadata(metadata)
                flash('Klasör metadatası güncellendi.', 'info')
    except Exception as e:
        flash(f'İşlem sırasında bir hata oluştu: {e}', 'danger')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)