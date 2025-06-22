from app import db, User, app

if __name__ == "__main__":
    with app.app_context():
        admins = User.query.filter_by(is_admin=True).all()
        if not admins:
            print("Không có tài khoản admin nào trong hệ thống.")
        else:
            print("Danh sách tài khoản admin:")
            for admin in admins:
                print(f"- {admin.username}") 