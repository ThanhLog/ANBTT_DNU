# Ứng dụng Quản lý Người dùng Bảo mật với SHA & Triple DES

## Đề tài 21: Ứng dụng SHA và Triple DES để bảo vệ mật khẩu người dùng trong cơ sở dữ liệu

---

## Mục lục
- [Giới thiệu](#giới-thiệu)
- [Tính năng](#tính-năng)
- [Cài đặt & Chạy thử](#cài-đặt--chạy-thử)
- [Cấu trúc thư mục](#cấu-trúc-thư-mục)
- [Công nghệ sử dụng](#công-nghệ-sử-dụng)
- [Hướng dẫn sử dụng](#hướng-dẫn-sử-dụng)
- [Ghi chú bảo mật](#ghi-chú-bảo-mật)
- [Tác giả](#tác-giả)

---

## Giới thiệu
Đây là ứng dụng web quản lý người dùng, sử dụng Flask (Python) với bảo mật mật khẩu bằng SHA-256 kết hợp mã hóa Triple DES (3DES). Giao diện hoàn toàn bằng tiếng Việt, thân thiện với người dùng và quản trị viên.

---

## Tính năng
- Đăng ký, đăng nhập, đổi mật khẩu, đăng xuất.
- Bảo vệ mật khẩu bằng SHA-256 + Triple DES.
- Quản trị viên:
  - Quản lý tài khoản người dùng (mở khóa, xóa, đặt lại mật khẩu, đổi quyền).
  - Xem nhật ký đăng nhập, thống kê hệ thống, cấu hình bảo mật.
- Giao diện tiếng Việt, thông báo rõ ràng.
- Lưu trữ dữ liệu bằng SQLite.

---

## Cài đặt & Chạy thử

### 1. Yêu cầu
- Python 3.8+
- pip

### 2. Cài đặt thư viện
```bash
pip install flask flask_sqlalchemy pycryptodome
```

### 3. Chạy ứng dụng
```bash
python app.py
```
- Truy cập: [http://localhost:5000](http://localhost:5000)

### 4. Tài khoản mặc định
- Tài khoản admin đầu tiên sẽ được tạo tự động:
  - **Tên đăng nhập:** `admin`
  - **Mật khẩu:** `admin`

---

## Cấu trúc thư mục
```
.
├── app.py
├── rsa_secure_file.py
├── users.db
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── register.html
│   ├── dashboard.html
│   ├── change_password.html
│   └── admin/
│       ├── dashboard.html
│       ├── logs.html
│       ├── statistics.html
│       └── settings.html
├── 3des.key
├── config.json
└── ...
```

---

## Công nghệ sử dụng
- **Flask**: Web framework Python.
- **Flask-SQLAlchemy**: ORM cho SQLite.
- **PyCryptodome**: Thư viện mã hóa (SHA, Triple DES).
- **Bootstrap, TailwindCSS**: Giao diện hiện đại, responsive.

---

## Hướng dẫn sử dụng
- **Đăng ký**: Tạo tài khoản mới.
- **Đăng nhập**: Sử dụng tên đăng nhập và mật khẩu đã đăng ký.
- **Đổi mật khẩu**: Vào mục "Đổi mật khẩu" sau khi đăng nhập.
- **Quản trị viên**: Truy cập bảng điều khiển để quản lý user, xem nhật ký, thống kê, cài đặt bảo mật.
- **Cấu hình bảo mật**: Vào "Cài đặt" để thay đổi số lần nhập sai tối đa, sinh lại khóa 3DES (cảnh báo: sinh lại khóa sẽ làm mất hiệu lực mật khẩu cũ).

---

## Ghi chú bảo mật
- **Mật khẩu** được băm SHA-256 và mã hóa bằng Triple DES trước khi lưu vào cơ sở dữ liệu.
- **Khóa 3DES** được lưu trong file `3des.key`. Nếu đổi khóa, tất cả mật khẩu cũ sẽ không xác thực được.
- **Số lần nhập sai tối đa** có thể cấu hình trong mục Cài đặt.

---

## Tác giả
- **Tên:** [Điền tên của bạn]
- **Email:** [Điền email của bạn]
- **GitHub:** [https://github.com/ThanhLog/ANBTT_DNU](https://github.com/ThanhLog/ANBTT_DNU) 