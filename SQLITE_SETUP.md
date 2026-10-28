# Chạy PTH Control Tower với Node.js và SQLite

Ứng dụng dùng một máy chủ Node.js và một file SQLite duy nhất để lưu tài khoản, dữ liệu sản xuất, file Excel mới nhất và các ghi nhận IPQC. Các trình duyệt truy cập cùng máy chủ; khi dữ liệu thay đổi, máy chủ phát sự kiện SSE để những client đang mở tải trạng thái mới.

## Yêu cầu và khởi chạy

Cài Node.js 22.13 trở lên (có module SQLite tích hợp `node:sqlite`, không cần cờ bật thử nghiệm). Ứng dụng không cần thư viện npm bên ngoài.

```powershell
node --version
node server.js --create-admin admin@congty.com
node server.js
```

Lệnh tạo admin yêu cầu nhập mật khẩu hai lần trong terminal và không hiển thị mật khẩu. Máy chủ mặc định chạy tại `http://127.0.0.1:8000`. Dữ liệu mặc định nằm trong `data/pth-dashboard.sqlite3`; có thể đổi file bằng biến môi trường `PTH_DB_PATH`.

Nếu triển khai mà không có terminal tương tác, có thể khởi tạo admin lần đầu qua `POST /api/setup-admin` bằng cách cấu hình `PTH_ADMIN_SETUP_TOKEN` có ít nhất 32 ký tự ngẫu nhiên trong môi trường server. Gửi JSON gồm `setupToken`, `email` và mật khẩu riêng do bạn chọn. API chỉ hoạt động khi database chưa có admin, tạo tài khoản được duyệt với quyền admin, rồi khóa vĩnh viễn sau lần tạo thành công. Gỡ `PTH_ADMIN_SETUP_TOKEN` khỏi cấu hình môi trường ngay sau đó. Không dùng chung mật khẩu mặc định trong mã nguồn và không gửi secret qua URL hoặc log.

Để các máy tính khác trong mạng truy cập, chạy máy chủ trên một máy chủ nội bộ hoặc VPS:

```powershell
node server.js --host 0.0.0.0 --port 8000
```

Chỉ cho phép truy cập qua HTTPS khi đưa lên mạng công ty/VPS. Có thể chạy sau HTTPS reverse proxy và đặt `PTH_COOKIE_SECURE=1`, hoặc cung cấp chứng chỉ trực tiếp:

```powershell
node server.js --host 0.0.0.0 --port 8443 --certfile duong-dan-chung-chi.pem --keyfile duong-dan-private-key.pem
```

Không mở HTTP công khai vì kết nối đăng nhập và dữ liệu sẽ không được mã hóa.

## Tài khoản và đồng bộ

- Người dùng đăng ký bằng email và mật khẩu dài ít nhất 10 ký tự.
- Tài khoản mới cần quản trị viên duyệt trước khi đọc hoặc cập nhật dữ liệu chung.
- Admin đăng nhập rồi chọn **Quản lý tài khoản** để duyệt hoặc thu hồi quyền.
- Thu hồi quyền sẽ xóa các phiên đăng nhập đang hoạt động; không thể thu hồi admin cuối cùng.
- File Excel đồng bộ có giới hạn 5 MB.

Ứng dụng tự tạo schema nếu database chưa có. Khi nâng cấp từ phiên bản trước, `server.js` tiếp tục sử dụng cùng đường dẫn `data/pth-dashboard.sqlite3` và schema tương thích; không xóa hoặc tạo lại file database hiện tại. Nên sao lưu database trước khi nâng cấp. Khi server đang chạy với WAL, dừng server trước khi sao chép file hoặc dùng công cụ SQLite backup.

## Kiểm thử

```powershell
npm test
```

## Giới hạn triển khai

Chạy một bản server ứng dụng ghi vào database SQLite đó; không chia sẻ file database qua ổ mạng hoặc giữa nhiều máy chủ. Với tải ghi lớn hay nhiều bản ứng dụng, chuyển backend sang cơ sở dữ liệu server như PostgreSQL.
