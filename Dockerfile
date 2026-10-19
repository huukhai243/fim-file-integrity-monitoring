# FIM Project - image chạy trên Linux (Debian) để dùng được inotify và quyền Unix (chmod, setuid)
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=Asia/Ho_Chi_Minh

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY fim ./fim
COPY tools ./tools
COPY tests ./tests
COPY main.py config.json config.linux.json ./
COPY test_folder ./test_folder

EXPOSE 5000
CMD ["python", "main.py", "monitor"]
