FROM python:3.12-alpine
RUN apk add --no-cache docker-cli docker-cli-compose tar tzdata util-linux \
 && pip install --no-cache-dir flask gunicorn
WORKDIR /app
COPY app.py restore.sh.tpl ./
COPY static static
ENV DATA_DIR=/config
EXPOSE 8800
# 任务状态保存在进程内,必须单 worker
CMD ["gunicorn","-b","0.0.0.0:8800","-w","1","--threads","8","--timeout","0","app:app"]
