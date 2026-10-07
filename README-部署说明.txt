应用: docker-backup    导出时间: 2026-10-07 08:31:46

这是「源文件包」: 只含 compose / .env / Dockerfile / 配置 / 代码,不含任何数据,可以直接分享。

【怎么部署】
1. 解压到目标机器的一个专属文件夹里。
2. 打开下面「已脱敏」列出的文件,把 CHANGE_ME 改成你自己的值(账号/密码/令牌等)。
3. compose 里如果有 /opt/... 之类的绝对路径,改成你自己机器上的路径。
4. 在该文件夹里运行: docker compose up -d --build

【用到的镜像】(没有 Dockerfile 的会自动拉取)
  docker-backup-docker-backup

【已脱敏的变量】(只列变量名,值已换成 CHANGE_ME)
  docker-compose.yml: AUTH_PASS, AUTH_USER, NOTIFY_URL

【没有打进来的数据】(对方需要自己准备,或留空让程序首次运行时自己创建)
  目录: /opt/1panel/apps/docker-backup/config

提醒: 只对 .env / compose 文件和 docker-run.sh 做了脱敏,其它配置文件(config.json、*.conf 等)里
如果写了密码或密钥,分享前请自己再检查一遍。
