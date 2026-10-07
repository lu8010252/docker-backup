#!/bin/sh
# ===== 自包含还原脚本: 不依赖 docker-backup 网页,也不依赖 1Panel =====
# 需要: root 权限、docker、GNU tar。
# 用法: sh restore.sh [--map 旧路径=新路径 ...] [--no-images] [--no-data]
#   --map 可重复,每个目录单独指定,例:
#   sh restore.sh --map /opt/1panel/apps/typecho=/vol1/docker/typecho \
#                 --map /opt/1panel/docker/compose/typecho=/vol1/docker/typecho/compose
#   规则里的路径彼此不要互相包含; compose 文件和 .env 里的旧路径会一并替换。
# 注意: 同级目录里 CHAIN 列出的其它时间戳目录必须保留(先完整备份、后增量,依次解压)。
set -e
cd "$(dirname "$0")"
NAME=@@NAME@@
CHAIN="@@CHAIN@@"
BASE=@@BASE@@
WORKDIR=@@WORKDIR@@
MAPS=
while [ $# -gt 0 ]; do
  case "$1" in
    --map) MAPS="$MAPS
$2"; shift 2 ;;
    --no-images) NO_IMAGES=1; shift ;;
    --no-data) NO_DATA=1; shift ;;
    *) echo "未知参数 $1"; exit 1 ;;
  esac
done

# 路径前缀映射: 第一条匹配的规则生效(网页会把长的规则排前面)
map() {
  p="$1"
  while IFS='=' read -r o n; do
    if [ -n "$o" ]; then
      case "$p" in
        "$o"|"$o"/*) printf '%s%s' "$n" "${p#"$o"}"; return 0 ;;
      esac
    fi
  done <<EOM
$MAPS
EOM
  printf '%s' "$p"
}
mapsed() {
  while IFS='=' read -r o n; do
    if [ -n "$o" ]; then printf 's#%s#%s#g\n' "$o" "$n"; fi
  done <<EOM
$MAPS
EOM
}
SEDS=$(mapsed)
untar() {
  f="$1"; set --
  while IFS='=' read -r o n; do
    if [ -n "$o" ]; then set -- "$@" --transform "s,^${o#/},${n#/},"; fi
  done <<EOM
$MAPS
EOM
  tar -xzpf "$f" -C / "$@"
}

for c in @@CONTAINERS@@; do docker stop "$c" >/dev/null 2>&1 || true; done
for n in @@NETS@@; do docker network inspect "$n" >/dev/null 2>&1 || docker network create "$n" >/dev/null; done

if [ -z "$NO_IMAGES" ] && [ -f "../$BASE/images.tar" ]; then
  A=$(docker version --format '{{.Server.Arch}}' 2>/dev/null || true)
  if [ -n "$A" ] && [ -n "@@ARCH@@" ] && [ "$A" != "@@ARCH@@" ]; then
    echo "CPU 架构不同(备份 @@ARCH@@ / 当前 $A),跳过镜像加载,启动时会从仓库拉取"
  else
    docker load -i "../$BASE/images.tar"
  fi
fi

if [ -z "$NO_DATA" ]; then
  tar --version 2>/dev/null | grep -q GNU || echo "警告: 未检测到 GNU tar, busybox tar 可能无法正确解压增量包"
  for t in $CHAIN; do
    if [ -f "../$t/data.tar.gz" ]; then echo "解压 $t"; untar "../$t/data.tar.gz"; fi
  done
fi

if [ "@@COMPOSE@@" = 1 ]; then
  WD=$(map "$WORKDIR")
  if [ -n "$SEDS" ]; then
    find "$WD" -maxdepth 3 \( -name '*.yml' -o -name '*.yaml' -o -name '.env' \) -exec sed -i "$SEDS" {} +
  fi
  cd "$WD"
  set --
  for f in @@FILES@@; do set -- "$@" -f "$(map "$f")"; done
  if docker compose version >/dev/null 2>&1; then DC="docker compose"; else DC="docker-compose"; fi
  $DC -p "$NAME" "$@" up -d
else
  if [ -n "$SEDS" ]; then sed "$SEDS" containers.sh | sh; else sh containers.sh; fi
fi
echo "还原完成: $NAME"
