# 多阶段构建：第一阶段 - 构建阶段
# 使用 1Panel 镜像源的 golang 镜像
FROM docker.1panel.live/library/golang:1.21-alpine AS builder
# 设置容器内的工作目录
WORKDIR /app
# 将当前目录下的所有文件复制到容器的工作目录
COPY . .
# 编译 Go 程序，生成名为 jwt-server 的可执行文件
RUN go build -o jwt-server

# 多阶段构建：第二阶段 - 运行阶段
# 使用 1Panel 镜像源的 alpine 镜像
FROM docker.1panel.live/library/alpine:latest
# 设置容器的工作目录
WORKDIR /app
# 从 builder 阶段复制编译好的可执行文件到当前阶段
COPY --from=builder /app/jwt-server .
# 复制私钥文件到容器中
COPY private_key.pem .

# 声明容器将要监听的端口
EXPOSE 8080
# 容器启动时执行的命令
CMD ["./jwt-server"]