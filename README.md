# vergeauth

[![CI](https://github.com/yeads/vergeauth/actions/workflows/ci.yml/badge.svg)](https://github.com/yeads/vergeauth/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![C99](https://img.shields.io/badge/C-C99-blue.svg)
[![CMake 3.16+](https://img.shields.io/badge/CMake-%3E%3D%203.16-064F8C?logo=cmake)](https://cmake.org/)

Clash Verge 的前置鉴权代理，使用 C99、libevent 和 llhttp，单线程运行。同一端口支持 HTTP Basic 代理鉴权和 SOCKS5 用户名密码鉴权，认证后统一连接 HTTP 上游。HTTP CONNECT 与 SOCKS5 CONNECT 均通过上游 HTTP CONNECT 建立 TCP 隧道，可代理 HTTPS。

HTTP 鉴权失败返回 `407 Proxy Authentication Required`；SOCKS5 未提供用户名密码认证方法时返回 `05 ff`，用户名密码错误时返回 `01 01`。普通 HTTP 请求每个连接处理一次，并发送 `Connection: close`；CONNECT 隧道持续转发。SOCKS5 支持 IPv4、域名、IPv6 目标，不支持 BIND 和 UDP ASSOCIATE；普通 HTTP 不支持 Upgrade，可使用 CONNECT 隧道。

## 构建

需要 Linux 或其他提供 POSIX 接口的系统、C99 编译器、CMake 3.16 及以上、pkg-config 和 libevent 2.1 及以上开发包。llhttp 源码已包含在项目中，构建时无需下载。

Debian / Ubuntu 安装依赖并构建：

```sh
sudo apt install build-essential cmake pkg-config libevent-dev python3
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Python 3 仅用于集成测试；不运行测试时，可在配置 CMake 时加入 `-DBUILD_TESTING=OFF`。

GitHub Actions 在推送、Pull Request 和手动触发时运行 CI：使用 Ubuntu 24.04 分别进行 GCC、Clang 的 Release 构建，以及启用 AddressSanitizer / UndefinedBehaviorSanitizer 的 Clang Debug 构建。每组构建均通过 CTest 运行协议、命令行和本地 TCP 集成测试。

可选安装：

```sh
sudo cmake --install build
```

## 配置

默认读取 `$HOME/.vergeauth`，也可以使用 `-f <path>` 指定文件。

```conf
listen 7898
upstream 127.0.0.1:7897
user alice change-me
user bob "another password"
```

- `listen <port>`：监听端口，范围为 1–65535，绑定所有 IPv4 网络接口。
- `upstream <address>`：Clash Verge 的 HTTP 或 mixed 代理地址，支持 `host:port`、`[IPv6]:port`，以及可选的 `http://` 前缀，必须写明端口。
- `user <user> <password>`：可配置多个用户，用户名不可重复。用户名、密码各为 1–255 字节，用户名不可包含冒号；支持单双引号与反斜杠转义。

支持空行和以 `#` 开始的注释，也可在参数后的空白处添加注释。没有 `user` 时拒绝所有认证。前置代理的凭据不会转发给上游；上游应配置为无需鉴权的 HTTP 代理。HTTP Basic 与 SOCKS5 用户名密码认证本身不加密，监听端口应仅向可信网络开放。

```sh
cp vergeauth.conf.example "$HOME/.vergeauth"
chmod 600 "$HOME/.vergeauth"
# 修改配置中的用户密码和 Clash Verge 端口后启动。
```

## 运行

前台运行：

```sh
./build/vergeauth
./build/vergeauth -f ./vergeauth.conf
```

后台守护进程：

```sh
./build/vergeauth -d
./build/vergeauth -d -f ./vergeauth.conf
```

前台日志写入标准错误，后台日志写入系统日志。后台启动命令在监听成功后返回成功状态；配置错误、端口占用或相同配置的实例已运行时返回失败。

修改用户后热更新：

```sh
./build/vergeauth -r
./build/vergeauth -r -f ./vergeauth.conf
```

`-r` 向对应实例发送 SIGHUP，用户表在事件循环中整体替换。命令返回成功表示信号已发送，加载结果见运行日志。热更新仅载入 `user`；修改 `listen`、`upstream` 需要重启。用户配置错误时保留旧用户表，删除全部用户会拒绝后续认证，已认证的连接不受影响。

PID 文件位于配置文件真实路径后追加 `.pid` 的位置，例如 `$HOME/.vergeauth.pid`；运行用户需有权在该目录中创建文件。进程退出时清空 PID 文件并释放锁，不删除文件。

前台按 Ctrl+C 停止；后台可发送 SIGTERM：

```sh
kill -TERM "$(cat "$HOME/.vergeauth.pid")"
```

使用 curl 连接：

```sh
curl --proxy http://127.0.0.1:7898 --proxy-user alice:change-me http://example.com
curl --proxy http://127.0.0.1:7898 --proxy-user alice:change-me https://example.com
curl --proxy socks5h://127.0.0.1:7898 --proxy-user alice:change-me https://example.com
```
