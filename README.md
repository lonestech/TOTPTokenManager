# TOTP Token Manager

TOTP Token Manager 是一个全栈应用程序，用于管理和生成基于时间的一次性密码（TOTP）。它提供了一个用户友好的界面来添加、删除、生成和导出TOTP令牌，并支持与GitHub Gist集成以进行备份和恢复。

## 功能特性

- 添加、查看和删除TOTP令牌
- 生成TOTP令牌
- 导出和导入TOTP数据
- 支持导入谷歌验证器二维码
- 与GitHub Gist集成，用于备份和恢复
- 响应式Web界面

## 技术栈

### 后端
- 语言：Go
- Web框架：Gorilla Mux
- 其他依赖：见`go.mod`文件

### 前端
- 框架：React
- UI库：Ant Design
- 构建工具：Webpack
- 其他依赖：见`package.json`文件

## 安装

### 后端

1. 确保已安装Go（推荐1.16+版本）
2. 克隆仓库： 
```git clone https://github.com/lonestech/TOTPTokenManager.git```
3. 进入项目目录：
   ```cd TOTPTokenManager```
4. 安装依赖：
   ```go mod tidy```
5. 运行后端服务：
   ```go run main.go```
6. 或者编译为可执行文件：
   ```go build```

### 前端

1. 确保已安装Node.js（推荐14.0.0+版本）和pnpm
2. 进入前端项目目录：
   ```cd totp-manager-frontend```
3. 安装依赖：
   ```pnpm install```
4. 构建生产版本：
   ```pnpm run build```
### 设置GitHub OAuth应用

1. 登录到你的GitHub账户
2. 进入Settings > Developer settings > OAuth Apps
3. 点击"New OAuth App"
4. 填写应用信息：
   - Application name: TOTP Token Manager
   - Homepage URL: http://localhost:8080 (或你的部署URL)
   - Authorization callback URL: http://localhost:8080/api/github/callback
5. 注册应用后，你会获得Client ID和Client Secret
### 环境变量设置

在运行应用之前，需要设置以下环境变量:

```export GITHUB_CLIENT_ID=你的Client ID```

```export GITHUB_CLIENT_SECRET=你的Client Secret```

也可以在github/auth.go中设置默认环境变量值
### 使用说明

1. 启动后端服务
2. 在浏览器中访问:`http://localhost:8080`
3. 使用界面添加、管理和生成TOTP令牌
4. 可以选择连接GitHub账户以使用Gist功能进行备份和恢复

### API端点

| 端点 | 方法  | 描述 |
|------|-----|----|
| `/api/totp` | POST | 添加新的TOTP |
| `/api/totp` | GET | 获取所有TOTP |
| `/api/totp/{id}` | DELETE | 删除特定TOTP |
| `/api/totp/{id}/generate` | GET | 生成特定TOTP的令牌 |
| `/api/totp/{id}/export` | GET | 导出特定TOTP |
| `/api/totp/clear-all` | POST | 清除所有TOTP |
| `/api/totp/import` | POST | 导入TOTP数据 |
| `/api/github/auth` | -   | 重定向用户到GitHub进行授权 |
| `/api/github/upload` | POST | 将TOTP数据上传到GitHub Gist。如果mode为"create"，则创建新的Gist；如果为"update"，则更新现有Gist。 |
| `/api/github/restore?id=<gist_id>` | GET | 从指定的Gist ID恢复TOTP数据 |
| `/api/github/versions` | GET | 列出所有可用的TOTP数据备份版本（Gist） |


### 注意事项

- 确保你的GitHub账户已启用Gist功能
- 所有的Gist备份都是私密的，只有你能访问
- 定期备份你的TOTP数据以确保数据安全
- 在恢复数据时请谨慎操作，以避免覆盖现有的重要数据

## 贡献

欢迎贡献代码、报告问题或提出新功能建议。请遵循标准的GitHub工作流程：

1. Fork 仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建一个 Pull Request

## 许可证

本项目采用 [MIT 许可证](LICENSE)
