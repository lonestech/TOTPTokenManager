# TOTP Manager Cloudflare Worker
一个用于管理基于时间的单次密码（TOTP）令牌的Cloudflare Pages版本。
范例网站：[https://2fa.civilguard.es/](https://2fa.civilguard.es/)
## 功能
- **TOTP管理**：创建、删除和生成令牌。
- **二维码导出**：为TOTP令牌生成和导出二维码。
- **备份管理**：将TOTP令牌备份到/从GitHub Gist中。
- **CORS支持**：允许跨源请求。
## 设置
1. 安装所需依赖项：
   - `npm install 建议使用 pnpm install`
2. 在Cloudflare Workers上创建一个新的Worker：
   - 访问[Cloudflare Workers](https://dash.cloudflare.com/workers)。
   - 创建一个kv空间，名称为`TOTP_STORE`
   - 创建一个新的Worker，并选择“Pages”类型。fork[前端仓库](https://github.com/lonestech/totppages-manager-frontend)使用Pages链接部署前端。构建命令`npm run build`,构建目录`build`，环境变量``
   - 设置自定义域名
3. 在GitHub上创建一个OAuth应用：
   - 访问[GitHub OAuth Apps](https://github.com/settings/applications/new)。
   - 设置应用名称，选择“Web”类型，主页url 设置前端域名并输入重定向URI（例如：`https://localhost:8080/auth/callback`）。保存并复制生成的客户端ID和客户端密钥.
   - 选择创建好的应用，创建客户端密钥
4. 在`wrangler.toml`中设置以下环境变量：
   - `GITHUB_CLIENT_ID`：您的GitHub OAuth客户端ID。
   - `GITHUB_CLIENT_SECRET`：您的GitHub OAuth客户端密钥。
   - `GITHUB_REDIRECT_URI`：GitHub认证后重定向的URL。
   - `FRONTEND_URL`：前端自定义域名。
   - `TOTP_STORE`：kv空间id。
   设置完成后，运行`pnpm run deploy`命令以部署到Workers中，得到后端接口域名。
5. 到workers设置中修改参数`GITHUB_REDIRECT_URI`为`https://你的后端接口域名/auth/callback`。添加路由，选择一个域，路由内容`*.域名/api/*`
6. 到pages设置,变量和机密中设置`REACT_APP_API_BASE_URL`为后端域名，`REACT_APP_GITHUB_AUTH_URL`为`https://你的后端接口域名/auth/callback`。
。
7. 到github设置中修改重定向URI

### API端点
- **/api/totp**
  - GET：获取TOTP令牌列表。
  - POST：创建新的TOTP令牌。
- **/api/totp/{id}/generate**
  - GET：为TOTP令牌生成一次性密码。
- **/api/totp/{id}/export**
  - GET：为TOTP令牌生成并导出二维码。
- **/api/totp/clear-all**
  - POST：删除所有TOTP令牌。
- **/api/totp/import**
  - POST：从二维码导入TOTP令牌。
- **/api/cleanup-kv**
  - POST：清理KV存储中的无效条目。
- **/api/github/auth-status**
  - GET：检查与GitHub的认证状态。
- **/api/github/auth**
  - GET：启动GitHub认证流程。
- **/api/github/callback**
  - GET：处理GitHub认证回调。
- **/api/github/upload**
  - POST：将TOTP令牌上传到GitHub Gist。
- **/api/github/versions**
  - GET：获取GitHub Gist的版本。
- **/api/github/restore**
  - GET：从GitHub Gist版本恢复TOTP令牌。
- **/api/github/delete-backup**
  - DELETE：删除GitHub Gist。