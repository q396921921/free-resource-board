# free-resource-board

免费资源台账 + 每日待办站：资源、操作流程（步骤）、备忘、今日待办与完成记录，带后台管理。
Node 22+ / Express / Postgres，无前端构建。

## 环境变量（全部走部署平台注入，不进仓库）
- `DATABASE_URL`  Postgres 连接串（需 TLS）
- `ADMIN_PASSWORD` 登录密码
- `SESSION_SECRET` 会话签名密钥（随机长串）
- `API_TOKEN`  可选，`POST /api/procedures/:id/complete` 自动标记完成用
- `APP_TZ` 可选，默认 Asia/Shanghai

## 运行
`npm install && npm start`，监听 `$PORT`（0.0.0.0），健康检查 `/health`。
