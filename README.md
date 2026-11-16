# DSH 凭据保险库 0.1.0

Windows 本地插件：使用 DPAPI CurrentUser 加密整个凭据库；通过 DSH credentials 服务接入现有模型适配器，提供只返回引用与状态的管理页面，以及可信连接器的固定操作接口。

## 安全边界

本插件不注册读取密钥的模型工具，管理 HTTP API 也不返回密钥。密钥在后端解密并用于请求。当前 Windows 用户仍可调用 DPAPI 解密；若模型具备同用户任意 shell、脚本或插件修改权限，不能承诺模型绝对无法取得密钥。需要强隔离时，须把模型工具放到另一操作系统身份/受限沙箱，密钥服务独立运行并限制网络与管理权限。

只保护通过 credentials 服务保存的 refs 与 records。进程环境变量、项目 .env、用户 .env 仍按 DSH 原优先级作为后备，不会被自动移动或抹除。DeepSeek 官方账号登录 token 走独立服务，本版不接管。其他插件自己保存的密钥不会自动纳入。

## 使用

启用后，在已登录 DSH 的同一浏览器，将当前 DSH 地址的路径改为 /credential-vault。端口随 DSH 重启变化，不能固定写死。凭据引用例如 OPENAI_API_KEY，必须是字母/下划线开头，仅含字母数字下划线。在原模型设置中使用同一个 apiKeyEnv 引用即可。

连接器页面保存 id、名称、引用、固定 HTTPS base URL、鉴权头与前缀。只保存配置不会把现有连接器自动改接到保险库；连接器作者须注册固定 operation 并调用 ctx.connectorVault。不要在URL、label、ref等可见元数据中放入密钥。

```js
export const inject = ['connectorVault'];
export function apply(ctx) {
  ctx.effect(() => ctx.connectorVault.register({
    connector: 'example',
    operation: 'profile',
    method: 'GET',
    path: '/profile',
    project: body => ({ name: body.name, plan: body.plan }),
  }));
  // 在自己的受控工具 execute 内调用：
  // return ctx.connectorVault.invoke('example', 'profile', args, {signal});
}
```

将固定操作暴露为模型工具时，可使用 `dsh-plugin-credential-vault/connector-tools` 的 `registerConnectorTool(ctx, {name, description, connector, operation, parameters, output})`。其中 connector 与 operation 来自可信代码，模型只传 parameters 声明的业务参数；将工具的精确 name 加入受控预设 allow。该辅助函数不提供任意URL、凭据引用或请求头参数。

operation 的路径、方法、参数编码与结果投影必须由可信插件代码决定。模型输入不能指定目标URL、引用或鉴权头。默认拒绝HTTP、IP目标、用户信息、URL查询和重定向；JSON响应限2MiB、请求超时30秒。结果白名单投影是主要防护，常见字面/URL/base64回显脱敏只是额外防线。

## 凭据受控会话（可选）

新增独立预设 `vault-guarded`（凭据受控会话），不替换当前会话。它在预设的站立作用域选择真实 NativeToolExecutor，随会话绑定生效，移除 run_code 任意程序入口；默认 `allow: []` 不开放工具。接入固定连接器操作时，由可信插件全局注册已审核工具，将精确工具名加入该预设的 allow 名单。不要加入 shell、任意文件读取、浏览器调试、远程代理、任意 MCP、管理员或派生不受控会话的工具。

工具限制同时使用 tools.restrict 与单调 tools.guard：拒绝后续注册工具及同名替换。已有同 scope 工具或 executor 冲突会拒绝创建，不会静默降级。宿主插件与工具实现仍为可信边界：换回 PTC、可信工具内部通用执行、宿主输入注入都不由本模块隔离。此模式牺牲任意代码能力；需要保留终端时应使用独立操作系统身份/VM。

## 数据与迁移

加密文件默认位于 DSH_HOME/credential-vault/vault.bin。没有明文密钥或主密钥文件。初始化将现有 version:1 的 .credentials.yaml refs/records 导入，保留一份加密原文备份，重新解密验证每个导入值后才从旧文件清除 refs/records 及注释。冲突、损坏、无法验证均拒绝继续，保留原文件。未带version的早期flat格式严格拒绝，不自动猜测。加密文件与Windows用户配置关联，换用户/系统可能无法解密，请用自己的凭据恢复流程。

连接器目标域名必须由用户信任；本版未做DNS解析结果绑定，不能将HTTPS域名校验当作内网隔离。结果投影须按具体API审查；任意编码或拆分回显无法靠通用字符串脱敏完全识别。移除活动凭据不会清除加密迁移备份，备份中仍可能保留旧值。

锁超时不自动破锁，避免损坏；确认没有写入进程后才可人工恢复。移除插件不会自动把密钥恢复成明文；直接禁用可能让原provider找不到已迁移凭据。

## 验证

独立Node可运行 store/connectors/web 测试。provider测试需DSH真实依赖；本机发行版在ASAR中，使用 Electron 的 ELECTRON_RUN_AS_NODE=1 + --require ./test/runtime-loader.cjs 运行 --test。测试仅使用合成密钥，不输出真实凭据。
