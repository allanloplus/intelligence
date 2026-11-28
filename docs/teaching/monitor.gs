/**
 * 情資更新監控與自動補跑（Google Apps Script）
 *
 * 作用：每 6 小時讀取戰情看板公開的 data/index.json，
 *       若「資料更新時間」超過 MAX_HOURS 小時，就呼叫 GitHub 補跑 workflow 並寄信通知。
 *
 * 設定步驟（教學版）：
 *   1. script.google.com → 新專案，貼上本檔內容並儲存。
 *   2. 左側齒輪「專案設定」→「指令碼屬性」→ 新增屬性
 *        名稱 GITHUB_TOKEN，值貼上 fine-grained token（只開單一 repo 的 Actions 讀寫）。
 *      權杖不要直接寫在程式碼裡。
 *   3. 上方函式選單選 checkAndRecover →「執行」，第一次會要求授權。
 *   4. 左側鬧鐘「觸發條件」→ 新增觸發條件：checkAndRecover／時間驅動／小時計時器／每 6 小時。
 */

const OWNER = 'allanloplus';
const REPO = 'intelligence';
const WORKFLOW_FILE = 'update-intel.yml';
const BRANCH = 'main';
const INDEX_URL = 'https://allanloplus.github.io/intelligence/data/index.json';
const MAX_HOURS = 12;               // 超過幾小時未更新就補跑
const NOTIFY_TO = Session.getEffectiveUser().getEmail(); // 寄給執行者本人；也可改成固定信箱

function checkAndRecover() {
  const generated = fetchGenerated_();            // 例："2026-11-28 10:11"（台北時間）
  const ageHours = (Date.now() - parseTaipei_(generated).getTime()) / 3600000;
  console.log(`看板更新時間 ${generated}，距今 ${ageHours.toFixed(1)} 小時`);
  if (ageHours <= MAX_HOURS) return;

  const res = dispatchWorkflow_();
  const ok = res.getResponseCode() === 204;       // GitHub 接受請求時回 204，沒有內容
  const subject = ok
    ? `[情資監控] 已自動補跑（${ageHours.toFixed(1)} 小時未更新）`
    : `[情資監控] 自動補跑失敗（HTTP ${res.getResponseCode()}）`;
  const body = [
    `看板最後更新：${generated}（台北時間）`,
    `距今：${ageHours.toFixed(1)} 小時，門檻 ${MAX_HOURS} 小時`,
    ok ? '已請 GitHub 執行 workflow，幾分鐘後可到 Actions 頁面確認。'
       : `GitHub 回應：${res.getContentText()}\n常見原因：權杖到期或權限不足。`,
    `https://github.com/${OWNER}/${REPO}/actions`,
  ].join('\n');
  MailApp.sendEmail(NOTIFY_TO, subject, body);
}

function fetchGenerated_() {
  // 加時間參數避開快取
  const res = UrlFetchApp.fetch(`${INDEX_URL}?t=${Date.now()}`, { muteHttpExceptions: true });
  if (res.getResponseCode() !== 200) {
    MailApp.sendEmail(NOTIFY_TO, '[情資監控] 讀不到看板資料', `HTTP ${res.getResponseCode()}\n${INDEX_URL}`);
    throw new Error('讀不到 index.json');
  }
  return JSON.parse(res.getContentText()).generated;
}

function parseTaipei_(s) {
  // "YYYY-MM-DD HH:MM" 視為 UTC+8
  return new Date(s.replace(' ', 'T') + ':00+08:00');
}

function dispatchWorkflow_() {
  const token = PropertiesService.getScriptProperties().getProperty('GITHUB_TOKEN');
  if (!token) throw new Error('尚未在「指令碼屬性」設定 GITHUB_TOKEN');
  return UrlFetchApp.fetch(
    `https://api.github.com/repos/${OWNER}/${REPO}/actions/workflows/${WORKFLOW_FILE}/dispatches`,
    {
      method: 'post',
      contentType: 'application/json',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
      payload: JSON.stringify({ ref: BRANCH }),
      muteHttpExceptions: true,
    });
}
