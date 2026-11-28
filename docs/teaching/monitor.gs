// Apps Script 專案「情資蒐集自動化通知」實際使用的程式碼（程式碼.gs）
// 觸發條件：checkIntelFreshness／時間驅動／每 6 小時
// 指令碼屬性：GITHUB_TOKEN = fine-grained token（僅 allanloplus/intelligence，Actions 讀寫，效期一年）

const URL = "https://allanloplus.github.io/intelligence/data/index.json";
const MAX_HOURS = 12;
const DISPATCH = "https://api.github.com/repos/allanloplus/intelligence/actions/workflows/update-intel.yml/dispatches";

function checkIntelFreshness() {
  const data = JSON.parse(UrlFetchApp.fetch(URL + "?t=" + Date.now()).getContentText());
  const last = new Date(data.generated.replace(" ", "T") + ":00+08:00");
  const hours = (Date.now() - last.getTime()) / 3600000;
  if (hours <= MAX_HOURS) return;

  const token = PropertiesService.getScriptProperties().getProperty("GITHUB_TOKEN");
  const res = UrlFetchApp.fetch(DISPATCH, {
    method: "post",
    contentType: "application/json",
    headers: { Authorization: "Bearer " + token, Accept: "application/vnd.github+json" },
    payload: JSON.stringify({ ref: "main" }),
    muteHttpExceptions: true
  });
  const ok = res.getResponseCode() === 204;
  MailApp.sendEmail(Session.getActiveUser().getEmail(),
    "【情資看板】已 " + Math.floor(hours) + " 小時未更新，" + (ok ? "已自動補跑" : "自動補跑失敗"),
    "最後更新時間：" + data.generated + "\n" +
    (ok ? "已觸發「情資自動更新」，約一分鐘後完成。"
        : "GitHub 回應 " + res.getResponseCode() + "：" + res.getContentText() + "\n請手動執行或檢查權杖是否過期。") +
    "\nhttps://github.com/allanloplus/intelligence/actions/workflows/update-intel.yml");
}
