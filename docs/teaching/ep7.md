# 會自我檢查的自動化：技術彙整
## 技術彙整｜第 T 集（技術）：開發工具、技術與平台一覽

> 形式：技術速查｜讀者：工程師、技術顧問｜不含對話，可直接跳到需要的段落

---

### 一張圖看懂架構

```
[排程] GitHub Actions：一天 6 次 ＋ 手動觸發 ＋ 外部補跑
   │
   ▼
[執行] python -m intel run
   ├─ 蒐集：TWCERT、NICS、iThome RSS、TechNews RSS
   ├─ 去重：以網址為鍵
   ├─ 評估：CISA KEV ＋ CVE Services（SSVC、CVSS）＋ 國內警訊
   ├─ 儲存：data/YYYY/YYYY-MM.json → git commit
   └─ 產出：public/（網站資料 JSON、Excel）
   │
   ▼
[發佈] GitHub Pages：戰情看板、明細查詢、Excel／CSV 下載
   │
   │  data/index.json 的 generated（最後更新時間）
   ▼
[監控] Google Apps Script，每 6 小時
   └─ 超過 12 小時未更新 → 呼叫 workflow_dispatch API 補跑 ＋ 寄信
```

---

### 技術棧總表

| 層 | 使用的工具／技術 | 重點 |
|---|---|---|
| 開發協作 | Claude Code（雲端工作階段） | AI 在 `claude/…` 分支開發，以 Pull Request 交付，由人審核合併 |
| 程式語言 | Python 3.12 | 約 1,000 行（`intel/`），以標準函式庫為主 |
| 第三方套件 | `openpyxl` | 唯一相依套件，用於產生 Excel |
| 抓取與解析 | `urllib.request`、`xml.etree.ElementTree`、`re`、`html` | RSS 以 XML 解析；TWCERT、NICS 列表頁以正規表示式解析 |
| 弱點資料 | CISA KEV JSON feed、CVE Services API（`cveawg.mitre.org`）、資安院／TWCERT 警訊 | KEV 主來源為 cisa.gov，失敗時改用 GitHub 上的 `cisagov/kev-data` 鏡像 |
| 資料儲存 | JSON 檔，存在 git | `data/YYYY/YYYY-MM.json` 每月一檔；國內警訊指標快取於 `data/_state/domestic.json` |
| 產出 | `openpyxl`（Excel）、前端產生 CSV | 每月與年度 Excel；判定依據寫在儲存格註解 |
| 前端 | 單一 HTML 檔（`site/index.html`，約 400 行） | 原生 HTML／CSS／JavaScript，無框架、無外部函式庫 |
| 排程與 CI | GitHub Actions | cron 一天六次、手動觸發、程式變更時觸發 |
| 部署 | GitHub Pages | Source 設為 GitHub Actions |
| 監控與矯正 | Google Apps Script | 時間驅動觸發，每 6 小時；`UrlFetchApp`、`MailApp`、`PropertiesService` |
| 憑證 | GitHub fine-grained personal access token | 單一 repo、Actions 讀寫、效期一年，存於 Apps Script 指令碼屬性 |
| 通知 | GitHub Actions 失敗信、Apps Script 自寄信、Apps Script 錯誤通知 | 「沒執行」由 Apps Script 補位偵測 |

---

### 資料模型：一筆紀錄長這樣

取自 `data/2026/2026-11.json` 的實際紀錄：

```json
{
  "id": "1abb2077393c",
  "date": "2026-11-01",
  "source": "TechNews",
  "title": "簡訊癱瘓手機通話，Android 驚現「死亡簡訊」漏洞",
  "url": "https://infosecu.technews.tw/2026/11/01/...",
  "category": "外部：安全事件情報",
  "severity": "低",
  "countermeasure": "列入風險評鑑",
  "kev": "否", "automatable": "是", "impact": "部分控制",
  "duePublic": "14天", "dueInternal": "60天",
  "auto": false,
  "cves": ["CVE-2026-58882"],
  "cve_detail": [{
    "cve": "CVE-2026-58882", "kev": "否", "automatable": "是", "impact": "部分控制",
    "duePublic": "14天", "dueInternal": "60天",
    "source": "CISA SSVC", "dueSource": "表一類型 6／14", "cvss": 7.5
  }],
  "assessed": "2026-11-26"
}
```

| 欄位 | 用途 |
|---|---|
| `id` | 由網址雜湊產生，作為去重鍵 |
| `kev`／`automatable`／`impact` | 指引的指標 2、3、4（整筆取最嚴格的 CVE） |
| `duePublic`／`dueInternal` | 處置期限：曝露／未曝露於公眾網路（指標 1 由使用者選用） |
| `cve_detail` | 逐一 CVE 的判定值、指標來源（`source`）、期限依據（`dueSource`）、CVSS |
| `auto` | `true` 為自動初判，人工覆核後改為 `false` |
| `assessed` | 最後一次評估日期，供動態調整追蹤 |

---

### 弱點判定邏輯

| 欄位 | 判定順序 |
|---|---|
| 已知被利用 | CISA KEV 清單現況 |
| 能否自動化利用、技術影響程度 | 資安院／TWCERT 警訊公布值 → CVE 紀錄中 CISA ADP 的 SSVC（`Automatable`、`Technical Impact`）→ 依 CVSS 推定並標示「（推定）」 |
| 處置期限 | 資安院指定期限 → 警訊公布期限（KEV 現況一致時）→ 依前三項查指引表一 |

其他規則：

- 每筆最多評估 20 個 CVE，KEV 與已有國內指標者優先，整筆取最嚴格值。
- iThome 資安日報一篇多則新聞，只評估標題頭條那一則的 CVE。
- 近 60 日有 CVE 的紀錄每次執行都重新評估（對應指引「動態調整」），例如 CVE 事後列入 KEV、CISA 補上 SSVC。
- 已存在的紀錄只更新弱點欄位，不覆寫其他欄位，保留人工修改。

---

### GitHub Actions 關鍵設定

檔案：`.github/workflows/update-intel.yml`

```yaml
on:
  schedule:
    - cron: "23 0,3,6,9,13,15 * * *"   # UTC；台北 08:23、11:23、14:23、17:23、21:23、23:23
  workflow_dispatch:                    # 手動與 Apps Script 補跑
  push:
    branches: [main]
    paths: ["intel/**", "site/**", "config/**", "data/**", ".github/workflows/update-intel.yml"]

permissions:
  contents: write    # 把新資料 commit 回 repo
  pages: write
  id-token: write

concurrency:
  group: intel-update
  cancel-in-progress: false   # 排程與補跑撞在一起時排隊，不互相取消
```

步驟：`actions/checkout@v4` → `actions/setup-python@v5` → `python -m intel run` → commit `data/` → `actions/configure-pages@v5` → `actions/upload-pages-artifact@v3` → `actions/deploy-pages@v4` → 若有來源抓到 0 筆，最後一步刻意 `exit 1`，讓 GitHub 寄失敗信。

---

### 監控與自動補跑

| 項目 | 設定 |
|---|---|
| 讀取 | `https://allanloplus.github.io/intelligence/data/index.json` 的 `generated`（台北時間） |
| 門檻 | `MAX_HOURS = 12` |
| 補跑 | `POST /repos/{owner}/{repo}/actions/workflows/update-intel.yml/dispatches`，body `{"ref":"main"}`，成功回 `204` |
| 通知 | 補跑成功或失敗都寄信；Apps Script 本身出錯由 Google 每日彙整寄錯誤通知 |
| 觸發 | 時間驅動，小時計時器，每 6 小時 |
| 完整程式 | 26 行，見第 4 集或 repo 的 `docs/teaching/monitor.gs` |

設計原則：**監控者與被監控者放在不同平台**。GitHub 排程不動時，放在 GitHub 裡的監控也不會動。

---

### 驗證方式與結果

| 驗證 | 方法 | 結果 |
|---|---|---|
| 期限判定邏輯 | 警訊中同時公布指標與期限的 36 個 CVE，以指標查表後比對 | 36/36 一致 |
| 與舊資料比對 | 2026 年 11 月 110 筆，與原 Google Sheet 逐欄比對 | 弱點欄位 13 筆不同，逐筆歸因 |
| 歷史資料搬移 | 2023–2026 年資料從 Google Sheet 唯讀匯入 | 1,908 筆，整理後 1,904 筆 |
| 監控補跑 | 暫時調低門檻，強制觸發 | 收到補跑信，Actions 出現對應執行紀錄 |
| 失敗通知 | 實際發生的 GitHub 暫時錯誤 | 收到 GitHub 失敗信 |
| 權杖到期 | 尚未發生 | 未實測 |

---

### 成本

| 項目 | 費用 |
|---|---|
| GitHub Actions、GitHub Pages | 公開 repo，未產生費用 |
| Google Apps Script | 個人帳號免費額度內 |
| 主機 | 無，不需自行維護主機 |
| AI 開發工具 | 依 Claude 訂閱方案 |

注意：公開 repo 代表程式碼與資料都公開。資料若不宜公開，需改用私有 repo，並重新評估 Actions 與 Pages 的方案與費用。

---

### 踩過的坑（照做前先看）

| # | 現象 | 原因／解法 |
|---|---|---|
| 1 | 網站顯示 README | Pages 的 Source 選成「Deploy from a branch」，改為「GitHub Actions」 |
| 2 | 排程完全沒跑，也沒收到任何通知 | GitHub 只在「執行了但失敗」時寄信；「沒執行」要自己監控 |
| 3 | 排程檔由 AI 修改後仍不啟動 | 推測與最後修改者不是有效帳號有關（**未驗證**）；由帳號擁有者在網頁上改一次後開始運作 |
| 4 | 排程晚了將近七小時才跑 | GitHub 排程不保證準時，尖峰可能延遲或略過；分鐘避開整點、增加時間點、外部監控補跑 |
| 5 | cron 時間不對 | cron 用 UTC，台北時間要減 8 小時 |
| 6 | 找不到權杖設定 | GitHub 有兩個 Settings：權杖在右上角頭像的帳號 Settings → Developer settings |
| 7 | 權杖權限選單與說明不同 | 現行介面要按「Add permissions」加入 Actions |
| 8 | 權杖只能讀公開 repo | 建立時 Repository access 預設是「Public repositories」，要改選「Only select repositories」 |
| 9 | 文件與實際設定不一致 | 排程改為六次後，註解與 README 仍寫五次；改設定時同步改文件 |

---

### 已知限制

- 「對組織的現況威脅程度」「因應對策」是規則初判，取決於 `config/settings.json` 的 `asset_watchlist`，需人工覆核。
- 「資產是否曝露於公眾網路」無法從情資判定，期限兩欄並列由使用者選用。
- iThome RSS 只涵蓋約 28 小時；TechNews 每日只取 1 則。
- 來源網站改版會導致解析失敗：抓到 0 筆時工作會失敗並寄信；警訊指標解析不到時退回 CISA／CVSS 判定。

---

### 原始碼位置

| 內容 | 路徑 |
|---|---|
| 蒐集、評估、匯出程式 | `intel/`（`sources.py`、`enrich.py`、`classify.py`、`export.py`、`store.py`） |
| 前端網頁 | `site/index.html` |
| 排程與部署 | `.github/workflows/update-intel.yml` |
| 來源與資產關鍵字設定 | `config/settings.json` |
| 監控程式（Apps Script） | `docs/teaching/monitor.gs` |
| 系統說明 | `README.md` |

Repo：https://github.com/allanloplus/intelligence
