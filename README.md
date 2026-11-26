# 資安情資自動蒐集（IS-P-052 資訊安全情資管理表）

每日自動蒐集資安情資、評估弱點處置期限、產生 Excel 與查詢網站。
**與現行 Google Sheet 完全獨立**：本系統只在初次匯入歷史資料時「唯讀」下載過試算表，不會寫入任何試算表。

## 運作流程

```
GitHub Actions 排程（每日 08:23、17:23 台北時間）
  └─ python -m intel run
       1. 蒐集   TWCERT（漏洞警訊 / KEV 週報 / 資安新聞）、NICS 漏洞警訊、iThome 資安日報、TechNews 資安
       2. 去重   以網址為鍵；已存在的紀錄永不覆寫（人工修改會被保留）
       3. 評估   擷取 CVE → CISA KEV 目錄 + CISA SSVC（自動化利用 / 技術影響）→ 依指引表一算出處置期限
                 CISA 尚無 SSVC 時依 CVSS 向量推定，並標示「（推定）」
       4. 分類   威脅情報類別 / 威脅程度 / 因應對策（規則初判，見下方「限制」）
       5. 儲存   data/YYYY/YYYY-MM.json（唯一資料來源，變更皆有 git 紀錄）
       6. 產出   public/：查詢網站 + 每月 Excel + 年度 Excel（分頁名稱「YYYY年M月」）
  └─ 發佈到 GitHub Pages
```

## Excel 欄位（同 2026 年 11 月分頁）

資料日期、資料來源、資料標題、訊息網址連結、威脅情資來源、威脅情報類別、對組織的現況威脅程度、因應對策、執行進度說明、
弱點已知被利用(CISA KEV)、弱點能否被自動化利用、弱點遭利用後之技術影響程度、弱點處置期限(曝露於公眾網路)、弱點處置期限(未曝露於公眾網路)

2026 年 10 月以前的月份沒有弱點評估資料，該五欄留白；舊有的「風險之層面」「受影響版本」欄位若有內容會附在最後。

## 查詢網站

- 年度 / 月份 / 來源 / 類別 / 威脅程度 / KEV 篩選，關鍵字可查標題、CVE 編號、網址
- 下載：當月 Excel、全年度 Excel、目前篩選結果 CSV
- 保留範圍：當年度 + 前 `retention_years` 年（`config/settings.json`，預設 3）。更早的資料仍留在 `data/`，只是不上網站。

## 常用操作

| 需求 | 作法 |
|---|---|
| 立即更新 | GitHub → Actions →「情資自動更新」→ Run workflow |
| 修正某筆分類 | 直接編輯 `data/YYYY/YYYY-MM.json` 該筆紀錄並 commit（可把 `"auto"` 改為 `false` 表示已人工覆核） |
| 新增 / 調整來源 | 編輯 `config/settings.json` 的 `sources` |
| 調整組織資產關鍵字 | 編輯 `config/settings.json` 的 `asset_watchlist` |
| 本機執行 | `pip install -r requirements.txt` 後 `python -m intel run`，再開 `public/index.html`（需經 http 伺服器） |
| 匯入其他年度歷史資料 | `python -m intel import-history 2027=<試算表ID或本機xlsx路徑>` |

## 第一次啟用

1. 將本分支合併到 `main`（排程只會在預設分支執行）。
2. repo → Settings → Pages → Source 選 **GitHub Actions**。
3. Actions →「情資自動更新」→ Run workflow，完成後網站網址會顯示在該次執行頁面。

## 限制（請先閱讀）

- **威脅程度與因應對策是規則初判**：以 2026 年 11 月現有資料回測，類別約 93% 相符、弱點五欄約 85–90% 相符，
  但「威脅程度」僅約 45% 相符——這一欄原本就需要依組織環境判斷。新蒐集的紀錄會帶 `"auto": true`，建議月底發佈前覆核。
- TechNews 每日只取 1 則（依資安關鍵字評分），選文不一定與人工挑選相同。
- 來源網站改版會導致該來源抓到 0 筆；此時排程會標示失敗並由 GitHub 寄信通知，其餘來源不受影響。
- 年度 Excel 只含每月情資分頁與說明；原試算表的「外部議題蒐集」「資安情資來源」「重大漏洞情資」「資通安全網路月報整理」分頁不在自動化範圍。
