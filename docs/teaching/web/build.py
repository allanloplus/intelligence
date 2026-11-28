import re, html, sys, pathlib, markdown

SRC = pathlib.Path(__file__).resolve().parent.parent
OUT = pathlib.Path(__file__).resolve().parents[3] / 'site' / 'teaching' / 'index.html'

FACE = {
    'Allan': {'微笑': 'allan-smile', '大笑': 'allan-laugh', '思考': 'allan-think', '抓頭': 'allan-scratch',
              '驚訝': 'allan-surprise', '豎指頭': 'allan-finger', '正經': 'allan-worry', '眨眼': 'allan-wink'},
    '阿拉蕾': {'揮手': 'arale-wave', '大笑': 'arale-laugh', '思考': 'arale-think', '驚訝': 'arale-surprise',
             '疑問抓頭': 'arale-question', '攤手說明': 'arale-explain', '流淚': 'arale-cry',
             '眨眼比讚': 'arale-thumb', '握拳加油': 'arale-fist', '平板展示': 'arale-tablet'},
}
missing = set()
SHOT_ALT = {'4': 'Apps Script 程式碼編輯畫面', '5': '編輯觸發條件畫面', '6': '觸發條件列表',
            '7': '指令碼屬性畫面', '8': 'Gmail 收到的補跑通知信'}
EMOJI = '💡📋🛠🔍🎒💬'
CALLOUT = {'💡': ('tip', '教學重點'), '📋': ('isms', 'ISMS 旁註'), '🛠': ('howto', '動手做'),
           '🔍': ('aside', '小插曲'), '💬': ('tip', '提醒')}


def prep(md):
    out, prev = [], ''
    for line in md.split('\n'):
        line = re.sub(r'^   (?=\S)', '    ', line)
        s = line.strip()
        is_list = bool(re.match(r'^(\d+\.|-)\s', s))
        is_tab = s.startswith('|')
        prev_s = prev.strip()
        if prev_s and ((is_list and not re.match(r'^(\d+\.|-)\s', prev_s) and not prev.startswith(' ') and not line.startswith(' '))
                       or (is_tab and not prev_s.startswith('|'))):
            out.append('')
        out.append(line)
        prev = line
    return '\n'.join(out)


def status(h):
    rep = {'✅': '<span class="dot ok" aria-label="已驗證"></span>', '⏳': '<span class="dot wait" aria-label="待驗證"></span>',
           '🟢': '<span class="dot ok" aria-label="綠燈"></span>', '🟡': '<span class="dot wait" aria-label="黃燈"></span>',
           '🔴': '<span class="dot bad" aria-label="紅燈"></span>', '⚠': '<span class="chip warn">注意</span>',
           '❓': '<span class="chip q">待確認</span>', '️': ''}
    for k, v in rep.items():
        h = h.replace(k, v)
    return h


def md(text):
    h = markdown.markdown(prep(text), extensions=['tables', 'fenced_code'])
    h = re.sub(r'<p>【畫面待補：(.+?)】</p>', r'<div class="todo"><span>畫面待補</span>\1</div>', h)
    def shot(m):
        n = m.group(2)
        return (f'<figure class="shot"><img src="img/shot{n}.jpg" alt="{SHOT_ALT[n]}" loading="lazy">'
                f'<figcaption>{m.group(1)}</figcaption></figure>')
    h = re.sub(r'<p>【畫面：(.+?)（截圖 (\d).*?）.*?】</p>', shot, h)
    h = re.sub(r'<p>【畫面：(.+?)】</p>', r'<p class="direction">\1</p>', h)
    h = re.sub(r'<table>', '<div class="tw"><table>', h).replace('</table>', '</table></div>')
    return status(h)


def strip_quote(lines):
    return '\n'.join(re.sub(r'^> ?', '', l) for l in lines)


SPEAK = re.compile(r'^\*\*(Allan|阿拉蕾)\*\*【表情：(.+?)】\s*$')


def is_starter(l):
    return (SPEAK.match(l) or l.startswith('###') or l.strip() == '---' or l.startswith('【畫面')
            or (l.startswith('> **') and any(e in l[:8] for e in EMOJI)))


def render_episode(text):
    lines = text.split('\n')
    i, out, meta, sub = 0, [], [], ''
    # header
    while i < len(lines) and not lines[i].startswith('### '):
        l = lines[i]
        if l.startswith('## '):
            sub = l[3:].split('｜', 1)[-1]
        elif l.startswith('> ') and ('形式' in l or '時間' in l):
            for part in l[2:].split('｜'):
                if part.startswith('時間：'):
                    meta.append(part[3:])
        i += 1
    m = re.match(r'第 (\S+) 集（(.+?)）：(.+)', sub)
    num, phase, title = m.groups()
    while i < len(lines):
        l = lines[i]
        if not l.strip() or l.strip() == '---':
            i += 1; continue
        if l.startswith('### '):
            h = re.sub(f'[{EMOJI}]\\s*', '', l[4:])
            cls = ' class="end"' if h in ('本集一句話', '課後思考', '全系列回顧', '帶得走的工具卡', '附錄：本集引用') else ''
            out.append(f'<h3{cls}>{html.escape(h)}</h3>'); i += 1; continue
        sm = SPEAK.match(l)
        if sm:
            who, face = sm.groups()
            img = FACE[who].get(face)
            if not img:
                missing.add((who, face)); img = FACE[who][list(FACE[who])[0]]
            i += 1; buf = []
            while i < len(lines):
                if lines[i].strip() == '' and i + 1 < len(lines):
                    j = i
                    while j < len(lines) and lines[j].strip() == '':
                        j += 1
                    if j >= len(lines) or is_starter(lines[j]):
                        break
                if is_starter(lines[i]):
                    break
                buf.append(lines[i]); i += 1
            body = '\n'.join(buf)
            body = re.sub(r'^> (「.+」)$', r'<blockquote class="said">\1</blockquote>', body, flags=re.M)
            side = 'a' if who == 'Allan' else 'r'
            name = 'Allan 講師' if who == 'Allan' else '阿拉蕾'
            out.append(f'<div class="say {side}"><img class="face" src="img/{img}.jpg" alt="{name}（{face}）">'
                       f'<div class="bubble"><div class="who">{name}<span>{face}</span></div>{md(body)}</div></div>')
            continue
        if l.startswith('【畫面'):
            out.append(md(l)); i += 1; continue
        if l.startswith('>'):
            buf = []
            while i < len(lines) and lines[i].startswith('>'):
                buf.append(lines[i]); i += 1
            inner = strip_quote(buf)
            first = inner.split('\n', 1)[0]
            em = next((e for e in EMOJI if first.startswith('**' + e)), None)
            if em:
                kind, label = CALLOUT[em]
                head = re.sub(r'^\*\*.️?\s*', '', first).rstrip('*').strip()
                head = head.split('｜', 1)[-1] if '｜' in head else head
                rest = inner.split('\n', 1)[1] if '\n' in inner else ''
                out.append(f'<aside class="box {kind}"><div class="lab">{label}</div><h4>{html.escape(head)}</h4>{md(rest)}</aside>')
            elif first.startswith('**'):
                out.append(f'<div class="key">{md(inner)}</div>')
            elif first.startswith('標題'):
                out.append(f'<div class="mail">{md(inner)}</div>')
            else:
                out.append(f'<blockquote>{md(inner)}</blockquote>')
            continue
        buf = []
        while i < len(lines) and lines[i].strip() and not is_starter(lines[i]) and not lines[i].startswith('>'):
            buf.append(lines[i]); i += 1
        # allow tables/code following a paragraph without blank line handling
        out.append(md('\n'.join(buf)))
    return num, phase, title, meta, '\n'.join(out)


def buf_continues(l):
    return False


eps = [render_episode((SRC / f'ep{n}.md').read_text()) for n in range(7)]
if missing:
    print('MISSING faces', missing, file=sys.stderr)

PH = {'前導': '序', 'Plan': 'P', 'Do': 'D', 'Check': 'C', 'Act': 'A', '判斷': 'E1', '架構': 'E2'}
SHORT = ['需求由來', '交代工作', '系統長出來了', '什麼叫做對', '它沒在跑', '從寫到判斷', '平台還是程式碼']
LAB = lambda n: f'延伸 {n[1:]}' if n.startswith('E') else f'第 {n} 集'
tabs = ''.join(f'<a class="tab" href="#ep{k}" data-ep="ep{k}" title="{html.escape(t)}"><b>{PH.get(ph, ph)}</b><span>{LAB(n)}</span><em>{SHORT[k]}</em></a>'
               for k, (n, ph, t, _, _) in enumerate(eps))
sections = ''
for k, (n, ph, t, meta, body) in enumerate(eps):
    prev = f'<a href="#ep{k-1}">← {LAB(eps[k-1][0])}</a>' if k else '<span></span>'
    nxt = f'<a href="#ep{k+1}">{LAB(eps[k+1][0])} →</a>' if k < len(eps) - 1 else '<span></span>'
    sections += (f'<section class="ep" id="ep{k}" aria-labelledby="t{k}"><header class="ephead">'
                 f'<div class="phase">{PH.get(ph, ph)}</div><div><p class="eyebrow">{"延伸篇・" if n.startswith("E") else ""}{LAB(n)}・{ph}{"・" + meta[0] if meta else ""}</p>'
                 f'<h2 id="t{k}">{html.escape(t)}</h2></div></header>{body}'
                 f'<nav class="pager">{prev}{nxt}</nav></section>')

tpl = (pathlib.Path(__file__).parent / 'template.html').read_text()
OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(tpl.replace('{{TABS}}', tabs).replace('{{SECTIONS}}', sections))
print('ok', OUT, len(OUT.read_text()))
