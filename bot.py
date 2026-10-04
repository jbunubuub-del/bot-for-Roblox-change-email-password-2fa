import os, asyncio, aiohttp, logging
from yarl import URL
from aiogram import Bot, Dispatcher, F
from aiogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton, CallbackQuery
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

TOKEN    = os.getenv("BOT_TOKEN", "")
OWNER_ID = int(os.getenv("OWNER_ID", "0"))

bot = Bot(token=TOKEN)
dp  = Dispatcher(storage=MemoryStorage())

_2fa_future: "asyncio.Future | None" = None

# ── States ────────────────────────────────────────────────────────────────────
class ChangePass(StatesGroup):
    s_cookie = State(); s_cur = State(); s_new = State(); s_2fa = State()

class ForgotPass(StatesGroup):
    s_id = State()

class ChangeEmail(StatesGroup):
    s_cookie = State(); s_pass = State(); s_email = State(); s_2fa = State()

class Add2FA(StatesGroup):
    s_cookie = State(); s_pass = State(); s_email = State()
    s_login2fa = State(); s_verify = State()

class Del2FA(StatesGroup):
    s_cookie = State(); s_pass = State(); s_2fa = State()

class Bulk(StatesGroup):
    s_mode = State(); s_list = State()

# ── Roblox API ────────────────────────────────────────────────────────────────
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
BH = {"Content-Type": "application/json", "User-Agent": UA}

def hdr(csrf): return {"X-CSRF-TOKEN": csrf, **BH}

def mk_session(roblosecurity: str = "") -> aiohttp.ClientSession:
    """Сессия с cookie .ROBLOSECURITY — обходит капчу Roblox."""
    jar = aiohttp.CookieJar(unsafe=True)
    s   = aiohttp.ClientSession(cookie_jar=jar)
    if roblosecurity:
        jar.update_cookies(
            {"ROBLOSECURITY": roblosecurity.strip().lstrip("_|WARNING:-DO-NOT-SHARE-THIS.-")},
            response_url=URL("https://www.roblox.com")
        )
    return s

async def get_csrf(s: aiohttp.ClientSession) -> str:
    """Получаем CSRF через logout — стандартный способ с cookie-сессией."""
    try:
        async with s.post("https://auth.roblox.com/v2/logout", headers=BH) as r:
            t = r.headers.get("x-csrf-token", "")
            log.info(f"get_csrf: status={r.status} token={'ok' if t else 'EMPTY'}")
            return t
    except Exception as e:
        log.error(f"get_csrf error: {e}")
        return ""

async def rbx_check_auth(s: aiohttp.ClientSession) -> dict:
    """Проверяем что cookie рабочий — получаем имя пользователя."""
    try:
        async with s.get("https://users.roblox.com/v1/users/authenticated",
                         headers=BH) as r:
            try: body = await r.json(content_type=None)
            except: body = {}
            log.info(f"check_auth: status={r.status} body={body}")
            if r.status == 200:
                return {"ok": True, "name": body.get("name", "?"), "id": body.get("id")}
            return {"error": "Cookie недействителен или устарел"}
    except Exception as e:
        return {"error": str(e)}

async def rbx_change_password(s: aiohttp.ClientSession, csrf: str, cur: str, new: str) -> dict:
    async with s.post(
        "https://auth.roblox.com/v2/user/passwords/change",
        json={"currentPassword": cur, "newPassword": new}, headers=hdr(csrf)
    ) as r:
        try: body = await r.json(content_type=None)
        except: body = {}
        log.info(f"change_pass: status={r.status} body={body}")
        if r.status == 200: return {"ok": True}
        errs = body.get("errors") or [{}]
        return {"error": errs[0].get("message") or f"HTTP {r.status}: {body}"}

async def rbx_change_email(s: aiohttp.ClientSession, csrf: str, email: str, password: str) -> dict:
    async with s.patch(
        "https://accountsettings.roblox.com/v1/email",
        json={"emailAddress": email, "password": password}, headers=hdr(csrf)
    ) as r:
        try: body = await r.json(content_type=None)
        except: body = {}
        log.info(f"change_email: status={r.status} body={body}")
        if r.status == 200: return {"ok": True}
        errs = body.get("errors") or [{}]
        return {"error": errs[0].get("message") or f"HTTP {r.status}: {body}"}

async def rbx_add_2fa_email(s: aiohttp.ClientSession, csrf: str, email: str) -> dict:
    async with s.post(
        "https://twostepverification.roblox.com/v1/users/current/configuration/email/enable",
        json={"emailAddress": email}, headers=hdr(csrf)
    ) as r:
        try: body = await r.json(content_type=None)
        except: body = {}
        log.info(f"add_2fa_email: status={r.status} body={body}")
        if r.status == 200: return {"ok": True}
        errs = body.get("errors") or [{}]
        return {"error": errs[0].get("message") or f"HTTP {r.status}: {body}"}

async def rbx_verify_2fa_email(s: aiohttp.ClientSession, csrf: str, code: str) -> dict:
    async with s.post(
        "https://twostepverification.roblox.com/v1/users/current/configuration/email/verify",
        json={"code": code}, headers=hdr(csrf)
    ) as r:
        try: body = await r.json(content_type=None)
        except: body = {}
        log.info(f"verify_2fa_email: status={r.status} body={body}")
        if r.status == 200: return {"ok": True}
        errs = body.get("errors") or [{}]
        return {"error": errs[0].get("message") or f"HTTP {r.status}: {body}"}

async def rbx_disable_2fa(s: aiohttp.ClientSession, csrf: str) -> dict:
    async with s.delete(
        "https://twostepverification.roblox.com/v1/users/current/configuration",
        headers=hdr(csrf)
    ) as r:
        try: body = await r.json(content_type=None)
        except: body = {}
        log.info(f"disable_2fa: status={r.status} body={body}")
        if r.status == 200: return {"ok": True}
        errs = body.get("errors") or [{}]
        return {"error": errs[0].get("message") or f"HTTP {r.status}: {body}"}

async def rbx_get_2fa_status(s: aiohttp.ClientSession, user_id: int) -> dict:
    async with s.get(
        f"https://twostepverification.roblox.com/v1/users/{user_id}/configuration",
        headers=BH
    ) as r:
        try: body = await r.json(content_type=None)
        except: body = {}
        log.info(f"2fa_status: status={r.status} body={body}")
        if r.status == 200: return {"ok": True, "data": body}
        return {"error": f"HTTP {r.status}"}

async def rbx_forgot_password(s: aiohttp.ClientSession, identifier: str) -> dict:
    csrf = await get_csrf(s)
    t = "Email" if "@" in identifier else "Username"
    async with s.post(
        "https://auth.roblox.com/v2/passwords/reset/send",
        json={"targetType": t, "target": identifier}, headers=hdr(csrf)
    ) as r:
        try: body = await r.json(content_type=None)
        except: body = {}
        log.info(f"forgot_pass: status={r.status} body={body}")
        if r.status == 200: return {"ok": True}
        errs = body.get("errors") or [{}]
        return {"error": errs[0].get("message") or f"HTTP {r.status}: {body}"}

# ── Helpers ───────────────────────────────────────────────────────────────────
def g(m): return m.from_user.id == OWNER_ID
def is_ok(r): return r.get("ok") is True
def errmsg(r): return r.get("error") or "Неизвестная ошибка"

COOKIE_HELP = (
    "🍪 <b>Как получить .ROBLOSECURITY cookie:</b>\n\n"
    "1. Открой <b>roblox.com</b> в браузере\n"
    "2. Войди в аккаунт\n"
    "3. Нажми <b>F12</b> → вкладка <b>Application</b> (Chrome) или <b>Storage</b> (Firefox)\n"
    "4. Слева: <b>Cookies</b> → <b>https://www.roblox.com</b>\n"
    "5. Найди <b>.ROBLOSECURITY</b> → скопируй значение (Value)\n\n"
    "Вставь сюда скопированное значение:"
)

def menu():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔑 Сменить пароль",  callback_data="c_pass")],
        [InlineKeyboardButton(text="🔓 Сброс пароля",    callback_data="c_forgot")],
        [InlineKeyboardButton(text="📧 Сменить почту",   callback_data="c_email")],
        [InlineKeyboardButton(text="🔐 Добавить 2FA",    callback_data="c_2fa_add")],
        [InlineKeyboardButton(text="🗑 Убрать 2FA",      callback_data="c_2fa_del")],
        [InlineKeyboardButton(text="⚡ Массовая смена",  callback_data="c_bulk")],
    ])
def bmenu():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔑 Только пароль",    callback_data="b_pass")],
        [InlineKeyboardButton(text="📧 Только почта",     callback_data="b_email")],
        [InlineKeyboardButton(text="🔑📧 Пароль + Почта", callback_data="b_both")],
    ])
def ckb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="❌ Отмена", callback_data="cancel")]
    ])

# ── /start /code cancel ───────────────────────────────────────────────────────
@dp.message(Command("start"))
async def cmd_start(m: Message, state: FSMContext):
    if not g(m): return
    await state.clear()
    await m.answer(
        "👾 <b>Roblox Account Changer</b>\n\n"
        "⚠️ Теперь вместо логина/пароля используется <b>.ROBLOSECURITY cookie</b> — "
        "это обходит капчу Roblox.\n\n"
        "Выбери действие:",
        reply_markup=menu(), parse_mode="HTML"
    )

@dp.message(Command("code"))
async def cmd_code(m: Message):
    global _2fa_future
    if not g(m): return
    parts = m.text.strip().split(maxsplit=1)
    if len(parts) < 2:
        await m.answer("❌ Формат: <code>/code 123456</code>", parse_mode="HTML"); return
    code = parts[1].strip()
    if _2fa_future and not _2fa_future.done():
        _2fa_future.set_result(code)
        await m.answer(f"✅ Код <code>{code}</code> принят!", parse_mode="HTML")
    else:
        await m.answer("⚠️ Сейчас 2FA не ожидается.")

@dp.callback_query(F.data == "cancel")
async def on_cancel(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    await cb.message.edit_text("Отменено.", reply_markup=menu())

# ══════════════════════════════════════════════════════════════════════════════
#  🔑 СМЕНА ПАРОЛЯ   (cookie → текущий пароль → новый пароль)
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "c_pass")
async def pass_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(ChangePass.s_cookie)
    await cb.message.edit_text(COOKIE_HELP, parse_mode="HTML", reply_markup=ckb())

@dp.message(ChangePass.s_cookie)
async def pass_cookie(m: Message, state: FSMContext):
    if not g(m): return
    cookie = m.text.strip()
    msg = await m.answer("⏳ Проверяем cookie...")
    s   = mk_session(cookie)
    auth = await rbx_check_auth(s)
    await s.close()
    if "error" in auth:
        await msg.edit_text(f"❌ {errmsg(auth)}\n\n{COOKIE_HELP}",
                            parse_mode="HTML", reply_markup=ckb()); return
    await state.update_data(cookie=cookie)
    await state.set_state(ChangePass.s_cur)
    await msg.edit_text(f"✅ Аккаунт: <b>{auth['name']}</b>\n\nТекущий пароль:",
                        parse_mode="HTML", reply_markup=ckb())

@dp.message(ChangePass.s_cur)
async def pass_cur(m: Message, state: FSMContext):
    if not g(m): return
    await state.update_data(cur=m.text.strip())
    await state.set_state(ChangePass.s_new)
    await m.answer("Новый пароль (мин. 8 симв.):", reply_markup=ckb())

@dp.message(ChangePass.s_new)
async def pass_new(m: Message, state: FSMContext):
    if not g(m): return
    new = m.text.strip()
    if len(new) < 8:
        await m.answer("❌ Минимум 8 символов!"); return
    d   = await state.get_data()
    msg = await m.answer("⏳ Меняем пароль...")
    s   = mk_session(d["cookie"])
    csrf = await get_csrf(s)
    r    = await rbx_change_password(s, csrf, d["cur"], new)
    await s.close(); await state.clear()
    if is_ok(r):
        await msg.edit_text(f"✅ <b>Пароль изменён!</b>\n🔑 Новый: <code>{new}</code>",
                            parse_mode="HTML", reply_markup=menu())
    else:
        await msg.edit_text(f"❌ {errmsg(r)}", reply_markup=menu())

# ══════════════════════════════════════════════════════════════════════════════
#  🔓 СБРОС ПАРОЛЯ
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "c_forgot")
async def forgot_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(ForgotPass.s_id)
    await cb.message.edit_text("🔓 <b>Сброс пароля</b>\n\nЛогин или email аккаунта:",
                                parse_mode="HTML", reply_markup=ckb())

@dp.message(ForgotPass.s_id)
async def forgot_run(m: Message, state: FSMContext):
    if not g(m): return
    idf = m.text.strip()
    msg = await m.answer("⏳ Отправляем запрос...")
    s   = mk_session()
    r   = await rbx_forgot_password(s, idf)
    await s.close(); await state.clear()
    link = f"https://www.roblox.com/login/forgot-password-or-username?identifier={idf}"
    if is_ok(r):
        await msg.edit_text(f"✅ <b>Письмо отправлено!</b>\n\nПрямая ссылка:\n{link}",
                            parse_mode="HTML", reply_markup=menu())
    else:
        await msg.edit_text(f"⚠️ {errmsg(r)}\n\nВручную:\n{link}", reply_markup=menu())

# ══════════════════════════════════════════════════════════════════════════════
#  📧 СМЕНА ПОЧТЫ   (cookie → пароль → новая почта)
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "c_email")
async def email_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(ChangeEmail.s_cookie)
    await cb.message.edit_text(COOKIE_HELP, parse_mode="HTML", reply_markup=ckb())

@dp.message(ChangeEmail.s_cookie)
async def email_cookie(m: Message, state: FSMContext):
    if not g(m): return
    cookie = m.text.strip()
    msg = await m.answer("⏳ Проверяем cookie...")
    s   = mk_session(cookie)
    auth = await rbx_check_auth(s)
    await s.close()
    if "error" in auth:
        await msg.edit_text(f"❌ {errmsg(auth)}\n\n{COOKIE_HELP}",
                            parse_mode="HTML", reply_markup=ckb()); return
    await state.update_data(cookie=cookie)
    await state.set_state(ChangeEmail.s_pass)
    await msg.edit_text(f"✅ Аккаунт: <b>{auth['name']}</b>\n\nПароль аккаунта:",
                        parse_mode="HTML", reply_markup=ckb())

@dp.message(ChangeEmail.s_pass)
async def email_pass(m: Message, state: FSMContext):
    if not g(m): return
    await state.update_data(password=m.text.strip())
    await state.set_state(ChangeEmail.s_email)
    await m.answer("📧 Новая почта:", reply_markup=ckb())

@dp.message(ChangeEmail.s_email)
async def email_new(m: Message, state: FSMContext):
    if not g(m): return
    new_email = m.text.strip()
    d    = await state.get_data()
    msg  = await m.answer("⏳ Меняем почту...")
    s    = mk_session(d["cookie"])
    csrf = await get_csrf(s)
    r    = await rbx_change_email(s, csrf, new_email, d["password"])
    await s.close(); await state.clear()
    if is_ok(r):
        await msg.edit_text(f"✅ <b>Почта изменена!</b>\n📧 <code>{new_email}</code>",
                            parse_mode="HTML", reply_markup=menu())
    else:
        await msg.edit_text(f"❌ {errmsg(r)}", reply_markup=menu())

# ══════════════════════════════════════════════════════════════════════════════
#  🔐 ДОБАВИТЬ 2FA   (cookie → пароль → почта 2FA → код с почты)
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "c_2fa_add")
async def add2fa_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(Add2FA.s_cookie)
    await cb.message.edit_text(COOKIE_HELP, parse_mode="HTML", reply_markup=ckb())

@dp.message(Add2FA.s_cookie)
async def a2_cookie(m: Message, state: FSMContext):
    if not g(m): return
    cookie = m.text.strip()
    msg = await m.answer("⏳ Проверяем cookie...")
    s   = mk_session(cookie)
    auth = await rbx_check_auth(s)
    await s.close()
    if "error" in auth:
        await msg.edit_text(f"❌ {errmsg(auth)}\n\n{COOKIE_HELP}",
                            parse_mode="HTML", reply_markup=ckb()); return
    await state.update_data(cookie=cookie, username=auth["name"])
    await state.set_state(Add2FA.s_email)
    await msg.edit_text(f"✅ Аккаунт: <b>{auth['name']}</b>\n\n📧 Почта для добавления в 2FA:",
                        parse_mode="HTML", reply_markup=ckb())

@dp.message(Add2FA.s_email)
async def a2_email(m: Message, state: FSMContext):
    if not g(m): return
    fa_email = m.text.strip()
    await state.update_data(fa_email=fa_email)
    d    = await state.get_data()
    msg  = await m.answer("⏳ Добавляем 2FA почту...")
    s    = mk_session(d["cookie"])
    csrf = await get_csrf(s)
    r    = await rbx_add_2fa_email(s, csrf, fa_email)
    await state.update_data(csrf=csrf)
    await s.close()
    if "error" in r:
        await state.clear()
        await msg.edit_text(f"❌ {errmsg(r)}", reply_markup=menu()); return
    await state.set_state(Add2FA.s_verify)
    await msg.edit_text(
        f"📨 Код отправлен на <code>{fa_email}</code>\n\nВведи 6-значный код подтверждения:",
        parse_mode="HTML", reply_markup=ckb())

@dp.message(Add2FA.s_verify)
async def a2_verify(m: Message, state: FSMContext):
    if not g(m): return
    code = m.text.strip()
    d    = await state.get_data()
    msg  = await m.answer("⏳ Подтверждаем...")
    s    = mk_session(d["cookie"])
    r    = await rbx_verify_2fa_email(s, d["csrf"], code)
    await s.close(); await state.clear()
    if is_ok(r):
        await msg.edit_text(f"✅ <b>2FA добавлена!</b>\n📧 <code>{d['fa_email']}</code>",
                            parse_mode="HTML", reply_markup=menu())
    else:
        await msg.edit_text(f"❌ {errmsg(r)}", reply_markup=menu())

# ══════════════════════════════════════════════════════════════════════════════
#  🗑 УБРАТЬ 2FA   (cookie)
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "c_2fa_del")
async def del2fa_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(Del2FA.s_cookie)
    await cb.message.edit_text(COOKIE_HELP, parse_mode="HTML", reply_markup=ckb())

@dp.message(Del2FA.s_cookie)
async def d2_cookie(m: Message, state: FSMContext):
    if not g(m): return
    cookie = m.text.strip()
    msg = await m.answer("⏳ Проверяем cookie...")
    s   = mk_session(cookie)
    auth = await rbx_check_auth(s)
    await s.close()
    if "error" in auth:
        await msg.edit_text(f"❌ {errmsg(auth)}\n\n{COOKIE_HELP}",
                            parse_mode="HTML", reply_markup=ckb()); return
    await state.update_data(cookie=cookie)
    msg2 = await msg.edit_text(f"✅ Аккаунт: <b>{auth['name']}</b>\n\n⏳ Отключаем 2FA...",
                               parse_mode="HTML")
    s    = mk_session(cookie)
    csrf = await get_csrf(s)
    r    = await rbx_disable_2fa(s, csrf)
    await s.close(); await state.clear()
    if is_ok(r):
        await msg2.edit_text(f"✅ <b>2FA отключена!</b>\n👤 <code>{auth['name']}</code>",
                             parse_mode="HTML", reply_markup=menu())
    else:
        await msg2.edit_text(f"❌ {errmsg(r)}", reply_markup=menu())

# ══════════════════════════════════════════════════════════════════════════════
#  ⚡ МАССОВАЯ СМЕНА
#  Формат: ROBLOSECURITY:пароль:новый_пароль
#          ROBLOSECURITY:пароль:новая_почта
#          ROBLOSECURITY:пароль:новый_пароль:новая_почта
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "c_bulk")
async def bulk_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(Bulk.s_mode)
    await cb.message.edit_text("⚡ <b>Массовая смена</b>\n\nРежим:", parse_mode="HTML", reply_markup=bmenu())

@dp.callback_query(F.data.startswith("b_"))
async def bulk_mode_cb(cb: CallbackQuery, state: FSMContext):
    mode = cb.data[2:]
    await state.update_data(mode=mode)
    await state.set_state(Bulk.s_list)
    fmt = {
        "pass":  "ROBLOSECURITY:текущий_пароль:новый_пароль",
        "email": "ROBLOSECURITY:пароль:новая_почта",
        "both":  "ROBLOSECURITY:пароль:новый_пароль:новая_почта",
    }
    lbl = {"pass": "Пароль", "email": "Почта", "both": "Пароль + Почта"}
    await cb.message.edit_text(
        f"⚡ Режим: <b>{lbl[mode]}</b>\n\n"
        f"Формат (каждый аккаунт с новой строки):\n"
        f"<code>{fmt[mode]}</code>\n\n"
        f"ROBLOSECURITY = cookie из браузера\n"
        f"При 2FA — пиши <code>/code XXXXXX</code>",
        parse_mode="HTML", reply_markup=ckb()
    )

@dp.message(Bulk.s_list)
async def bulk_run(m: Message, state: FSMContext):
    global _2fa_future
    if not g(m): return
    d     = await state.get_data()
    mode  = d["mode"]
    lines = [l.strip() for l in m.text.strip().split("\n") if l.strip()]
    await state.clear()

    msg = await m.answer(
        f"⚡ Запускаю {len(lines)} аккаунтов...",
        parse_mode="HTML"
    )
    ok_list, fail_list = [], []
    min_p = 4 if mode == "both" else 3

    for i, line in enumerate(lines):
        parts = line.split(":", 3)
        if len(parts) < min_p:
            fail_list.append(f"❌ строка {i+1} — неверный формат"); continue

        cookie   = parts[0].strip()
        password = parts[1].strip()
        arg1     = parts[2].strip()
        arg2     = parts[3].strip() if mode == "both" and len(parts) > 3 else ""

        await msg.edit_text(f"⚡ [{i+1}/{len(lines)}] Аккаунт {i+1}...", parse_mode="HTML")

        try:
            s    = mk_session(cookie)
            auth = await rbx_check_auth(s)
            if "error" in auth:
                fail_list.append(f"❌ аккаунт {i+1} — {errmsg(auth)}")
                await s.close(); continue

            name = auth["name"]
            await msg.edit_text(f"⚡ [{i+1}/{len(lines)}] <code>{name}</code>...", parse_mode="HTML")

            csrf   = await get_csrf(s)
            result = {"ok": True}

            if mode in ("pass", "both"):
                result = await rbx_change_password(s, csrf, password, arg1)

            if is_ok(result) and mode in ("email", "both"):
                em = arg2 if mode == "both" else arg1
                pw = arg1 if mode == "both" else password
                result = await rbx_change_email(s, csrf, em, pw)

            await s.close()
            if is_ok(result):
                ok_list.append(f"✅ {name}")
            else:
                fail_list.append(f"❌ {name} — {errmsg(result)}")

        except Exception as e:
            log.error(f"bulk error #{i+1}: {e}")
            fail_list.append(f"❌ аккаунт {i+1} — {e}")
            try: await s.close()
            except: pass

        await asyncio.sleep(1.2)

    rep = f"⚡ <b>Готово!</b> {len(ok_list)} ✅ / {len(fail_list)} ❌\n\n"
    if ok_list:   rep += "✅ <b>Успех:</b>\n"  + "\n".join(ok_list[:40])  + "\n\n"
    if fail_list: rep += "❌ <b>Ошибки:</b>\n" + "\n".join(fail_list[:40])
    await msg.edit_text(rep, parse_mode="HTML", reply_markup=menu())

# ── main ──────────────────────────────────────────────────────────────────────
async def main():
    log.info(f"Bot started. OWNER_ID={OWNER_ID}")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
