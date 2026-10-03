import os, asyncio, aiohttp, logging
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

# ── Глобальный future для /code в массовом режиме ─────────────────────────────
_2fa_future: "asyncio.Future | None" = None

# ── States ────────────────────────────────────────────────────────────────────
class ChangePass(StatesGroup):
    s_login = State(); s_cur = State(); s_new = State(); s_2fa = State()

class ForgotPass(StatesGroup):
    s_id = State()

class ChangeEmail(StatesGroup):
    s_login = State(); s_pass = State(); s_email = State(); s_2fa = State()

class Add2FA(StatesGroup):
    s_login = State(); s_pass = State(); s_email = State()
    s_login2fa = State()   # 2FA при входе
    s_verify   = State()   # код подтверждения добавления почты

class Del2FA(StatesGroup):
    s_login = State(); s_pass = State(); s_2fa = State()

class Bulk(StatesGroup):
    s_mode = State(); s_list = State()

# ── Roblox API ────────────────────────────────────────────────────────────────
UA  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
BH  = {"Content-Type": "application/json", "User-Agent": UA}

def mk_session():
    """Создаём сессию с unsafe cookie jar (нужно для cross-domain roblox.com)"""
    jar = aiohttp.CookieJar(unsafe=True)
    return aiohttp.ClientSession(cookie_jar=jar, headers=BH)

def hdr(csrf): return {"X-CSRF-TOKEN": csrf}

async def get_csrf(s: aiohttp.ClientSession) -> str:
    try:
        async with s.post("https://auth.roblox.com/v2/login", json={}) as r:
            return r.headers.get("x-csrf-token", "")
    except Exception as e:
        log.error(f"get_csrf error: {e}")
        return ""

async def rbx_login(s: aiohttp.ClientSession, login: str, password: str) -> dict:
    """
    OK        → {"ok": True, "csrf": "..."}
    2FA       → {"need2fa": True, "csrf": "...", "ticket": "...", "media": "Email"}
    Error     → {"error": "message"}
    """
    csrf = await get_csrf(s)
    async with s.post(
        "https://auth.roblox.com/v2/login",
        json={"ctype": "Username", "cvalue": login, "password": password},
        headers=hdr(csrf)
    ) as r:
        new_csrf = r.headers.get("x-csrf-token", csrf)
        try:
            body = await r.json(content_type=None)
        except Exception:
            body = {}
        log.info(f"login {login}: status={r.status} body={body}")

        if r.status == 200:
            return {"ok": True, "csrf": new_csrf}

        twofa = body.get("twoStepVerificationData") or {}
        if twofa.get("ticket"):
            return {
                "need2fa": True,
                "csrf":    new_csrf,
                "ticket":  twofa["ticket"],
                "media":   twofa.get("mediaType", "Email"),
            }
        errs = body.get("errors") or [{}]
        msg  = errs[0].get("message") or f"HTTP {r.status}"
        return {"error": msg}

async def rbx_verify2fa(s: aiohttp.ClientSession, csrf: str,
                         ticket: str, code: str, media: str = "Email") -> dict:
    """Подтверждение 2FA. После успеха сессия s имеет ROBLOSECURITY."""
    payload = {"ticket": ticket, "code": code, "rememberDevice": False, "mediaType": media}
    log.info(f"verify2fa: ticket={ticket[:20]}... code={code} media={media}")

    # Попытка 1
    async with s.post(
        "https://auth.roblox.com/v2/twostepverification/login",
        json=payload, headers=hdr(csrf)
    ) as r:
        new_csrf = r.headers.get("x-csrf-token", csrf)
        try:
            body = await r.json(content_type=None)
        except Exception:
            body = {}
        log.info(f"verify2fa attempt1: status={r.status} body={body}")

        if r.status == 200:
            return {"ok": True, "csrf": new_csrf}

        if r.status != 403:
            errs = body.get("errors") or [{}]
            return {"error": errs[0].get("message") or f"HTTP {r.status}: {body}"}

        # 403 → обновляем csrf и повторяем
        csrf = new_csrf

    # Попытка 2 с новым CSRF
    async with s.post(
        "https://auth.roblox.com/v2/twostepverification/login",
        json=payload, headers=hdr(csrf)
    ) as r:
        new_csrf = r.headers.get("x-csrf-token", csrf)
        try:
            body = await r.json(content_type=None)
        except Exception:
            body = {}
        log.info(f"verify2fa attempt2: status={r.status} body={body}")

        if r.status == 200:
            return {"ok": True, "csrf": new_csrf}

        errs = body.get("errors") or [{}]
        return {"error": errs[0].get("message") or f"HTTP {r.status}: {body}"}

async def rbx_change_password(s: aiohttp.ClientSession,
                               csrf: str, cur: str, new: str) -> dict:
    async with s.post(
        "https://auth.roblox.com/v2/user/passwords/change",
        json={"currentPassword": cur, "newPassword": new},
        headers=hdr(csrf)
    ) as r:
        try: body = await r.json(content_type=None)
        except: body = {}
        log.info(f"change_pass: status={r.status} body={body}")
        if r.status == 200: return {"ok": True}
        errs = body.get("errors") or [{}]
        return {"error": errs[0].get("message") or f"HTTP {r.status}: {body}"}

async def rbx_change_email(s: aiohttp.ClientSession,
                            csrf: str, email: str, password: str) -> dict:
    async with s.patch(
        "https://accountsettings.roblox.com/v1/email",
        json={"emailAddress": email, "password": password},
        headers=hdr(csrf)
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
    await m.answer("👾 <b>Roblox Account Changer</b>\n\nВыбери действие:",
                   reply_markup=menu(), parse_mode="HTML")

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
#  🔑 СМЕНА ПАРОЛЯ
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "c_pass")
async def pass_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(ChangePass.s_login)
    await cb.message.edit_text("🔑 <b>Смена пароля</b>\n\nЛогин:", parse_mode="HTML", reply_markup=ckb())

@dp.message(ChangePass.s_login)
async def pass_l(m: Message, state: FSMContext):
    if not g(m): return
    await state.update_data(login=m.text.strip())
    await state.set_state(ChangePass.s_cur)
    await m.answer("Текущий пароль:", reply_markup=ckb())

@dp.message(ChangePass.s_cur)
async def pass_c(m: Message, state: FSMContext):
    if not g(m): return
    await state.update_data(cur=m.text.strip())
    await state.set_state(ChangePass.s_new)
    await m.answer("Новый пароль (мин. 8 симв.):", reply_markup=ckb())

@dp.message(ChangePass.s_new)
async def pass_n(m: Message, state: FSMContext):
    if not g(m): return
    new = m.text.strip()
    if len(new) < 8:
        await m.answer("❌ Минимум 8 символов!"); return
    await state.update_data(new=new)
    d   = await state.get_data()
    msg = await m.answer("⏳ Входим...")

    s = mk_session()
    lg = await rbx_login(s, d["login"], d["cur"])

    if lg.get("need2fa"):
        await state.update_data(csrf=lg["csrf"], ticket=lg["ticket"], media=lg["media"])
        await state.set_state(ChangePass.s_2fa)
        # НЕ закрываем сессию — кладём в state (нельзя, сессия не сериализуется)
        # Закрываем здесь, в pass_2fa откроем новую — это OK для 2FA verify
        await s.close()
        await msg.edit_text(
            f"🔐 2FA ({lg['media']}) — Roblox уже отправил код на привязанную почту/приложение\n\n"
            f"Введи 6-значный код:", reply_markup=ckb())
        return

    if "error" in lg:
        await s.close(); await state.clear()
        await msg.edit_text(f"❌ Ошибка входа: <code>{errmsg(lg)}</code>",
                            parse_mode="HTML", reply_markup=menu()); return

    r = await rbx_change_password(s, lg["csrf"], d["cur"], new)
    await s.close(); await state.clear()
    if is_ok(r):
        await msg.edit_text(f"✅ <b>Пароль изменён!</b>\n👤 <code>{d['login']}</code>\n🔑 <code>{new}</code>",
                            parse_mode="HTML", reply_markup=menu())
    else:
        await msg.edit_text(f"❌ {errmsg(r)}", reply_markup=menu())

@dp.message(ChangePass.s_2fa)
async def pass_2fa(m: Message, state: FSMContext):
    if not g(m): return
    code = m.text.strip()
    d    = await state.get_data()
    msg  = await m.answer("⏳ Проверяем 2FA...")

    # Открываем НОВУЮ сессию — verify2fa установит cookie, затем меняем пароль
    s   = mk_session()
    lg2 = await rbx_verify2fa(s, d["csrf"], d["ticket"], code, d.get("media","Email"))
    if "error" in lg2:
        await s.close(); await state.clear()
        await msg.edit_text(f"❌ Неверный 2FA код: <code>{errmsg(lg2)}</code>",
                            parse_mode="HTML", reply_markup=menu()); return

    r = await rbx_change_password(s, lg2["csrf"], d["cur"], d["new"])
    await s.close(); await state.clear()
    if is_ok(r):
        await msg.edit_text(f"✅ <b>Пароль изменён!</b>\n👤 <code>{d['login']}</code>",
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
#  📧 СМЕНА ПОЧТЫ
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "c_email")
async def email_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(ChangeEmail.s_login)
    await cb.message.edit_text("📧 <b>Смена почты</b>\n\nЛогин:", parse_mode="HTML", reply_markup=ckb())

@dp.message(ChangeEmail.s_login)
async def email_l(m: Message, state: FSMContext):
    if not g(m): return
    await state.update_data(login=m.text.strip())
    await state.set_state(ChangeEmail.s_pass)
    await m.answer("Пароль:", reply_markup=ckb())

@dp.message(ChangeEmail.s_pass)
async def email_p(m: Message, state: FSMContext):
    if not g(m): return
    await state.update_data(password=m.text.strip())
    await state.set_state(ChangeEmail.s_email)
    await m.answer("Новая почта:", reply_markup=ckb())

@dp.message(ChangeEmail.s_email)
async def email_e(m: Message, state: FSMContext):
    if not g(m): return
    new_email = m.text.strip()
    await state.update_data(new_email=new_email)
    d   = await state.get_data()
    msg = await m.answer("⏳ Входим...")

    s  = mk_session()
    lg = await rbx_login(s, d["login"], d["password"])

    if lg.get("need2fa"):
        await state.update_data(csrf=lg["csrf"], ticket=lg["ticket"], media=lg["media"])
        await state.set_state(ChangeEmail.s_2fa)
        await s.close()
        await msg.edit_text(
            f"🔐 2FA ({lg['media']}) — введи 6-значный код:", reply_markup=ckb())
        return

    if "error" in lg:
        await s.close(); await state.clear()
        await msg.edit_text(f"❌ {errmsg(lg)}", reply_markup=menu()); return

    r = await rbx_change_email(s, lg["csrf"], new_email, d["password"])
    await s.close(); await state.clear()
    if is_ok(r):
        await msg.edit_text(f"✅ <b>Почта изменена!</b>\n👤 <code>{d['login']}</code>\n📧 <code>{new_email}</code>",
                            parse_mode="HTML", reply_markup=menu())
    else:
        await msg.edit_text(f"❌ {errmsg(r)}", reply_markup=menu())

@dp.message(ChangeEmail.s_2fa)
async def email_2fa(m: Message, state: FSMContext):
    if not g(m): return
    code = m.text.strip()
    d    = await state.get_data()
    msg  = await m.answer("⏳ Проверяем 2FA...")

    s   = mk_session()
    lg2 = await rbx_verify2fa(s, d["csrf"], d["ticket"], code, d.get("media","Email"))
    if "error" in lg2:
        await s.close(); await state.clear()
        await msg.edit_text(f"❌ Неверный 2FA: <code>{errmsg(lg2)}</code>",
                            parse_mode="HTML", reply_markup=menu()); return

    r = await rbx_change_email(s, lg2["csrf"], d["new_email"], d["password"])
    await s.close(); await state.clear()
    if is_ok(r):
        await msg.edit_text(f"✅ <b>Почта изменена!</b>\n📧 <code>{d['new_email']}</code>",
                            parse_mode="HTML", reply_markup=menu())
    else:
        await msg.edit_text(f"❌ {errmsg(r)}", reply_markup=menu())

# ══════════════════════════════════════════════════════════════════════════════
#  🔐 ДОБАВИТЬ 2FA
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "c_2fa_add")
async def add2fa_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(Add2FA.s_login)
    await cb.message.edit_text("🔐 <b>Добавление 2FA почты</b>\n\nЛогин:",
                                parse_mode="HTML", reply_markup=ckb())

@dp.message(Add2FA.s_login)
async def a2_l(m: Message, state: FSMContext):
    if not g(m): return
    await state.update_data(login=m.text.strip())
    await state.set_state(Add2FA.s_pass)
    await m.answer("Пароль:", reply_markup=ckb())

@dp.message(Add2FA.s_pass)
async def a2_p(m: Message, state: FSMContext):
    if not g(m): return
    await state.update_data(password=m.text.strip())
    await state.set_state(Add2FA.s_email)
    await m.answer("📧 Почта для добавления в 2FA:", reply_markup=ckb())

@dp.message(Add2FA.s_email)
async def a2_e(m: Message, state: FSMContext):
    if not g(m): return
    fa_email = m.text.strip()
    await state.update_data(fa_email=fa_email)
    d   = await state.get_data()
    msg = await m.answer("⏳ Входим...")

    s  = mk_session()
    lg = await rbx_login(s, d["login"], d["password"])

    if lg.get("need2fa"):
        await state.update_data(csrf=lg["csrf"], ticket=lg["ticket"], media=lg["media"])
        await state.set_state(Add2FA.s_login2fa)
        await s.close()
        await msg.edit_text(f"🔐 Нужен текущий 2FA код ({lg['media']}):\n\nВведи код:", reply_markup=ckb())
        return

    if "error" in lg:
        await s.close(); await state.clear()
        await msg.edit_text(f"❌ {errmsg(lg)}", reply_markup=menu()); return

    # Вошли — добавляем 2FA почту
    r = await rbx_add_2fa_email(s, lg["csrf"], fa_email)
    await state.update_data(csrf=lg["csrf"])
    await s.close()
    if "error" in r:
        await state.clear()
        await msg.edit_text(f"❌ {errmsg(r)}", reply_markup=menu()); return

    await state.set_state(Add2FA.s_verify)
    await msg.edit_text(f"📨 Код отправлен на <code>{fa_email}</code>\n\nВведи код подтверждения:",
                        parse_mode="HTML", reply_markup=ckb())

@dp.message(Add2FA.s_login2fa)
async def a2_login2fa(m: Message, state: FSMContext):
    """2FA при входе — потом добавляем 2FA почту"""
    if not g(m): return
    code = m.text.strip()
    d    = await state.get_data()
    msg  = await m.answer("⏳ Проверяем 2FA входа...")

    s   = mk_session()
    lg2 = await rbx_verify2fa(s, d["csrf"], d["ticket"], code, d.get("media","Email"))
    if "error" in lg2:
        await s.close(); await state.clear()
        await msg.edit_text(f"❌ Неверный 2FA: <code>{errmsg(lg2)}</code>",
                            parse_mode="HTML", reply_markup=menu()); return

    r = await rbx_add_2fa_email(s, lg2["csrf"], d["fa_email"])
    await state.update_data(csrf=lg2["csrf"])
    await s.close()
    if "error" in r:
        await state.clear()
        await msg.edit_text(f"❌ {errmsg(r)}", reply_markup=menu()); return

    await state.set_state(Add2FA.s_verify)
    await msg.edit_text(f"📨 Код отправлен на <code>{d['fa_email']}</code>\n\nВведи код подтверждения:",
                        parse_mode="HTML", reply_markup=ckb())

@dp.message(Add2FA.s_verify)
async def a2_verify(m: Message, state: FSMContext):
    """Подтверждение кода для добавления 2FA почты"""
    if not g(m): return
    code = m.text.strip()
    d    = await state.get_data()
    msg  = await m.answer("⏳ Подтверждаем...")

    s = mk_session()
    r = await rbx_verify_2fa_email(s, d["csrf"], code)
    await s.close(); await state.clear()
    if is_ok(r):
        await msg.edit_text(f"✅ <b>2FA добавлена!</b>\n📧 <code>{d['fa_email']}</code>",
                            parse_mode="HTML", reply_markup=menu())
    else:
        await msg.edit_text(f"❌ {errmsg(r)}", reply_markup=menu())

# ══════════════════════════════════════════════════════════════════════════════
#  🗑 УБРАТЬ 2FA
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "c_2fa_del")
async def del2fa_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(Del2FA.s_login)
    await cb.message.edit_text("🗑 <b>Отключение 2FA</b>\n\nЛогин:", parse_mode="HTML", reply_markup=ckb())

@dp.message(Del2FA.s_login)
async def d2_l(m: Message, state: FSMContext):
    if not g(m): return
    await state.update_data(login=m.text.strip())
    await state.set_state(Del2FA.s_pass)
    await m.answer("Пароль:", reply_markup=ckb())

@dp.message(Del2FA.s_pass)
async def d2_p(m: Message, state: FSMContext):
    if not g(m): return
    password = m.text.strip()
    d   = await state.get_data()
    msg = await m.answer("⏳ Входим...")

    s  = mk_session()
    lg = await rbx_login(s, d["login"], password)

    if lg.get("need2fa"):
        await state.update_data(password=password, csrf=lg["csrf"],
                                ticket=lg["ticket"], media=lg["media"])
        await state.set_state(Del2FA.s_2fa)
        await s.close()
        await msg.edit_text(f"🔐 Нужен 2FA код ({lg['media']}):\n\nВведи код:", reply_markup=ckb())
        return

    if "error" in lg:
        await s.close(); await state.clear()
        await msg.edit_text(f"❌ {errmsg(lg)}", reply_markup=menu()); return

    r = await rbx_disable_2fa(s, lg["csrf"])
    await s.close(); await state.clear()
    if is_ok(r):
        await msg.edit_text(f"✅ <b>2FA отключена!</b>\n👤 <code>{d['login']}</code>",
                            parse_mode="HTML", reply_markup=menu())
    else:
        await msg.edit_text(f"❌ {errmsg(r)}", reply_markup=menu())

@dp.message(Del2FA.s_2fa)
async def d2_2fa(m: Message, state: FSMContext):
    if not g(m): return
    code = m.text.strip()
    d    = await state.get_data()
    msg  = await m.answer("⏳ Проверяем 2FA и отключаем...")

    s   = mk_session()
    lg2 = await rbx_verify2fa(s, d["csrf"], d["ticket"], code, d.get("media","Email"))
    if "error" in lg2:
        await s.close(); await state.clear()
        await msg.edit_text(f"❌ Неверный 2FA: <code>{errmsg(lg2)}</code>",
                            parse_mode="HTML", reply_markup=menu()); return

    r = await rbx_disable_2fa(s, lg2["csrf"])
    await s.close(); await state.clear()
    if is_ok(r):
        await msg.edit_text("✅ <b>2FA отключена!</b>", parse_mode="HTML", reply_markup=menu())
    else:
        await msg.edit_text(f"❌ {errmsg(r)}", reply_markup=menu())

# ══════════════════════════════════════════════════════════════════════════════
#  ⚡ МАССОВАЯ СМЕНА
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
    fmt = {"pass": "логин:пароль:новый_пароль",
           "email": "логин:пароль:новая_почта",
           "both":  "логин:пароль:новый_пароль:новая_почта"}
    lbl = {"pass": "Пароль", "email": "Почта", "both": "Пароль + Почта"}
    await cb.message.edit_text(
        f"⚡ Режим: <b>{lbl[mode]}</b>\n\nФормат:\n<code>{fmt[mode]}</code>\n\n"
        f"При 2FA — бот остановится, пиши <code>/code XXXXXX</code>",
        parse_mode="HTML", reply_markup=ckb()
    )

@dp.message(Bulk.s_list)
async def bulk_run(m: Message, state: FSMContext):
    global _2fa_future
    if not g(m): return
    d    = await state.get_data()
    mode = d["mode"]
    lines = [l.strip() for l in m.text.strip().split("\n") if l.strip()]
    await state.clear()

    msg = await m.answer(
        f"⚡ Запускаю {len(lines)} аккаунтов...\n"
        f"При 2FA пишу сюда — ты вводишь <code>/code XXXXXX</code>",
        parse_mode="HTML"
    )
    ok_list, fail_list = [], []
    min_p = 4 if mode == "both" else 3

    for i, line in enumerate(lines):
        parts = line.split(":")
        if len(parts) < min_p:
            fail_list.append(f"❌ {line[:30]} — неверный формат"); continue

        login    = parts[0].strip()
        password = parts[1].strip()
        arg1     = parts[2].strip()
        arg2     = parts[3].strip() if mode == "both" and len(parts) > 3 else ""

        await msg.edit_text(f"⚡ [{i+1}/{len(lines)}] <code>{login}</code>...", parse_mode="HTML")

        try:
            s  = mk_session()
            lg = await rbx_login(s, login, password)

            # 2FA — ждём код от тебя
            if lg.get("need2fa"):
                fa_csrf   = lg["csrf"]
                fa_ticket = lg["ticket"]
                fa_media  = lg["media"]

                # Показываем сообщение и ждём /code
                _2fa_future = asyncio.get_running_loop().create_future()
                await msg.edit_text(
                    f"🔐 <b>2FA на аккаунте</b> <code>{login}</code>\n"
                    f"Тип: {fa_media}\n\n"
                    f"Roblox отправил код — введи его:\n<code>/code 123456</code>\n\n"
                    f"⏳ Жду 120 сек...",
                    parse_mode="HTML"
                )
                try:
                    code = await asyncio.wait_for(asyncio.shield(_2fa_future), timeout=120)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    _2fa_future = None
                    fail_list.append(f"❌ {login} — 2FA таймаут"); await s.close(); continue

                _2fa_future = None
                await msg.edit_text(f"⚡ [{i+1}/{len(lines)}] <code>{login}</code> — проверяем 2FA...",
                                    parse_mode="HTML")
                # verify2fa в ТОЙ ЖЕ сессии s — ticket не требует старых кук
                lg = await rbx_verify2fa(s, fa_csrf, fa_ticket, code, fa_media)
                if "error" in lg:
                    fail_list.append(f"❌ {login} — 2FA ошибка: {errmsg(lg)}")
                    await s.close(); continue

            if "error" in lg:
                fail_list.append(f"❌ {login} — {errmsg(lg)}")
                await s.close(); continue

            csrf   = lg["csrf"]
            result = {"ok": True}

            if mode in ("pass", "both"):
                result = await rbx_change_password(s, csrf, password, arg1)

            if is_ok(result) and mode in ("email", "both"):
                em = arg2 if mode == "both" else arg1
                pw = arg1 if mode == "both" else password
                result = await rbx_change_email(s, csrf, em, pw)

            await s.close()
            if is_ok(result):
                ok_list.append(f"✅ {login}")
            else:
                fail_list.append(f"❌ {login} — {errmsg(result)}")

        except Exception as e:
            log.error(f"bulk error {login}: {e}")
            fail_list.append(f"❌ {login} — {e}")
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
