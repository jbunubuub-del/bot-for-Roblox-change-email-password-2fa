import os
import asyncio
import aiohttp
from aiogram import Bot, Dispatcher, F
from aiogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton, CallbackQuery
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage

TOKEN    = os.getenv("BOT_TOKEN", "")
OWNER_ID = int(os.getenv("OWNER_ID", "0"))

bot = Bot(token=TOKEN)
dp  = Dispatcher(storage=MemoryStorage())

# ── 2FA WAITER ───────────────────────────────────────────────────────────────
# Храним future для ожидания кода 2FA в массовом режиме
_2fa_future: asyncio.Future | None = None

async def wait_for_2fa_code(bot_msg, login: str) -> str | None:
    global _2fa_future
    _2fa_future = asyncio.get_event_loop().create_future()
    await bot_msg.edit_text(
        f"🔐 <b>Нужен 2FA код!</b>\n\n"
        f"👤 Аккаунт: <code>{login}</code>\n\n"
        f"Введи 6-значный код из почты / приложения командой:\n"
        f"<code>/code XXXXXX</code>",
        parse_mode="HTML"
    )
    try:
        code = await asyncio.wait_for(_2fa_future, timeout=120)
        return code
    except asyncio.TimeoutError:
        _2fa_future = None
        return None

# ── STATES ───────────────────────────────────────────────────────────────────
class PassChange(StatesGroup):
    login    = State()
    cur_pass = State()
    new_pass = State()
    code_2fa = State()

class PassForgot(StatesGroup):
    identifier = State()

class EmailChange(StatesGroup):
    login    = State()
    password = State()
    new_email= State()
    code_2fa = State()

class TwoFAAdd(StatesGroup):
    login    = State()
    password = State()
    email_2fa= State()
    code_2fa = State()

class TwoFARemove(StatesGroup):
    login    = State()
    password = State()
    code_2fa = State()

class BulkChange(StatesGroup):
    mode     = State()
    accounts = State()

# ── ROBLOX API ────────────────────────────────────────────────────────────────
H = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}

async def rbx_get_csrf(s):
    try:
        async with s.post("https://auth.roblox.com/v2/login", json={}, headers=H) as r:
            return r.headers.get("x-csrf-token", "")
    except:
        return ""

async def rbx_login(s, login, password):
    csrf = await rbx_get_csrf(s)
    h = {**H, "X-CSRF-TOKEN": csrf}
    async with s.post("https://auth.roblox.com/v2/login",
                      json={"ctype": "Username", "cvalue": login, "password": password},
                      headers=h) as r:
        body = await r.json(content_type=None)
        new_csrf = r.headers.get("x-csrf-token", csrf)
        if r.status == 200:
            return {"ok": True, "csrf": new_csrf}
        errs = body.get("errors") or [{}]
        code = errs[0].get("code", -1)
        if r.status == 403 and code == 0:
            ticket = body.get("twoStepVerificationData", {}).get("ticket", "")
            media_type = body.get("twoStepVerificationData", {}).get("mediaType", "Email")
            return {"ok": False, "need2fa": True, "csrf": new_csrf,
                    "ticket": ticket, "mediaType": media_type}
        return {"ok": False, "error": errs[0].get("message", f"Ошибка {r.status}")}

async def rbx_login_2fa(s, csrf, ticket, code, media_type="Email"):
    """Подтверждение входа через 2FA код"""
    h = {**H, "X-CSRF-TOKEN": csrf}
    async with s.post(
        "https://auth.roblox.com/v2/twostepverification/login",
        json={"ticket": ticket, "code": code, "rememberDevice": False, "mediaType": media_type},
        headers=h
    ) as r:
        if r.status == 200:
            new_csrf = r.headers.get("x-csrf-token", csrf)
            return {"ok": True, "csrf": new_csrf}
        b = await r.json(content_type=None)
        return {"ok": False, "error": (b.get("errors") or [{}])[0].get("message", str(r.status))}

async def rbx_change_password(s, csrf, cur, new):
    h = {**H, "X-CSRF-TOKEN": csrf}
    async with s.post("https://auth.roblox.com/v2/user/passwords/change",
                      json={"currentPassword": cur, "newPassword": new}, headers=h) as r:
        if r.status == 200: return {"ok": True}
        b = await r.json(content_type=None)
        return {"ok": False, "error": (b.get("errors") or [{}])[0].get("message", str(r.status))}

async def rbx_change_email(s, csrf, new_email, password):
    """Смена почты без отправки письма подтверждения — только через API"""
    h = {**H, "X-CSRF-TOKEN": csrf}
    async with s.patch("https://accountsettings.roblox.com/v1/email",
                       json={"emailAddress": new_email, "password": password}, headers=h) as r:
        if r.status == 200: return {"ok": True}
        b = await r.json(content_type=None)
        return {"ok": False, "error": (b.get("errors") or [{}])[0].get("message", str(r.status))}

async def rbx_forgot_password(s, identifier):
    """Запрос сброса пароля через email/username"""
    csrf = await rbx_get_csrf(s)
    h = {**H, "X-CSRF-TOKEN": csrf}
    async with s.post("https://auth.roblox.com/v2/passwords/reset/send",
                      json={"targetType": "Email" if "@" in identifier else "Username",
                            "target": identifier}, headers=h) as r:
        if r.status == 200: return {"ok": True}
        b = await r.json(content_type=None)
        return {"ok": False, "error": (b.get("errors") or [{}])[0].get("message", str(r.status))}

async def rbx_add_2fa_email(s, csrf, email):
    h = {**H, "X-CSRF-TOKEN": csrf}
    async with s.post(
        "https://twostepverification.roblox.com/v1/users/current/configuration/email/enable",
        json={"emailAddress": email}, headers=h) as r:
        if r.status == 200: return {"ok": True}
        b = await r.json(content_type=None)
        return {"ok": False, "error": (b.get("errors") or [{}])[0].get("message", str(r.status))}

async def rbx_verify_2fa_email(s, csrf, code):
    h = {**H, "X-CSRF-TOKEN": csrf}
    async with s.post(
        "https://twostepverification.roblox.com/v1/users/current/configuration/email/verify",
        json={"code": code}, headers=h) as r:
        if r.status == 200: return {"ok": True}
        b = await r.json(content_type=None)
        return {"ok": False, "error": (b.get("errors") or [{}])[0].get("message", str(r.status))}

async def rbx_disable_2fa(s, csrf):
    h = {**H, "X-CSRF-TOKEN": csrf}
    async with s.delete(
        "https://twostepverification.roblox.com/v1/users/current/configuration", headers=h) as r:
        if r.status == 200: return {"ok": True}
        b = await r.json(content_type=None)
        return {"ok": False, "error": (b.get("errors") or [{}])[0].get("message", str(r.status))}

# ── LOGIN HELPER (авто 2FA через бота) ───────────────────────────────────────
async def login_full(s, login, password, status_msg=None):
    lg = await rbx_login(s, login, password)
    if lg["ok"]: return lg
    if lg.get("need2fa"):
        if status_msg:
            code = await wait_for_2fa_code(status_msg, login)
            if not code:
                return {"ok": False, "error": "2FA таймаут (120 сек)"}
            r2 = await rbx_login_2fa(s, lg["csrf"], lg["ticket"], code, lg.get("mediaType","Email"))
            return r2
        return {"ok": False, "error": f"2FA required (ticket: {lg.get('ticket','?')})"}
    return lg

# ── KEYBOARDS ─────────────────────────────────────────────────────────────────
def main_menu():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔑 Сменить пароль",    callback_data="cmd_pass")],
        [InlineKeyboardButton(text="🔓 Сброс пароля",      callback_data="cmd_forgot")],
        [InlineKeyboardButton(text="📧 Сменить почту",     callback_data="cmd_email")],
        [InlineKeyboardButton(text="🔐 Добавить 2FA",      callback_data="cmd_2fa_add")],
        [InlineKeyboardButton(text="🗑 Убрать 2FA",        callback_data="cmd_2fa_del")],
        [InlineKeyboardButton(text="⚡ Массовая смена",    callback_data="cmd_bulk")],
    ])

def bulk_mode_menu():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔑 Только пароль",    callback_data="bulk_pass")],
        [InlineKeyboardButton(text="📧 Только почта",     callback_data="bulk_email")],
        [InlineKeyboardButton(text="🔑📧 Пароль + Почта", callback_data="bulk_both")],
    ])

def cancel_kb():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="❌ Отмена", callback_data="cancel")]
    ])

# ── /start ────────────────────────────────────────────────────────────────────
@dp.message(Command("start"))
async def cmd_start(message: Message, state: FSMContext):
    if message.from_user.id != OWNER_ID:
        await message.answer("⛔ Нет доступа.")
        return
    await state.clear()
    await message.answer(
        "👾 <b>Roblox Account Changer Bot</b>\n\nВыбери действие:",
        reply_markup=main_menu(), parse_mode="HTML"
    )

# ── /code — ввод 2FA кода в массовом режиме ──────────────────────────────────
@dp.message(Command("code"))
async def cmd_code(message: Message):
    global _2fa_future
    if message.from_user.id != OWNER_ID: return
    parts = message.text.strip().split()
    if len(parts) < 2:
        await message.answer("❌ Используй: <code>/code 123456</code>", parse_mode="HTML")
        return
    code = parts[1].strip()
    if _2fa_future and not _2fa_future.done():
        _2fa_future.set_result(code)
        await message.answer(f"✅ Код <code>{code}</code> принят!", parse_mode="HTML")
    else:
        await message.answer("⚠️ Сейчас 2FA не ожидается.")

# ── CANCEL ────────────────────────────────────────────────────────────────────
@dp.callback_query(F.data == "cancel")
async def on_cancel(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    await cb.message.edit_text("❌ Отменено.", reply_markup=main_menu())

# ══════════════════════════════════════════════════════════════════════════════
#  СМЕНА ПАРОЛЯ
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "cmd_pass")
async def pass_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(PassChange.login)
    await cb.message.edit_text("🔑 <b>Смена пароля</b>\n\nВведи <b>логин</b>:",
                                parse_mode="HTML", reply_markup=cancel_kb())

@dp.message(PassChange.login)
async def pass_login(message: Message, state: FSMContext):
    if message.from_user.id != OWNER_ID: return
    await state.update_data(login=message.text.strip())
    await state.set_state(PassChange.cur_pass)
    await message.answer("🔒 Введи <b>текущий пароль</b>:", parse_mode="HTML", reply_markup=cancel_kb())

@dp.message(PassChange.cur_pass)
async def pass_curpass(message: Message, state: FSMContext):
    if message.from_user.id != OWNER_ID: return
    await state.update_data(cur_pass=message.text.strip())
    await state.set_state(PassChange.new_pass)
    await message.answer("🆕 Введи <b>новый пароль</b> (мин. 8 символов):", parse_mode="HTML", reply_markup=cancel_kb())

@dp.message(PassChange.new_pass)
async def pass_newpass(message: Message, state: FSMContext):
    if message.from_user.id != OWNER_ID: return
    new = message.text.strip()
    if len(new) < 8:
        await message.answer("❌ Пароль < 8 символов!", reply_markup=cancel_kb())
        return
    await state.update_data(new_pass=new)
    data = await state.get_data()
    msg = await message.answer("⏳ Входим...")
    async with aiohttp.ClientSession() as s:
        lg = await rbx_login(s, data["login"], data["cur_pass"])
        if lg.get("need2fa"):
            await state.update_data(csrf=lg["csrf"], ticket=lg.get("ticket",""), media=lg.get("mediaType","Email"))
            await state.set_state(PassChange.code_2fa)
            await msg.edit_text(
                f"🔐 Нужен 2FA код!\n\nВведи <b>6-значный код</b> из {'почты' if lg.get('mediaType','Email')=='Email' else 'приложения'}:",
                parse_mode="HTML", reply_markup=cancel_kb())
            return
        if not lg["ok"]:
            await state.clear()
            await msg.edit_text(f"❌ Ошибка: <code>{lg['error']}</code>", parse_mode="HTML", reply_markup=main_menu())
            return
        await msg.edit_text("⏳ Меняем пароль...")
        r = await rbx_change_password(s, lg["csrf"], data["cur_pass"], new)
    await state.clear()
    if r["ok"]:
        await msg.edit_text(f"✅ <b>Пароль изменён!</b>\n👤 <code>{data['login']}</code>\n🆕 <code>{new}</code>",
                            parse_mode="HTML", reply_markup=main_menu())
    else:
        await msg.edit_text(f"❌ {r['error']}", parse_mode="HTML", reply_markup=main_menu())

@dp.message(PassChange.code_2fa)
async def pass_2fa(message: Message, state: FSMContext):
    if message.from_user.id != OWNER_ID: return
    code = message.text.strip()
    data = await state.get_data()
    msg = await message.answer("⏳ Подтверждаем 2FA...")
    async with aiohttp.ClientSession() as s:
        r2 = await rbx_login_2fa(s, data["csrf"], data["ticket"], code, data.get("media","Email"))
        if not r2["ok"]:
            await state.clear()
            await msg.edit_text(f"❌ Неверный 2FA код: <code>{r2['error']}</code>", parse_mode="HTML", reply_markup=main_menu())
            return
        r = await rbx_change_password(s, r2["csrf"], data["cur_pass"], data["new_pass"])
    await state.clear()
    if r["ok"]:
        await msg.edit_text(f"✅ <b>Пароль изменён!</b>\n👤 <code>{data['login']}</code>", parse_mode="HTML", reply_markup=main_menu())
    else:
        await msg.edit_text(f"❌ {r['error']}", parse_mode="HTML", reply_markup=main_menu())

# ══════════════════════════════════════════════════════════════════════════════
#  СБРОС ПАРОЛЯ (forgot)
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "cmd_forgot")
async def forgot_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(PassForgot.identifier)
    await cb.message.edit_text(
        "🔓 <b>Сброс пароля</b>\n\n"
        "Введи <b>логин или email</b> аккаунта.\n"
        "Roblox отправит ссылку на почту привязанную к аккаунту.",
        parse_mode="HTML", reply_markup=cancel_kb()
    )

@dp.message(PassForgot.identifier)
async def forgot_run(message: Message, state: FSMContext):
    if message.from_user.id != OWNER_ID: return
    identifier = message.text.strip()
    msg = await message.answer("⏳ Отправляем запрос сброса пароля...")
    async with aiohttp.ClientSession() as s:
        r = await rbx_forgot_password(s, identifier)
    await state.clear()
    if r["ok"]:
        await msg.edit_text(
            f"✅ <b>Запрос отправлен!</b>\n\n"
            f"📧 Письмо со ссылкой для сброса пароля отправлено на почту привязанную к <code>{identifier}</code>\n\n"
            f"Или открой ссылку вручную:\n"
            f"https://www.roblox.com/login/forgot-password-or-username?identifier={identifier}",
            parse_mode="HTML", reply_markup=main_menu()
        )
    else:
        await msg.edit_text(
            f"⚠️ API ответил: <code>{r['error']}</code>\n\n"
            f"Попробуй открыть вручную:\n"
            f"https://www.roblox.com/login/forgot-password-or-username?identifier={identifier}",
            parse_mode="HTML", reply_markup=main_menu()
        )

# ══════════════════════════════════════════════════════════════════════════════
#  СМЕНА ПОЧТЫ
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "cmd_email")
async def email_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(EmailChange.login)
    await cb.message.edit_text("📧 <b>Смена почты</b>\n\nВведи <b>логин</b>:",
                                parse_mode="HTML", reply_markup=cancel_kb())

@dp.message(EmailChange.login)
async def email_login(message: Message, state: FSMContext):
    if message.from_user.id != OWNER_ID: return
    await state.update_data(login=message.text.strip())
    await state.set_state(EmailChange.password)
    await message.answer("🔒 Введи <b>пароль</b>:", parse_mode="HTML", reply_markup=cancel_kb())

@dp.message(EmailChange.password)
async def email_password(message: Message, state: FSMContext):
    if message.from_user.id != OWNER_ID: return
    await state.update_data(password=message.text.strip())
    await state.set_state(EmailChange.new_email)
    await message.answer("📧 Введи <b>новую почту</b>:", parse_mode="HTML", reply_markup=cancel_kb())

@dp.message(EmailChange.new_email)
async def email_newemail(message: Message, state: FSMContext):
    if message.from_user.id != OWNER_ID: return
    new_email = message.text.strip()
    await state.update_data(new_email=new_email)
    data = await state.get_data()
    msg = await message.answer("⏳ Входим...")
    async with aiohttp.ClientSession() as s:
        lg = await rbx_login(s, data["login"], data["password"])
        if lg.get("need2fa"):
            await state.update_data(csrf=lg["csrf"], ticket=lg.get("ticket",""), media=lg.get("mediaType","Email"))
            await state.set_state(EmailChange.code_2fa)
            await msg.edit_text("🔐 Нужен 2FA код!\n\nВведи <b>6-значный код</b>:",
                                parse_mode="HTML", reply_markup=cancel_kb())
            return
        if not lg["ok"]:
            await state.clear()
            await msg.edit_text(f"❌ Ошибка входа: <code>{lg['error']}</code>",
                                parse_mode="HTML", reply_markup=main_menu())
            return
        await msg.edit_text("⏳ Меняем почту...")
        r = await rbx_change_email(s, lg["csrf"], new_email, data["password"])
    await state.clear()
    if r["ok"]:
        await msg.edit_text(f"✅ <b>Почта изменена!</b>\n👤 <code>{data['login']}</code>\n📧 <code>{new_email}</code>",
                            parse_mode="HTML", reply_markup=main_menu())
    else:
        await msg.edit_text(f"❌ {r['error']}", parse_mode="HTML", reply_markup=main_menu())

@dp.message(EmailChange.code_2fa)
async def email_2fa(message: Message, state: FSMContext):
    if message.from_user.id != OWNER_ID: return
    code = message.text.strip()
    data = await state.get_data()
    msg = await message.answer("⏳ Подтверждаем 2FA...")
    async with aiohttp.ClientSession() as s:
        r2 = await rbx_login_2fa(s, data["csrf"], data["ticket"], code, data.get("media","Email"))
        if not r2["ok"]:
            await state.clear()
            await msg.edit_text(f"❌ Неверный 2FA: <code>{r2['error']}</code>",
                                parse_mode="HTML", reply_markup=main_menu())
            return
        r = await rbx_change_email(s, r2["csrf"], data["new_email"], data["password"])
    await state.clear()
    if r["ok"]:
        await msg.edit_text(f"✅ <b>Почта изменена!</b>\n📧 <code>{data['new_email']}</code>",
                            parse_mode="HTML", reply_markup=main_menu())
    else:
        await msg.edit_text(f"❌ {r['error']}", parse_mode="HTML", reply_markup=main_menu())

# ══════════════════════════════════════════════════════════════════════════════
#  ДОБАВИТЬ 2FA
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "cmd_2fa_add")
async def twofa_add_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(TwoFAAdd.login)
    await cb.message.edit_text("🔐 <b>Добавление 2FA</b>\n\nВведи <b>логин</b>:",
                                parse_mode="HTML", reply_markup=cancel_kb())

@dp.message(TwoFAAdd.login)
async def twofa_add_login(message: Message, state: FSMContext):
    if message.from_user.id != OWNER_ID: return
    await state.update_data(login=message.text.strip())
    await state.set_state(TwoFAAdd.password)
    await message.answer("🔒 Введи <b>пароль</b>:", parse_mode="HTML", reply_markup=cancel_kb())

@dp.message(TwoFAAdd.password)
async def twofa_add_password(message: Message, state: FSMContext):
    if message.from_user.id != OWNER_ID: return
    await state.update_data(password=message.text.strip())
    await state.set_state(TwoFAAdd.email_2fa)
    await message.answer("📧 Введи <b>почту для 2FA</b>:", parse_mode="HTML", reply_markup=cancel_kb())

@dp.message(TwoFAAdd.email_2fa)
async def twofa_add_email(message: Message, state: FSMContext):
    if message.from_user.id != OWNER_ID: return
    email_2fa = message.text.strip()
    await state.update_data(email_2fa=email_2fa)
    data = await state.get_data()
    msg = await message.answer("⏳ Входим...")
    async with aiohttp.ClientSession() as s:
        lg = await rbx_login(s, data["login"], data["password"])
        csrf = lg.get("csrf","")
        if lg.get("need2fa"):
            await state.update_data(csrf=csrf, ticket=lg.get("ticket",""), media=lg.get("mediaType","Email"))
            await state.set_state(TwoFAAdd.code_2fa)
            await msg.edit_text("🔐 Нужен 2FA код!\n\nВведи <b>6-значный код</b>:",
                                parse_mode="HTML", reply_markup=cancel_kb())
            return
        if not lg["ok"]:
            await state.clear()
            await msg.edit_text(f"❌ Ошибка: <code>{lg['error']}</code>",
                                parse_mode="HTML", reply_markup=main_menu())
            return
        await state.update_data(csrf=csrf)
        await msg.edit_text("⏳ Добавляем 2FA почту...")
        r = await rbx_add_2fa_email(s, csrf, email_2fa)
    if not r["ok"]:
        await state.clear()
        await msg.edit_text(f"❌ {r['error']}", parse_mode="HTML", reply_markup=main_menu())
        return
    await state.set_state(TwoFAAdd.code_2fa)
    await msg.edit_text(
        f"📨 Код отправлен на <code>{email_2fa}</code>\n\nВведи <b>6-значный код</b> подтверждения:",
        parse_mode="HTML", reply_markup=cancel_kb()
    )

@dp.message(TwoFAAdd.code_2fa)
async def twofa_add_code(message: Message, state: FSMContext):
    if message.from_user.id != OWNER_ID: return
    code = message.text.strip()
    data = await state.get_data()
    msg = await message.answer("⏳ Подтверждаем...")
    async with aiohttp.ClientSession() as s:
        # Если была 2FA при входе — сначала логинимся через неё
        if data.get("ticket"):
            r2 = await rbx_login_2fa(s, data["csrf"], data["ticket"], code, data.get("media","Email"))
            if not r2["ok"]:
                await state.clear()
                await msg.edit_text(f"❌ {r2['error']}", parse_mode="HTML", reply_markup=main_menu())
                return
            # Теперь добавляем 2FA
            r = await rbx_add_2fa_email(s, r2["csrf"], data["email_2fa"])
            if r["ok"]:
                await state.clear()
                await msg.edit_text(f"✅ <b>2FA добавлена!</b>\n📧 <code>{data['email_2fa']}</code>",
                                    parse_mode="HTML", reply_markup=main_menu())
            else:
                await state.clear()
                await msg.edit_text(f"❌ {r['error']}", parse_mode="HTML", reply_markup=main_menu())
        else:
            r = await rbx_verify_2fa_email(s, data["csrf"], code)
            await state.clear()
            if r["ok"]:
                await msg.edit_text(f"✅ <b>2FA успешно добавлена!</b>\n📧 <code>{data['email_2fa']}</code>",
                                    parse_mode="HTML", reply_markup=main_menu())
            else:
                await msg.edit_text(f"❌ {r['error']}", parse_mode="HTML", reply_markup=main_menu())

# ══════════════════════════════════════════════════════════════════════════════
#  УБРАТЬ 2FA
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "cmd_2fa_del")
async def twofa_del_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(TwoFARemove.login)
    await cb.message.edit_text("🗑 <b>Отключение 2FA</b>\n\nВведи <b>логин</b>:",
                                parse_mode="HTML", reply_markup=cancel_kb())

@dp.message(TwoFARemove.login)
async def twofa_del_login(message: Message, state: FSMContext):
    if message.from_user.id != OWNER_ID: return
    await state.update_data(login=message.text.strip())
    await state.set_state(TwoFARemove.password)
    await message.answer("🔒 Введи <b>пароль</b>:", parse_mode="HTML", reply_markup=cancel_kb())

@dp.message(TwoFARemove.password)
async def twofa_del_password(message: Message, state: FSMContext):
    if message.from_user.id != OWNER_ID: return
    data_in = await state.get_data()
    password = message.text.strip()
    msg = await message.answer("⏳ Входим...")
    async with aiohttp.ClientSession() as s:
        lg = await rbx_login(s, data_in["login"], password)
        if lg.get("need2fa"):
            await state.update_data(password=password, csrf=lg["csrf"],
                                    ticket=lg.get("ticket",""), media=lg.get("mediaType","Email"))
            await state.set_state(TwoFARemove.code_2fa)
            await msg.edit_text("🔐 Нужен текущий 2FA код!\n\nВведи <b>6-значный код</b>:",
                                parse_mode="HTML", reply_markup=cancel_kb())
            return
        if not lg["ok"]:
            await state.clear()
            await msg.edit_text(f"❌ {lg['error']}", parse_mode="HTML", reply_markup=main_menu())
            return
        await msg.edit_text("⏳ Отключаем 2FA...")
        r = await rbx_disable_2fa(s, lg["csrf"])
    await state.clear()
    if r["ok"]:
        await msg.edit_text(f"✅ <b>2FA отключена!</b>\n👤 <code>{data_in['login']}</code>",
                            parse_mode="HTML", reply_markup=main_menu())
    else:
        await msg.edit_text(f"❌ {r['error']}", parse_mode="HTML", reply_markup=main_menu())

@dp.message(TwoFARemove.code_2fa)
async def twofa_del_code(message: Message, state: FSMContext):
    if message.from_user.id != OWNER_ID: return
    code = message.text.strip()
    data = await state.get_data()
    msg = await message.answer("⏳ Подтверждаем и отключаем 2FA...")
    async with aiohttp.ClientSession() as s:
        r2 = await rbx_login_2fa(s, data["csrf"], data["ticket"], code, data.get("media","Email"))
        if not r2["ok"]:
            await state.clear()
            await msg.edit_text(f"❌ Неверный код: <code>{r2['error']}</code>",
                                parse_mode="HTML", reply_markup=main_menu())
            return
        r = await rbx_disable_2fa(s, r2["csrf"])
    await state.clear()
    if r["ok"]:
        await msg.edit_text("✅ <b>2FA отключена!</b>", parse_mode="HTML", reply_markup=main_menu())
    else:
        await msg.edit_text(f"❌ {r['error']}", parse_mode="HTML", reply_markup=main_menu())

# ══════════════════════════════════════════════════════════════════════════════
#  МАССОВАЯ СМЕНА
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "cmd_bulk")
async def bulk_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(BulkChange.mode)
    await cb.message.edit_text("⚡ <b>Массовая смена</b>\n\nВыбери режим:",
                                parse_mode="HTML", reply_markup=bulk_mode_menu())

@dp.callback_query(F.data.startswith("bulk_"))
async def bulk_mode_cb(cb: CallbackQuery, state: FSMContext):
    mode = cb.data.replace("bulk_", "")
    await state.update_data(mode=mode)
    await state.set_state(BulkChange.accounts)
    hints = {
        "pass":  "логин:пароль:новый_пароль",
        "email": "логин:пароль:новая_почта",
        "both":  "логин:пароль:новый_пароль:новая_почта",
    }
    labels = {"pass": "Пароль", "email": "Почта", "both": "Пароль + Почта"}
    await cb.message.edit_text(
        f"⚡ Режим: <b>{labels[mode]}</b>\n\n"
        f"Отправь список (каждый с новой строки):\n"
        f"<code>{hints[mode]}</code>\n\n"
        f"⚠️ Если аккаунт с 2FA — бот остановится и попросит тебя ввести <code>/code XXXXXX</code>",
        parse_mode="HTML", reply_markup=cancel_kb()
    )

@dp.message(BulkChange.accounts)
async def bulk_run(message: Message, state: FSMContext):
    if message.from_user.id != OWNER_ID: return
    data = await state.get_data()
    mode = data["mode"]
    lines = [l.strip() for l in message.text.strip().split("\n") if l.strip()]
    await state.clear()

    msg = await message.answer(f"⚡ Запускаю {len(lines)} аккаунтов...\n\n"
                               f"Если встретится 2FA — напишу тебе и буду ждать <code>/code XXXXXX</code>",
                               parse_mode="HTML")
    ok_list, fail_list = [], []

    async with aiohttp.ClientSession() as s:
        for i, line in enumerate(lines):
            parts = line.split(":")
            min_len = 4 if mode == "both" else 3
            if len(parts) < min_len:
                fail_list.append(f"❌ {line} — неверный формат")
                continue

            login, password = parts[0].strip(), parts[1].strip()
            arg1 = parts[2].strip()
            arg2 = parts[3].strip() if mode == "both" and len(parts) > 3 else ""

            await msg.edit_text(
                f"⚡ [{i+1}/{len(lines)}] <code>{login}</code>...",
                parse_mode="HTML"
            )

            try:
                lg = await rbx_login(s, login, password)

                # 2FA — ждём код от пользователя
                if lg.get("need2fa"):
                    code = await wait_for_2fa_code(msg, login)
                    if not code:
                        fail_list.append(f"❌ {login} — 2FA таймаут")
                        continue
                    lg = await rbx_login_2fa(s, lg["csrf"], lg["ticket"], code, lg.get("mediaType","Email"))
                    if not lg["ok"]:
                        fail_list.append(f"❌ {login} — неверный 2FA: {lg['error']}")
                        continue
                    await msg.edit_text(f"⚡ [{i+1}/{len(lines)}] <code>{login}</code> — 2FA принят, продолжаем...",
                                        parse_mode="HTML")

                if not lg["ok"]:
                    fail_list.append(f"❌ {login} — {lg.get('error','?')}")
                    continue

                csrf = lg["csrf"]
                result = {"ok": True}

                if mode in ("pass", "both"):
                    result = await rbx_change_password(s, csrf, password, arg1)

                if result["ok"] and mode in ("email", "both"):
                    em = arg2 if mode == "both" else arg1
                    pw = arg1 if mode == "both" else password
                    result = await rbx_change_email(s, csrf, em, pw)

                if result["ok"]:
                    ok_list.append(f"✅ {login}")
                else:
                    fail_list.append(f"❌ {login} — {result['error']}")

            except Exception as e:
                fail_list.append(f"❌ {login} — {str(e)}")

            await asyncio.sleep(1.0)

    report = f"⚡ <b>Готово!</b> {len(ok_list)} ✅ / {len(fail_list)} ❌\n\n"
    if ok_list:
        report += "✅ <b>Успех:</b>\n" + "\n".join(ok_list[:40]) + "\n\n"
    if fail_list:
        report += "❌ <b>Ошибки:</b>\n" + "\n".join(fail_list[:40])
    await msg.edit_text(report, parse_mode="HTML", reply_markup=main_menu())

# ── MAIN ──────────────────────────────────────────────────────────────────────
async def main():
    print(f"Bot started. Owner: {OWNER_ID}")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
