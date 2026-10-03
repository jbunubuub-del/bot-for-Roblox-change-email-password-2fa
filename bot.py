import os
import asyncio
import aiohttp
from aiogram import Bot, Dispatcher, F
from aiogram.types import Message, InlineKeyboardMarkup, InlineKeyboardButton, CallbackQuery
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage

TOKEN    = os.getenv("BOT_TOKEN")
OWNER_ID = int(os.getenv("OWNER_ID", "0"))

bot = Bot(token=TOKEN)
dp  = Dispatcher(storage=MemoryStorage())

# ── GUARD ────────────────────────────────────────────────────────────────────
def owner_only(func):
    async def wrapper(message: Message, state: FSMContext, *a, **kw):
        if message.from_user.id != OWNER_ID:
            await message.answer("⛔ Нет доступа.")
            return
        return await func(message, state, *a, **kw)
    wrapper.__name__ = func.__name__
    return wrapper

# ── STATES ───────────────────────────────────────────────────────────────────
class PassChange(StatesGroup):
    login    = State()
    cur_pass = State()
    new_pass = State()
    code_2fa = State()

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
HEADERS_BASE = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}

async def rbx_get_csrf(session: aiohttp.ClientSession) -> str:
    try:
        async with session.post("https://auth.roblox.com/v2/login",
                                json={}, headers=HEADERS_BASE) as r:
            return r.headers.get("x-csrf-token", "")
    except:
        return ""

async def rbx_login(session, login, password):
    csrf = await rbx_get_csrf(session)
    h = {**HEADERS_BASE, "X-CSRF-TOKEN": csrf}
    async with session.post("https://auth.roblox.com/v2/login",
                            json={"ctype": "Username", "cvalue": login, "password": password},
                            headers=h) as r:
        body = await r.json(content_type=None)
        new_csrf = r.headers.get("x-csrf-token", csrf)
        if r.status == 200:
            return {"ok": True, "csrf": new_csrf}
        code = (body.get("errors") or [{}])[0].get("code", -1)
        if r.status == 403 and code == 0:
            ticket = body.get("twoStepVerificationData", {}).get("ticket", "")
            return {"ok": False, "need2fa": True, "csrf": new_csrf, "ticket": ticket}
        msg = (body.get("errors") or [{}])[0].get("message", f"Ошибка {r.status}")
        return {"ok": False, "error": msg}

async def rbx_change_password(session, csrf, cur, new):
    h = {**HEADERS_BASE, "X-CSRF-TOKEN": csrf}
    async with session.post("https://auth.roblox.com/v2/user/passwords/change",
                            json={"currentPassword": cur, "newPassword": new},
                            headers=h) as r:
        if r.status == 200: return {"ok": True}
        b = await r.json(content_type=None)
        return {"ok": False, "error": (b.get("errors") or [{}])[0].get("message", str(r.status))}

async def rbx_change_email(session, csrf, new_email, password):
    h = {**HEADERS_BASE, "X-CSRF-TOKEN": csrf}
    async with session.patch("https://accountsettings.roblox.com/v1/email",
                             json={"emailAddress": new_email, "password": password},
                             headers=h) as r:
        if r.status == 200: return {"ok": True}
        b = await r.json(content_type=None)
        return {"ok": False, "error": (b.get("errors") or [{}])[0].get("message", str(r.status))}

async def rbx_add_2fa_email(session, csrf, email):
    h = {**HEADERS_BASE, "X-CSRF-TOKEN": csrf}
    async with session.post(
        "https://twostepverification.roblox.com/v1/users/current/configuration/email/enable",
        json={"emailAddress": email}, headers=h) as r:
        if r.status == 200: return {"ok": True}
        b = await r.json(content_type=None)
        return {"ok": False, "error": (b.get("errors") or [{}])[0].get("message", str(r.status))}

async def rbx_verify_2fa_email(session, csrf, code):
    h = {**HEADERS_BASE, "X-CSRF-TOKEN": csrf}
    async with session.post(
        "https://twostepverification.roblox.com/v1/users/current/configuration/email/verify",
        json={"code": code}, headers=h) as r:
        if r.status == 200: return {"ok": True}
        b = await r.json(content_type=None)
        return {"ok": False, "error": (b.get("errors") or [{}])[0].get("message", str(r.status))}

async def rbx_disable_2fa(session, csrf):
    h = {**HEADERS_BASE, "X-CSRF-TOKEN": csrf}
    async with session.delete(
        "https://twostepverification.roblox.com/v1/users/current/configuration",
        headers=h) as r:
        if r.status == 200: return {"ok": True}
        b = await r.json(content_type=None)
        return {"ok": False, "error": (b.get("errors") or [{}])[0].get("message", str(r.status))}

# ── MENUS ─────────────────────────────────────────────────────────────────────
def main_menu():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔑 Сменить пароль",  callback_data="cmd_pass")],
        [InlineKeyboardButton(text="📧 Сменить почту",   callback_data="cmd_email")],
        [InlineKeyboardButton(text="🔐 Добавить 2FA",    callback_data="cmd_2fa_add")],
        [InlineKeyboardButton(text="🗑 Убрать 2FA",      callback_data="cmd_2fa_del")],
        [InlineKeyboardButton(text="⚡ Массовая смена",  callback_data="cmd_bulk")],
    ])

def bulk_mode_menu():
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔑 Только пароль",   callback_data="bulk_pass")],
        [InlineKeyboardButton(text="📧 Только почта",    callback_data="bulk_email")],
        [InlineKeyboardButton(text="🔑📧 Пароль + Почта",callback_data="bulk_both")],
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
        "👾 <b>Roblox Account Changer Bot</b>\n\n"
        "Выбери действие:",
        reply_markup=main_menu(),
        parse_mode="HTML"
    )

# ── CANCEL ───────────────────────────────────────────────────────────────────
@dp.callback_query(F.data == "cancel")
async def on_cancel(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    await cb.message.edit_text("❌ Отменено. /start — главное меню")

# ══════════════════════════════════════════════════════════════════════════════
#  СМЕНА ПАРОЛЯ
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "cmd_pass")
async def pass_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(PassChange.login)
    await cb.message.edit_text("🔑 <b>Смена пароля</b>\n\nВведи <b>логин</b> аккаунта Roblox:", parse_mode="HTML", reply_markup=cancel_kb())

@dp.message(PassChange.login)
async def pass_login(message: Message, state: FSMContext):
    await state.update_data(login=message.text.strip())
    await state.set_state(PassChange.cur_pass)
    await message.answer("🔒 Введи <b>текущий пароль</b>:", parse_mode="HTML", reply_markup=cancel_kb())

@dp.message(PassChange.cur_pass)
async def pass_curpass(message: Message, state: FSMContext):
    await state.update_data(cur_pass=message.text.strip())
    await state.set_state(PassChange.new_pass)
    await message.answer("🆕 Введи <b>новый пароль</b> (мин. 8 символов):", parse_mode="HTML", reply_markup=cancel_kb())

@dp.message(PassChange.new_pass)
async def pass_newpass(message: Message, state: FSMContext):
    new = message.text.strip()
    if len(new) < 8:
        await message.answer("❌ Пароль слишком короткий! Минимум 8 символов.", reply_markup=cancel_kb())
        return
    await state.update_data(new_pass=new)
    data = await state.get_data()
    msg = await message.answer("⏳ Входим в аккаунт...")
    async with aiohttp.ClientSession() as s:
        lg = await rbx_login(s, data["login"], data["cur_pass"])
        if lg.get("need2fa"):
            await state.update_data(csrf=lg["csrf"], ticket=lg.get("ticket",""), session_key="pass")
            await state.set_state(PassChange.code_2fa)
            await msg.edit_text("🔐 Аккаунт защищён 2FA!\n\nВведи <b>6-значный код</b> из почты / приложения:", parse_mode="HTML", reply_markup=cancel_kb())
            return
        if not lg["ok"]:
            await state.clear()
            await msg.edit_text(f"❌ Ошибка входа: <code>{lg['error']}</code>\n\n/start", parse_mode="HTML")
            return
        await msg.edit_text("⏳ Меняем пароль...")
        r = await rbx_change_password(s, lg["csrf"], data["cur_pass"], new)
    await state.clear()
    if r["ok"]:
        await msg.edit_text(f"✅ <b>Пароль изменён!</b>\n\n👤 Логин: <code>{data['login']}</code>\n🆕 Новый пароль: <code>{new}</code>", parse_mode="HTML")
    else:
        await msg.edit_text(f"❌ Ошибка: <code>{r['error']}</code>", parse_mode="HTML")

@dp.message(PassChange.code_2fa)
async def pass_2fa(message: Message, state: FSMContext):
    code = message.text.strip()
    data = await state.get_data()
    msg = await message.answer("⏳ Подтверждаем 2FA и меняем пароль...")
    # After 2FA confirm — retry login isn't possible without cookie, inform user
    await state.clear()
    await msg.edit_text(
        f"ℹ️ 2FA код получен: <code>{code}</code>\n\n"
        "⚠️ Для полного обхода 2FA через API нужен .ROBLOSECURITY cookie.\n"
        "Добавь его в переменную <code>ROBLOSEC</code> в настройках Railway.",
        parse_mode="HTML"
    )

# ══════════════════════════════════════════════════════════════════════════════
#  СМЕНА ПОЧТЫ
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "cmd_email")
async def email_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(EmailChange.login)
    await cb.message.edit_text("📧 <b>Смена почты</b>\n\nВведи <b>логин</b>:", parse_mode="HTML", reply_markup=cancel_kb())

@dp.message(EmailChange.login)
async def email_login(message: Message, state: FSMContext):
    await state.update_data(login=message.text.strip())
    await state.set_state(EmailChange.password)
    await message.answer("🔒 Введи <b>пароль</b>:", parse_mode="HTML", reply_markup=cancel_kb())

@dp.message(EmailChange.password)
async def email_password(message: Message, state: FSMContext):
    await state.update_data(password=message.text.strip())
    await state.set_state(EmailChange.new_email)
    await message.answer("📧 Введи <b>новую почту</b>:", parse_mode="HTML", reply_markup=cancel_kb())

@dp.message(EmailChange.new_email)
async def email_newemail(message: Message, state: FSMContext):
    new_email = message.text.strip()
    await state.update_data(new_email=new_email)
    data = await state.get_data()
    msg = await message.answer("⏳ Входим в аккаунт...")
    async with aiohttp.ClientSession() as s:
        lg = await rbx_login(s, data["login"], data["password"])
        if lg.get("need2fa"):
            await state.update_data(csrf=lg["csrf"])
            await state.set_state(EmailChange.code_2fa)
            await msg.edit_text("🔐 Нужен 2FA код!\n\nВведи <b>6-значный код</b>:", parse_mode="HTML", reply_markup=cancel_kb())
            return
        if not lg["ok"]:
            await state.clear()
            await msg.edit_text(f"❌ Ошибка входа: <code>{lg['error']}</code>\n\n/start", parse_mode="HTML")
            return
        await msg.edit_text("⏳ Меняем почту...")
        r = await rbx_change_email(s, lg["csrf"], new_email, data["password"])
    await state.clear()
    if r["ok"]:
        await msg.edit_text(f"✅ <b>Почта изменена!</b>\n\n👤 Логин: <code>{data['login']}</code>\n📧 Новая почта: <code>{new_email}</code>", parse_mode="HTML")
    else:
        await msg.edit_text(f"❌ Ошибка: <code>{r['error']}</code>", parse_mode="HTML")

@dp.message(EmailChange.code_2fa)
async def email_2fa(message: Message, state: FSMContext):
    data = await state.get_data()
    msg = await message.answer("⏳ Применяем...")
    async with aiohttp.ClientSession() as s:
        r = await rbx_change_email(s, data["csrf"], data["new_email"], data["password"])
    await state.clear()
    if r["ok"]:
        await msg.edit_text(f"✅ <b>Почта изменена!</b>\n📧 <code>{data['new_email']}</code>", parse_mode="HTML")
    else:
        await msg.edit_text(f"❌ {r['error']}", parse_mode="HTML")

# ══════════════════════════════════════════════════════════════════════════════
#  ДОБАВИТЬ 2FA
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "cmd_2fa_add")
async def twofa_add_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(TwoFAAdd.login)
    await cb.message.edit_text("🔐 <b>Добавление 2FA</b>\n\nВведи <b>логин</b>:", parse_mode="HTML", reply_markup=cancel_kb())

@dp.message(TwoFAAdd.login)
async def twofa_add_login(message: Message, state: FSMContext):
    await state.update_data(login=message.text.strip())
    await state.set_state(TwoFAAdd.password)
    await message.answer("🔒 Введи <b>пароль</b>:", parse_mode="HTML", reply_markup=cancel_kb())

@dp.message(TwoFAAdd.password)
async def twofa_add_password(message: Message, state: FSMContext):
    await state.update_data(password=message.text.strip())
    await state.set_state(TwoFAAdd.email_2fa)
    await message.answer("📧 Введи <b>почту для 2FA</b>:", parse_mode="HTML", reply_markup=cancel_kb())

@dp.message(TwoFAAdd.email_2fa)
async def twofa_add_email(message: Message, state: FSMContext):
    email_2fa = message.text.strip()
    await state.update_data(email_2fa=email_2fa)
    data = await state.get_data()
    msg = await message.answer("⏳ Входим и добавляем 2FA...")
    async with aiohttp.ClientSession() as s:
        lg = await rbx_login(s, data["login"], data["password"])
        if not lg["ok"] and not lg.get("need2fa"):
            await state.clear()
            await msg.edit_text(f"❌ Ошибка входа: <code>{lg['error']}</code>", parse_mode="HTML")
            return
        csrf = lg["csrf"]
        await state.update_data(csrf=csrf)
        r = await rbx_add_2fa_email(s, csrf, email_2fa)
    if not r["ok"]:
        await state.clear()
        await msg.edit_text(f"❌ Ошибка добавления 2FA: <code>{r['error']}</code>", parse_mode="HTML")
        return
    await state.set_state(TwoFAAdd.code_2fa)
    await msg.edit_text(
        f"📨 Код отправлен на <code>{email_2fa}</code>\n\n"
        "Введи <b>6-значный код подтверждения</b>:",
        parse_mode="HTML", reply_markup=cancel_kb()
    )

@dp.message(TwoFAAdd.code_2fa)
async def twofa_add_code(message: Message, state: FSMContext):
    code = message.text.strip()
    data = await state.get_data()
    msg = await message.answer("⏳ Подтверждаем...")
    async with aiohttp.ClientSession() as s:
        r = await rbx_verify_2fa_email(s, data["csrf"], code)
    await state.clear()
    if r["ok"]:
        await msg.edit_text(f"✅ <b>2FA успешно добавлена!</b>\n📧 Почта: <code>{data['email_2fa']}</code>", parse_mode="HTML")
    else:
        await msg.edit_text(f"❌ Ошибка: <code>{r['error']}</code>", parse_mode="HTML")

# ══════════════════════════════════════════════════════════════════════════════
#  УБРАТЬ 2FA
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "cmd_2fa_del")
async def twofa_del_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(TwoFARemove.login)
    await cb.message.edit_text("🗑 <b>Отключение 2FA</b>\n\nВведи <b>логин</b>:", parse_mode="HTML", reply_markup=cancel_kb())

@dp.message(TwoFARemove.login)
async def twofa_del_login(message: Message, state: FSMContext):
    await state.update_data(login=message.text.strip())
    await state.set_state(TwoFARemove.password)
    await message.answer("🔒 Введи <b>пароль</b>:", parse_mode="HTML", reply_markup=cancel_kb())

@dp.message(TwoFARemove.password)
async def twofa_del_password(message: Message, state: FSMContext):
    data_in = await state.get_data()
    password = message.text.strip()
    msg = await message.answer("⏳ Входим...")
    async with aiohttp.ClientSession() as s:
        lg = await rbx_login(s, data_in["login"], password)
        if lg.get("need2fa"):
            await state.update_data(password=password, csrf=lg["csrf"])
            await state.set_state(TwoFARemove.code_2fa)
            await msg.edit_text("🔐 Нужен текущий 2FA код!\n\nВведи <b>6-значный код</b>:", parse_mode="HTML", reply_markup=cancel_kb())
            return
        if not lg["ok"]:
            await state.clear()
            await msg.edit_text(f"❌ Ошибка: <code>{lg['error']}</code>", parse_mode="HTML")
            return
        await msg.edit_text("⏳ Отключаем 2FA...")
        r = await rbx_disable_2fa(s, lg["csrf"])
    await state.clear()
    if r["ok"]:
        await msg.edit_text(f"✅ <b>2FA отключена!</b>\n👤 <code>{data_in['login']}</code>", parse_mode="HTML")
    else:
        await msg.edit_text(f"❌ {r['error']}", parse_mode="HTML")

@dp.message(TwoFARemove.code_2fa)
async def twofa_del_code(message: Message, state: FSMContext):
    data = await state.get_data()
    msg = await message.answer("⏳ Отключаем 2FA...")
    async with aiohttp.ClientSession() as s:
        r = await rbx_disable_2fa(s, data["csrf"])
    await state.clear()
    if r["ok"]:
        await msg.edit_text(f"✅ <b>2FA отключена!</b>", parse_mode="HTML")
    else:
        await msg.edit_text(f"❌ {r['error']}", parse_mode="HTML")

# ══════════════════════════════════════════════════════════════════════════════
#  МАССОВАЯ СМЕНА
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "cmd_bulk")
async def bulk_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(BulkChange.mode)
    await cb.message.edit_text("⚡ <b>Массовая смена</b>\n\nВыбери режим:", parse_mode="HTML", reply_markup=bulk_mode_menu())

@dp.callback_query(F.data.startswith("bulk_"))
async def bulk_mode(cb: CallbackQuery, state: FSMContext):
    mode = cb.data.replace("bulk_", "")
    await state.update_data(mode=mode)
    await state.set_state(BulkChange.accounts)
    hints = {
        "pass":  "логин:пароль:новый_пароль",
        "email": "логин:пароль:новая_почта",
        "both":  "логин:пароль:новый_пароль:новая_почта",
    }
    await cb.message.edit_text(
        f"⚡ Режим: <b>{'Пароль' if mode=='pass' else 'Почта' if mode=='email' else 'Пароль + Почта'}</b>\n\n"
        f"Отправь список аккаунтов (каждый с новой строки):\n"
        f"<code>{hints[mode]}</code>",
        parse_mode="HTML", reply_markup=cancel_kb()
    )

@dp.message(BulkChange.accounts)
async def bulk_run(message: Message, state: FSMContext):
    data = await state.get_data()
    mode = data["mode"]
    lines = [l.strip() for l in message.text.strip().split("\n") if l.strip()]
    await state.clear()

    msg = await message.answer(f"⚡ Запускаю {len(lines)} аккаунтов...")
    ok_list, fail_list = [], []

    async with aiohttp.ClientSession() as s:
        for i, line in enumerate(lines):
            parts = line.split(":")
            min_len = 4 if mode == "both" else 3
            if len(parts) < min_len:
                fail_list.append(f"❌ {line} — неверный формат")
                continue

            login, password = parts[0], parts[1]
            arg1 = parts[2]
            arg2 = parts[3] if mode == "both" and len(parts) > 3 else ""

            await msg.edit_text(f"⚡ [{i+1}/{len(lines)}] Обрабатываем <code>{login}</code>...", parse_mode="HTML")

            try:
                lg = await rbx_login(s, login, password)
                if not lg["ok"]:
                    err = "Нужен 2FA код (пропущен)" if lg.get("need2fa") else lg.get("error","?")
                    fail_list.append(f"❌ {login} — {err}")
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

            await asyncio.sleep(1.2)

    # Final report
    report = f"⚡ <b>Готово!</b> {len(ok_list)} успех / {len(fail_list)} ошибок\n\n"
    if ok_list:
        report += "✅ <b>Успех:</b>\n" + "\n".join(ok_list[:30]) + "\n\n"
    if fail_list:
        report += "❌ <b>Ошибки:</b>\n" + "\n".join(fail_list[:30])
    if len(ok_list) + len(fail_list) > 60:
        report += "\n\n(показаны первые 30 каждого)"

    await msg.edit_text(report, parse_mode="HTML", reply_markup=main_menu())

# ── MAIN ──────────────────────────────────────────────────────────────────────
async def main():
    print("Bot started")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
