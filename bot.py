import os, asyncio, logging
from playwright.async_api import async_playwright, Browser, BrowserContext

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

# ── Глобальный Playwright браузер (создаётся один раз) ────────────────────────
_pw      = None
_browser: Browser | None = None

async def get_browser() -> Browser:
    global _pw, _browser
    if _browser is None or not _browser.is_connected():
        log.info("Запускаем Chromium...")
        _pw      = await async_playwright().start()
        _browser = await _pw.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]
        )
        log.info("Chromium запущен!")
    return _browser

async def mk_context(cookie: str = "") -> BrowserContext:
    """Создаём изолированный контекст браузера с нужным cookie."""
    browser = await get_browser()
    ctx = await browser.new_context(
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        locale="en-US",
        timezone_id="America/New_York",
    )
    if cookie:
        val = cookie.strip().strip('"').strip("'")
        await ctx.add_cookies([{
            "name":     ".ROBLOSECURITY",
            "value":    val,
            "domain":   ".roblox.com",
            "path":     "/",
            "httpOnly": True,
            "secure":   True,
            "sameSite": "None",
        }])
        log.info(f"Cookie установлен: len={len(val)} start={val[:25]!r}")
    return ctx

async def get_csrf(ctx: BrowserContext) -> str:
    """CSRF через logout endpoint."""
    try:
        r = await ctx.request.post("https://auth.roblox.com/v2/logout")
        csrf = r.headers.get("x-csrf-token", "")
        log.info(f"CSRF: {'ok' if csrf else 'EMPTY'} status={r.status}")
        return csrf
    except Exception as e:
        log.error(f"get_csrf error: {e}")
        return ""

# ── Roblox API через Playwright request (реальный браузер, нет CORS) ──────────

async def rbx_check_auth(ctx: BrowserContext) -> dict:
    try:
        r = await ctx.request.get("https://users.roblox.com/v1/users/authenticated")
        body = await r.json()
        log.info(f"check_auth: status={r.status} body={body}")
        if r.status == 200 and body.get("id"):
            return {"ok": True, "name": body.get("name","?"), "id": body["id"]}
        # Fallback
        r2 = await ctx.request.get("https://www.roblox.com/mobileapi/userinfo")
        b2 = await r2.json()
        log.info(f"check_auth mobileapi: status={r2.status} body={b2}")
        if r2.status == 200 and b2.get("UserID"):
            return {"ok": True, "name": b2.get("UserName","?"), "id": b2["UserID"]}
        return {"error": f"Cookie не валид (HTTP {r.status}) — возьми свежий из браузера"}
    except Exception as e:
        log.error(f"check_auth error: {e}")
        return {"error": str(e)}

async def rbx_change_password(ctx: BrowserContext, csrf: str,
                               cur: str, new: str) -> dict:
    r = await ctx.request.post(
        "https://auth.roblox.com/v2/user/passwords/change",
        data={"currentPassword": cur, "newPassword": new},
        headers={"X-CSRF-TOKEN": csrf, "Content-Type": "application/json"},
    )
    try: body = await r.json()
    except: body = {}
    log.info(f"change_pass: status={r.status} body={body}")
    if r.status == 200: return {"ok": True}
    errs = body.get("errors") or [{}]
    return {"error": errs[0].get("message") or f"HTTP {r.status}: {body}"}

async def rbx_change_email(ctx: BrowserContext, csrf: str,
                            email: str, password: str) -> dict:
    r = await ctx.request.patch(
        "https://accountsettings.roblox.com/v1/email",
        data={"emailAddress": email, "password": password},
        headers={"X-CSRF-TOKEN": csrf, "Content-Type": "application/json"},
    )
    try: body = await r.json()
    except: body = {}
    log.info(f"change_email: status={r.status} body={body}")
    if r.status == 200: return {"ok": True}
    errs = body.get("errors") or [{}]
    return {"error": errs[0].get("message") or f"HTTP {r.status}: {body}"}

async def rbx_add_2fa_email(ctx: BrowserContext, csrf: str, email: str) -> dict:
    r = await ctx.request.post(
        "https://twostepverification.roblox.com/v1/users/current/configuration/email/enable",
        data={"emailAddress": email},
        headers={"X-CSRF-TOKEN": csrf, "Content-Type": "application/json"},
    )
    try: body = await r.json()
    except: body = {}
    log.info(f"add_2fa: status={r.status} body={body}")
    if r.status == 200: return {"ok": True}
    errs = body.get("errors") or [{}]
    return {"error": errs[0].get("message") or f"HTTP {r.status}: {body}"}

async def rbx_verify_2fa_email(ctx: BrowserContext, csrf: str, code: str) -> dict:
    r = await ctx.request.post(
        "https://twostepverification.roblox.com/v1/users/current/configuration/email/verify",
        data={"code": code},
        headers={"X-CSRF-TOKEN": csrf, "Content-Type": "application/json"},
    )
    try: body = await r.json()
    except: body = {}
    log.info(f"verify_2fa: status={r.status} body={body}")
    if r.status == 200: return {"ok": True}
    errs = body.get("errors") or [{}]
    return {"error": errs[0].get("message") or f"HTTP {r.status}: {body}"}

async def rbx_disable_2fa(ctx: BrowserContext, csrf: str) -> dict:
    r = await ctx.request.delete(
        "https://twostepverification.roblox.com/v1/users/current/configuration",
        headers={"X-CSRF-TOKEN": csrf, "Content-Type": "application/json"},
    )
    try: body = await r.json()
    except: body = {}
    log.info(f"disable_2fa: status={r.status} body={body}")
    if r.status == 200: return {"ok": True}
    errs = body.get("errors") or [{}]
    return {"error": errs[0].get("message") or f"HTTP {r.status}: {body}"}

async def rbx_forgot_password(identifier: str) -> dict:
    ctx = await mk_context()
    try:
        csrf = await get_csrf(ctx)
        t = "Email" if "@" in identifier else "Username"
        r = await ctx.request.post(
            "https://auth.roblox.com/v2/passwords/reset/send",
            data={"targetType": t, "target": identifier},
            headers={"X-CSRF-TOKEN": csrf, "Content-Type": "application/json"},
        )
        try: body = await r.json()
        except: body = {}
        log.info(f"forgot: status={r.status} body={body}")
        if r.status == 200: return {"ok": True}
        errs = body.get("errors") or [{}]
        return {"error": errs[0].get("message") or f"HTTP {r.status}"}
    finally:
        await ctx.close()

# ── States ────────────────────────────────────────────────────────────────────
class ChangePass(StatesGroup):
    s_cookie = State(); s_cur = State(); s_new = State()

class ForgotPass(StatesGroup):
    s_id = State()

class ChangeEmail(StatesGroup):
    s_cookie = State(); s_pass = State(); s_email = State()

class Add2FA(StatesGroup):
    s_cookie = State(); s_email = State(); s_verify = State()

class Del2FA(StatesGroup):
    s_cookie = State()

class Bulk(StatesGroup):
    s_mode = State(); s_list = State()

# ── Helpers ───────────────────────────────────────────────────────────────────
def g(m): return m.from_user.id == OWNER_ID
def is_ok(r): return r.get("ok") is True
def err(r): return r.get("error") or "Неизвестная ошибка"

COOKIE_HELP = (
    "🍪 <b>Как получить .ROBLOSECURITY cookie:</b>\n\n"
    "1. Открой <b>roblox.com</b> в Chrome\n"
    "2. Войди в аккаунт\n"
    "3. <b>F12</b> → <b>Application</b> → <b>Cookies</b> → roblox.com\n"
    "4. Найди <b>.ROBLOSECURITY</b> → дважды кликни на Value → Ctrl+A → Ctrl+C\n\n"
    "Вставь сюда (начинается с <code>_|WARNING</code>):"
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

async def check_cookie_step(m: Message, state: FSMContext,
                              next_state, next_text: str):
    """Общая проверка cookie — используется во всех флоу."""
    cookie = m.text.strip().strip('"').strip("'")
    msg    = await m.answer("⏳ Проверяем cookie через Chromium...")
    ctx    = await mk_context(cookie)
    auth   = await rbx_check_auth(ctx)
    await ctx.close()
    if "error" in auth:
        await msg.edit_text(f"❌ {err(auth)}\n\n{COOKIE_HELP}",
                            parse_mode="HTML", reply_markup=ckb())
        return False
    await state.update_data(cookie=cookie, username=auth["name"])
    await msg.edit_text(f"✅ Аккаунт: <b>{auth['name']}</b>\n\n{next_text}",
                        parse_mode="HTML", reply_markup=ckb())
    await state.set_state(next_state)
    return True

# ── /start cancel ─────────────────────────────────────────────────────────────
@dp.message(Command("start"))
async def cmd_start(m: Message, state: FSMContext):
    if not g(m): return
    await state.clear()
    await m.answer("👾 <b>Roblox Account Changer</b>\n\n"
                   "🔵 Работает через <b>Chromium</b> — никаких проблем с cookie!\n\n"
                   "Выбери действие:", reply_markup=menu(), parse_mode="HTML")

@dp.callback_query(F.data == "cancel")
async def on_cancel(cb: CallbackQuery, state: FSMContext):
    await state.clear()
    await cb.message.edit_text("Отменено.", reply_markup=menu())

# ══════════════════════════════════════════════════════════════════════════════
#  🔑 СМЕНА ПАРОЛЯ
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "c_pass")
async def pass_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(ChangePass.s_cookie)
    await cb.message.edit_text(COOKIE_HELP, parse_mode="HTML", reply_markup=ckb())

@dp.message(ChangePass.s_cookie)
async def pass_cookie(m: Message, state: FSMContext):
    if not g(m): return
    await check_cookie_step(m, state, ChangePass.s_cur, "Текущий пароль:")

@dp.message(ChangePass.s_cur)
async def pass_cur(m: Message, state: FSMContext):
    if not g(m): return
    await state.update_data(cur=m.text.strip())
    await state.set_state(ChangePass.s_new)
    await m.answer("🆕 Новый пароль (мин. 8 симв.):", reply_markup=ckb())

@dp.message(ChangePass.s_new)
async def pass_new(m: Message, state: FSMContext):
    if not g(m): return
    new = m.text.strip()
    if len(new) < 8:
        await m.answer("❌ Минимум 8 символов!"); return
    d   = await state.get_data()
    msg = await m.answer("⏳ Меняем пароль через Chromium...")
    ctx  = await mk_context(d["cookie"])
    csrf = await get_csrf(ctx)
    r    = await rbx_change_password(ctx, csrf, d["cur"], new)
    await ctx.close(); await state.clear()
    if is_ok(r):
        await msg.edit_text(f"✅ <b>Пароль изменён!</b>\n"
                            f"👤 <code>{d['username']}</code>\n"
                            f"🔑 Новый: <code>{new}</code>",
                            parse_mode="HTML", reply_markup=menu())
    else:
        await msg.edit_text(f"❌ {err(r)}", reply_markup=menu())

# ══════════════════════════════════════════════════════════════════════════════
#  🔓 СБРОС ПАРОЛЯ
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "c_forgot")
async def forgot_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(ForgotPass.s_id)
    await cb.message.edit_text("🔓 <b>Сброс пароля</b>\n\nЛогин или email:",
                                parse_mode="HTML", reply_markup=ckb())

@dp.message(ForgotPass.s_id)
async def forgot_run(m: Message, state: FSMContext):
    if not g(m): return
    idf = m.text.strip()
    msg = await m.answer("⏳ Отправляем запрос...")
    r   = await rbx_forgot_password(idf)
    await state.clear()
    link = f"https://www.roblox.com/login/forgot-password-or-username?identifier={idf}"
    if is_ok(r):
        await msg.edit_text(f"✅ <b>Письмо отправлено!</b>\nСсылка: {link}",
                            parse_mode="HTML", reply_markup=menu())
    else:
        await msg.edit_text(f"⚠️ {err(r)}\n\nВручную: {link}", reply_markup=menu())

# ══════════════════════════════════════════════════════════════════════════════
#  📧 СМЕНА ПОЧТЫ
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "c_email")
async def email_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(ChangeEmail.s_cookie)
    await cb.message.edit_text(COOKIE_HELP, parse_mode="HTML", reply_markup=ckb())

@dp.message(ChangeEmail.s_cookie)
async def email_cookie(m: Message, state: FSMContext):
    if not g(m): return
    await check_cookie_step(m, state, ChangeEmail.s_pass, "Пароль аккаунта:")

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
    msg  = await m.answer("⏳ Меняем почту через Chromium...")
    ctx  = await mk_context(d["cookie"])
    csrf = await get_csrf(ctx)
    r    = await rbx_change_email(ctx, csrf, new_email, d["password"])
    await ctx.close(); await state.clear()
    if is_ok(r):
        await msg.edit_text(f"✅ <b>Почта изменена!</b>\n"
                            f"👤 <code>{d['username']}</code>\n"
                            f"📧 <code>{new_email}</code>",
                            parse_mode="HTML", reply_markup=menu())
    else:
        await msg.edit_text(f"❌ {err(r)}", reply_markup=menu())

# ══════════════════════════════════════════════════════════════════════════════
#  🔐 ДОБАВИТЬ 2FA
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "c_2fa_add")
async def add2fa_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(Add2FA.s_cookie)
    await cb.message.edit_text(COOKIE_HELP, parse_mode="HTML", reply_markup=ckb())

@dp.message(Add2FA.s_cookie)
async def a2_cookie(m: Message, state: FSMContext):
    if not g(m): return
    await check_cookie_step(m, state, Add2FA.s_email, "📧 Почта для добавления в 2FA:")

@dp.message(Add2FA.s_email)
async def a2_email(m: Message, state: FSMContext):
    if not g(m): return
    fa_email = m.text.strip()
    d    = await state.get_data()
    msg  = await m.answer("⏳ Добавляем 2FA через Chromium...")
    ctx  = await mk_context(d["cookie"])
    csrf = await get_csrf(ctx)
    r    = await rbx_add_2fa_email(ctx, csrf, fa_email)
    await state.update_data(fa_email=fa_email, csrf=csrf)
    await ctx.close()
    if "error" in r:
        await state.clear()
        await msg.edit_text(f"❌ {err(r)}", reply_markup=menu()); return
    await state.set_state(Add2FA.s_verify)
    await msg.edit_text(
        f"📨 Код отправлен на <code>{fa_email}</code>\n\nВведи 6-значный код:",
        parse_mode="HTML", reply_markup=ckb())

@dp.message(Add2FA.s_verify)
async def a2_verify(m: Message, state: FSMContext):
    if not g(m): return
    code = m.text.strip()
    d    = await state.get_data()
    msg  = await m.answer("⏳ Подтверждаем...")
    ctx  = await mk_context(d["cookie"])
    r    = await rbx_verify_2fa_email(ctx, d["csrf"], code)
    await ctx.close(); await state.clear()
    if is_ok(r):
        await msg.edit_text(f"✅ <b>2FA добавлена!</b>\n📧 <code>{d['fa_email']}</code>",
                            parse_mode="HTML", reply_markup=menu())
    else:
        await msg.edit_text(f"❌ {err(r)}", reply_markup=menu())

# ══════════════════════════════════════════════════════════════════════════════
#  🗑 УБРАТЬ 2FA
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "c_2fa_del")
async def del2fa_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(Del2FA.s_cookie)
    await cb.message.edit_text(COOKIE_HELP, parse_mode="HTML", reply_markup=ckb())

@dp.message(Del2FA.s_cookie)
async def d2_cookie(m: Message, state: FSMContext):
    if not g(m): return
    cookie = m.text.strip().strip('"').strip("'")
    msg    = await m.answer("⏳ Проверяем и отключаем 2FA...")
    ctx    = await mk_context(cookie)
    auth   = await rbx_check_auth(ctx)
    if "error" in auth:
        await ctx.close(); await state.clear()
        await msg.edit_text(f"❌ {err(auth)}\n\n{COOKIE_HELP}",
                            parse_mode="HTML", reply_markup=ckb()); return
    csrf = await get_csrf(ctx)
    r    = await rbx_disable_2fa(ctx, csrf)
    await ctx.close(); await state.clear()
    if is_ok(r):
        await msg.edit_text(f"✅ <b>2FA отключена!</b>\n👤 <code>{auth['name']}</code>",
                            parse_mode="HTML", reply_markup=menu())
    else:
        await msg.edit_text(f"❌ {err(r)}", reply_markup=menu())

# ══════════════════════════════════════════════════════════════════════════════
#  ⚡ МАССОВАЯ СМЕНА
#  Формат: COOKIE:пароль:новый_пароль  (режим pass)
#          COOKIE:пароль:новая_почта   (режим email)
#          COOKIE:пароль:новый_пароль:новая_почта (режим both)
# ══════════════════════════════════════════════════════════════════════════════
@dp.callback_query(F.data == "c_bulk")
async def bulk_start(cb: CallbackQuery, state: FSMContext):
    await state.set_state(Bulk.s_mode)
    await cb.message.edit_text("⚡ <b>Массовая смена</b>\n\nРежим:",
                                parse_mode="HTML", reply_markup=bmenu())

@dp.callback_query(F.data.startswith("b_"))
async def bulk_mode_cb(cb: CallbackQuery, state: FSMContext):
    mode = cb.data[2:]
    await state.update_data(mode=mode)
    await state.set_state(Bulk.s_list)
    fmt = {
        "pass":  "COOKIE:тек_пароль:новый_пароль",
        "email": "COOKIE:пароль:новая_почта",
        "both":  "COOKIE:пароль:новый_пароль:новая_почта",
    }
    lbl = {"pass": "Пароль", "email": "Почта", "both": "Пароль + Почта"}
    await cb.message.edit_text(
        f"⚡ Режим: <b>{lbl[mode]}</b>\n\n"
        f"Формат (каждый аккаунт с новой строки):\n"
        f"<code>{fmt[mode]}</code>\n\n"
        f"COOKIE = .ROBLOSECURITY из браузера",
        parse_mode="HTML", reply_markup=ckb()
    )

@dp.message(Bulk.s_list)
async def bulk_run(m: Message, state: FSMContext):
    if not g(m): return
    d     = await state.get_data()
    mode  = d["mode"]
    lines = [l.strip() for l in m.text.strip().split("\n") if l.strip()]
    await state.clear()

    msg = await m.answer(f"⚡ Запускаю {len(lines)} аккаунтов через Chromium...",
                         parse_mode="HTML")
    ok_list, fail_list = [], []
    min_p = 4 if mode == "both" else 3

    for i, line in enumerate(lines):
        # Делим только на 4 части максимум (cookie может содержать ":")
        parts = line.split(":", 3)
        if len(parts) < min_p:
            fail_list.append(f"❌ строка {i+1} — неверный формат"); continue

        cookie   = parts[0].strip()
        password = parts[1].strip()
        arg1     = parts[2].strip()
        arg2     = parts[3].strip() if mode == "both" and len(parts) > 3 else ""

        await msg.edit_text(f"⚡ [{i+1}/{len(lines)}] Аккаунт {i+1}...", parse_mode="HTML")
        ctx = None
        try:
            ctx  = await mk_context(cookie)
            auth = await rbx_check_auth(ctx)
            if "error" in auth:
                fail_list.append(f"❌ аккаунт {i+1} — {err(auth)}")
                await ctx.close(); continue

            name = auth["name"]
            await msg.edit_text(f"⚡ [{i+1}/{len(lines)}] <code>{name}</code>...",
                                parse_mode="HTML")

            csrf   = await get_csrf(ctx)
            result = {"ok": True}

            if mode in ("pass", "both"):
                result = await rbx_change_password(ctx, csrf, password, arg1)

            if is_ok(result) and mode in ("email", "both"):
                em = arg2 if mode == "both" else arg1
                pw = arg1 if mode == "both" else password
                result = await rbx_change_email(ctx, csrf, em, pw)

            if is_ok(result): ok_list.append(f"✅ {name}")
            else: fail_list.append(f"❌ {name} — {err(result)}")

        except Exception as e:
            log.error(f"bulk #{i+1} error: {e}")
            fail_list.append(f"❌ аккаунт {i+1} — {e}")
        finally:
            if ctx:
                try: await ctx.close()
                except: pass

        await asyncio.sleep(0.5)

    rep = f"⚡ <b>Готово!</b> {len(ok_list)} ✅ / {len(fail_list)} ❌\n\n"
    if ok_list:   rep += "✅ <b>Успех:</b>\n"  + "\n".join(ok_list[:40])  + "\n\n"
    if fail_list: rep += "❌ <b>Ошибки:</b>\n" + "\n".join(fail_list[:40])
    await msg.edit_text(rep, parse_mode="HTML", reply_markup=menu())

# ── main ──────────────────────────────────────────────────────────────────────
async def main():
    log.info(f"Bot started. OWNER_ID={OWNER_ID}")
    # Прогреваем браузер при старте
    await get_browser()
    log.info("Chromium готов!")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
