"""Bwrapped worker. Network is disabled; every Playwright route uses stdin/stdout IPC."""
import asyncio, json, sys, uuid

def emit(value):
    sys.stdout.write(json.dumps(value,separators=(",",":"))+"\n"); sys.stdout.flush()

async def main():
    from playwright.async_api import async_playwright
    try: initial=json.loads(sys.stdin.readline())
    except ValueError: return
    if initial.get("type")!="initialize" or initial.get("executable")!="/usr/lib/chromium/chromium": return
    async with async_playwright() as p:
        context=await p.chromium.launch_persistent_context("/tmp/profile",headless=True,executable_path=initial["executable"],service_workers="block",accept_downloads=False,args=["--no-sandbox","--single-process","--disable-gpu","--disable-background-networking","--disable-component-update","--disable-domain-reliability","--disable-sync","--metrics-recording-only","--no-first-run","--no-default-browser-check","--disable-dev-shm-usage"])
        browser=context.browser
        page=await context.new_page()
        async def popup_denied(popup):
            emit({"type":"blocked","capability":"popup"})
            await popup.close()
        page.on("popup",lambda popup: asyncio.create_task(popup_denied(popup)))
        async def websocket_denied(ws):
            emit({"type":"blocked","capability":"websocket"})
            await ws.close()
        if not hasattr(context, "route_web_socket"):
            raise RuntimeError("WebSocket containment unavailable")
        await context.route_web_socket("**/*", websocket_denied)
        route_lock=asyncio.Lock()
        async def route_handler(route):
            request=route.request; ident=uuid.uuid4().hex
            if request.resource_type=="websocket": await route.abort(); return
            async with route_lock:
                emit({"type":"route","id":ident,"url":request.url,"method":request.method})
                line=await asyncio.get_running_loop().run_in_executor(None,sys.stdin.readline)
            try: reply=json.loads(line)
            except ValueError: await route.abort(); return
            if reply.get("type")!="route_response" or reply.get("id")!=ident or reply.get("error"): await route.abort(); return
            import base64
            await route.fulfill(status=int(reply["status"]),headers=reply.get("headers",{}),body=base64.b64decode(reply["body"]))
        await context.route("**/*",route_handler)
        while True:
            line=await asyncio.get_running_loop().run_in_executor(None,sys.stdin.readline)
            if not line: break
            try: command=json.loads(line)
            except ValueError: emit({"type":"error"}); continue
            if command.get("type")!="send": emit({"type":"error"}); continue
            try:
                await page.goto(command["url"], wait_until="load", timeout=30000)
                if command.get("prompt_selector"):
                    await page.locator(command["prompt_selector"]).fill(command["prompt"])
                    await page.locator(command["submit_selector"]).click()
                text=await page.locator(command["response_selector"]).inner_text()
                emit({"type":"result","text":text})
            except Exception as exc: emit({"type":"error","code":type(exc).__name__})
        await browser.close()

if __name__=="__main__":
    try: asyncio.run(main())
    except Exception as exc: emit({"type":"error","code":type(exc).__name__})
