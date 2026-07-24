//go:build windows

package main

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"

	webview "github.com/jchv/go-webview2"
)

//go:embed assets/fendit.png
var iconBytes []byte

func runUI() {
	// Lock this goroutine to its OS thread so the CBT hook and webview.New()
	// run on the same thread (CBT hooks are thread-local).
	runtime.LockOSThread()

	// WH_CBT hook: intercepts CreateWindowExW at HCBT_CREATEWND — after the
	// HWND is allocated but before ShowWindow is called. Sets WS_EX_LAYERED +
	// alpha=0 so the window is invisible at the compositor before it's ever shown.
	installCBTHook()
	w := webview.NewWithOptions(webview.WebViewOptions{
		Debug: false,
		WindowOptions: webview.WindowOptions{
			Title:  "Fendit Security",
			Width:  500,
			Height: 680,
			IconId: 1, // goversioninfo embeds our icon at resource ID 1
			Center: true,
		},
	})
	removeCBTHook()

	if w == nil {
		writeCrashLog("fatal: WebView2 runtime not available — install Microsoft Edge WebView2")
		showCrashBox(crashLogPath)
		return
	}
	defer w.Destroy()

	hwnd := w.Window()
	w.SetSize(500, 680, webview.HintFixed) // makes window non-resizable
	setWindowBackground(hwnd)
	setDarkTitleBar(hwnd)
	setWindowIcon(hwnd)

	installer := NewApp()

	// goReady is called by JS after window.load + one rAF — first paint is done.
	_ = w.Bind("goReady", func() {
		w.Dispatch(func() { makeOpaque(hwnd) })
	})

	_ = w.Bind("goInstall", func(code string) {
		go func() {
			installer.onProgress = func(msg string) {
				js, _ := json.Marshal(msg)
				w.Dispatch(func() {
					w.Eval(fmt.Sprintf("appendLog(%s)", string(js)))
				})
			}
			err := installer.Install(code)
			w.Dispatch(func() {
				if err != nil {
					js, _ := json.Marshal(err.Error())
					w.Eval(fmt.Sprintf("onInstallError(%s)", string(js)))
				} else {
					w.Eval("onInstallSuccess()")
				}
			})
		}()
	})

	_ = w.Bind("goClose", func() {
		w.Dispatch(func() { w.Terminate() })
	})

	logoB64 := base64.StdEncoding.EncodeToString(iconBytes)
	html := strings.Replace(installerHTML, "{{LOGO}}", logoB64, 1)
	w.SetHtml(html)
	w.Run()
}

const installerHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Fendit Security</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
::-webkit-scrollbar{width:4px}
::-webkit-scrollbar-track{background:#0B0D14}
::-webkit-scrollbar-thumb{background:#2A2D3E;border-radius:2px}
html,body{height:100%;overflow:hidden}
body{
  background:#0B0D14;
  color:#F0F2FF;
  font-family:'Segoe UI',system-ui,sans-serif;
  font-size:14px;
  display:flex;
  flex-direction:column;
  align-items:center;
  padding:32px 24px 20px;
  -webkit-user-select:none;
  user-select:none;
}
.logo{width:68px;height:68px;border-radius:14px;margin-bottom:14px}
.title{font-size:22px;font-weight:700;letter-spacing:.12em;color:#F0F2FF;margin-bottom:4px}
.subtitle{font-size:13px;color:#6B7085;margin-bottom:24px}
.card{
  background:#13161E;
  border:1px solid #2A2D3E;
  border-radius:12px;
  padding:18px;
  width:100%;
  max-width:448px;
  margin-bottom:14px;
}
label{display:block;font-size:13px;font-weight:600;color:#F0F2FF;margin-bottom:6px}
.hint{font-size:12px;color:#6B7085;margin-top:5px}
input[type=text]{
  width:100%;
  background:#1A1D28;
  border:1px solid #2A2D3E;
  border-radius:8px;
  color:#F0F2FF;
  font-size:15px;
  font-family:'Consolas','Courier New',monospace;
  letter-spacing:.18em;
  padding:9px 13px;
  outline:none;
  transition:border-color .15s;
  -webkit-user-select:text;
  user-select:text;
}
input[type=text]:focus{border-color:#4F46E5;box-shadow:0 0 0 3px rgba(79,70,229,.15)}
input[type=text]:disabled{opacity:.45;cursor:not-allowed}
hr{border:none;border-top:1px solid #2A2D3E;margin:15px 0}
button{
  width:100%;
  background:#4F46E5;
  color:#F0F2FF;
  border:none;
  border-radius:8px;
  font-size:14px;
  font-weight:600;
  padding:11px;
  cursor:pointer;
  transition:background .15s,opacity .15s;
}
button:hover:not(:disabled){background:#4338CA}
button:disabled{opacity:.4;cursor:not-allowed}
button.secondary{background:#2A2D3E}
button.secondary:hover:not(:disabled){background:#363A50}
.progress{width:100%;max-width:448px}
.spinner{display:none;text-align:center;padding:8px 0}
.spinner.on{display:block}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.dot{
  display:inline-block;width:7px;height:7px;
  border-radius:50%;background:#4F46E5;margin:0 3px;
  animation:pulse 1.2s ease-in-out infinite;
}
.dot:nth-child(2){animation-delay:.2s}
.dot:nth-child(3){animation-delay:.4s}
.logbox{
  display:none;
  background:#0D0F17;
  border:1px solid #2A2D3E;
  border-radius:8px;
  padding:10px 12px;
  font-family:'Consolas','Courier New',monospace;
  font-size:12px;
  line-height:1.65;
  max-height:148px;
  overflow-y:auto;
  margin-top:8px;
}
.logbox.on{display:block}
.ll{color:#A0A6BF}
.ll.ok{color:#10B981}
.ll.err{color:#EF4444}
.status{
  text-align:center;font-size:13px;
  padding:7px 0;min-height:22px;color:#6B7085;
}
.status.ok{color:#10B981}
.status.err{color:#EF4444}
.status.warn{color:#F59E0B}
</style>
</head>
<body>
<img class="logo" src="data:image/png;base64,{{LOGO}}" alt="Fendit">
<div class="title">FENDIT</div>
<div class="subtitle">Security Agent Installer</div>
<div class="card">
  <label for="code">Activation Code</label>
  <input id="code" type="text" maxlength="6" placeholder="e.g. A1B2C3"
         autocomplete="off" spellcheck="false">
  <hr>
  <button id="btn" onclick="startInstall()">Activate &amp; Install</button>
</div>
<div class="progress">
  <div class="spinner" id="spin">
    <span class="dot"></span><span class="dot"></span><span class="dot"></span>
  </div>
  <div class="logbox" id="log"></div>
  <div class="status" id="st"></div>
</div>
<script>
const inp=document.getElementById('code');
const btn=document.getElementById('btn');
const spin=document.getElementById('spin');
const log=document.getElementById('log');
const st=document.getElementById('st');

inp.addEventListener('input',()=>{
  const s=inp.selectionStart;
  inp.value=inp.value.toUpperCase();
  inp.setSelectionRange(s,s);
});
inp.addEventListener('keydown',e=>{if(e.key==='Enter')startInstall()});

function startInstall(){
  const code=inp.value.trim();
  if(code.length!==6){setStatus('Code must be exactly 6 characters.','err');return;}
  log.innerHTML='';
  setStatus('','');
  spin.classList.add('on');
  log.classList.add('on');
  btn.disabled=true;
  inp.disabled=true;
  goInstall(code);
}

function appendLog(msg){
  const d=document.createElement('div');
  d.className='ll';
  d.textContent='→  '+msg;
  log.appendChild(d);
  log.scrollTop=log.scrollHeight;
}

function onInstallSuccess(){
  spin.classList.remove('on');
  const d=document.createElement('div');
  d.className='ll ok';
  d.textContent='✓  Installation complete!';
  log.appendChild(d);
  log.scrollTop=log.scrollHeight;
  setStatus('Fendit Security Agent is now protecting this device.','ok');
  btn.textContent='Close';
  btn.className='secondary';
  btn.onclick=()=>goClose();
  btn.disabled=false;
}

function onInstallError(msg){
  spin.classList.remove('on');
  const d=document.createElement('div');
  d.className='ll err';
  d.textContent='✗  Installation failed.';
  log.appendChild(d);
  log.scrollTop=log.scrollHeight;
  setStatus(msg,'err');
  btn.disabled=false;
  inp.disabled=false;
}

function setStatus(msg,cls){
  st.textContent=msg;
  st.className='status'+(cls?' '+cls:'');
}
window.addEventListener('load',()=>requestAnimationFrame(()=>goReady()));
</script>
</body>
</html>`
