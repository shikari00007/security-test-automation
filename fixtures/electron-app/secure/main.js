const { app, BrowserWindow, shell, ipcMain } = require('electron');

const ALLOWED_HOSTS = new Set(['example.com', 'docs.example.com']);

function createWindow() {
  const win = new BrowserWindow({
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webSecurity: true,
    },
  });
  win.loadFile('index.html');
}

ipcMain.on('open-link', (event, link) => {
  const url = new URL(link);
  if (url.protocol === 'https:' && ALLOWED_HOSTS.has(url.hostname)) {
    shell.openExternal(url.toString());
  }
});

app.whenReady().then(createWindow);
