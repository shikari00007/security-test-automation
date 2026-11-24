const { app, BrowserWindow, shell, ipcMain } = require('electron');

// nodeIntegration: true  (commented, must be ignored)
function createWindow() {
  const win = new BrowserWindow({
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      sandbox: false,
      webSecurity: false,
    },
  });
  win.loadURL('http://app.example.com/index.html');
}

ipcMain.on('open-link', (event, link) => {
  shell.openExternal(link);
});

app.whenReady().then(createWindow);
