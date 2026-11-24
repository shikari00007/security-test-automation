const { autoUpdater } = require('electron-updater');

autoUpdater.verifyUpdateCodeSignature = true;
autoUpdater.setFeedURL({ provider: 'generic', url: 'https://updates.example.com/releases' });
