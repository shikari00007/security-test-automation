const { autoUpdater } = require('electron-updater');

autoUpdater.verifyUpdateCodeSignature = false;
autoUpdater.setFeedURL({ provider: 'generic', url: 'http://updates.example.com/releases' });
