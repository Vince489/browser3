const { app, BrowserWindow, protocol, net, ipcMain, Menu } = require('electron');
const path = require('path');
const fs = require('fs');

// Security: Enable all recommended security settings
app.enableSandbox();

// Register VIRT as a privileged scheme (required for webviews)
protocol.registerSchemesAsPrivileged([
  {
    scheme: 'virt',
    privileges: {
      standard: true,
      secure: true,
      bypassCSP: true,
      allowServiceWorkers: true,
      supportFetchAPI: true,
      corsEnabled: true
    }
  }
]);

// Keep a global reference of the window object
let mainWindow;

// Enhanced Navigation Validator for 2026 security standards
function isValidVirtUrl(url) {
  const validTlds = ['.vc', '.vmc', '.at', '.lit'];
  const isSystemPage = url === 'virt://register.at' || url === 'virt://lookin.at' || url === 'virt://v12browser.vc';
  const hasValidTld = validTlds.some(tld => url.endsWith(tld));

  return url.startsWith('virt://') && (isSystemPage || hasValidTld);
}

function createWindow() {
  // Create the browser window with security settings
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      enableRemoteModule: false,
      preload: path.join(__dirname, 'preload.js'),
      // Additional security
      allowRunningInsecureContent: false,
      experimentalFeatures: false,
      webviewTag: true // Enable webview tag for external websites
    },
    titleBarStyle: 'hiddenInset', // macOS style
    show: false,
    icon: path.join(__dirname, 'src', 'assets', 'favicon.ico'),
    backgroundColor: '#1f2937',
    menu: null // Hide the menu bar (File, Edit, View, Window, etc.)
  });

  // Completely hide the application menu bar
  Menu.setApplicationMenu(null);

  // Load the browser UI
  mainWindow.loadFile('src/renderer/index.html');

  // Show window when ready to prevent visual flash
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();

    // Open DevTools in development
    if (process.env.NODE_ENV === 'development') {
      mainWindow.webContents.openDevTools();
    }
  });

  // Handle window closed
  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  // Prevent new window creation
  mainWindow.webContents.setWindowOpenHandler(() => {
    return { action: 'deny' };
  });

  // Handle navigation within the app - allow both VIRT and HTTPS
  mainWindow.webContents.on('will-navigate', (event, url) => {
    if (!isValidVirtUrl(url) && !url.startsWith('https://')) {
      event.preventDefault();
      console.log('Blocked navigation to:', url);
    }
  });
}

// Protocol Registration (Critical for VIRT://)
app.whenReady().then(() => {
  // Register VIRT protocol handler
  protocol.handle('virt', async (request) => {
    const urlObj = new URL(request.url);

    // Handle favicon requests automatically
    if (urlObj.pathname === '/favicon.ico') {
      const faviconPath = path.join(__dirname, 'src/assets/favicon.ico');
      if (fs.existsSync(faviconPath)) {
        return net.fetch(`file://${faviconPath}`);
      }
    }

    const hostname = urlObj.hostname; // e.g., "virtron.at"

    try {
      // Handle system sites
      if (hostname === 'register.at') {
        const pathname = urlObj.pathname;
        if (pathname === '/' || pathname === '/index.html' || pathname === '') {
          const filePath = path.join(__dirname, 'src/assets/registration.html');
          return net.fetch(`file://${filePath}`);
        } else {
          // Handle assets for registration page if needed
          const assetPath = path.join(__dirname, 'src/assets', pathname.slice(1));
          if (fs.existsSync(assetPath)) {
            return net.fetch(`file://${assetPath}`);
          } else {
            return new Response('Asset not found', { status: 404 });
          }
        }
      }

      if (hostname === 'lookin.at') {
        const pathname = urlObj.pathname;

        // Determine which file to serve
        let relativePath = (pathname === '/' || pathname === '/index.html' || pathname === '')
          ? 'search.html'
          : pathname.slice(1); // remove the leading slash

        const filePath = path.join(__dirname, 'src/assets', relativePath);

        // Safety check: does the file actually exist?
        if (fs.existsSync(filePath)) {
          // USE net.fetch with file:// protocol - it handles streams and mime-types automatically
          return net.fetch(`file://${filePath}`);
        } else {
          console.error('File not found:', filePath);
          return new Response('Not Found', { status: 404 });
        }
      }

      if (hostname === 'v12browser.vc') {
        const pathname = urlObj.pathname;

        // Determine which file to serve
        let relativePath = (pathname === '/' || pathname === '/index.html' || pathname === '')
          ? 'sales.html'
          : pathname.slice(1); // remove the leading slash

        const filePath = path.join(__dirname, 'src/assets', relativePath);

        // Safety check: does the file actually exist?
        if (fs.existsSync(filePath)) {
          // USE net.fetch with file:// protocol - it handles streams and mime-types automatically
          return net.fetch(`file://${filePath}`);
        } else {
          console.error('File not found:', filePath);
          return new Response('Not Found', { status: 404 });
        }
      }

      // DNS lookup: Ask backend where this domain points to
      const [domain, tld] = hostname.split('.');
      if (domain && tld) {
        try {
          const dnsResponse = await net.fetch(`https://virt-protocol-production.up.railway.app/api/lookup/${domain}/${tld}`);

          if (dnsResponse.ok) {
            const siteData = await dnsResponse.json();

            // Fetch content from the target URL with error handling
            try {
              return net.fetch(siteData.target);
            } catch (error) {
              console.error('Target fetch failed:', error);
              const placeholderHtml = `
                <!DOCTYPE html>
                <html>
                <head><title>V12 Browser</title></head>
                <body style="font-family: sans-serif; padding: 50px; text-align: center; background: #1f2937; color: white;">
                  <h1>Welcome to V12 Browser</h1>
                  <p>Failed to load content for <strong>${hostname}</strong>.</p>
                  <p><a href="virt://register.at" style="color: #3b82f6;">Register this domain now!</a></p>
                </body>
                </html>
              `;
              return new Response(placeholderHtml, { headers: { 'Content-Type': 'text/html' } });
            }
          }
        } catch (error) {
          console.error('DNS Lookup failed:', error);
        }
      }

      // Fallback: Domain not registered
      const placeholderHtml = `
        <!DOCTYPE html>
        <html>
        <head><title>V12 Browser</title></head>
        <body style="font-family: sans-serif; padding: 50px; text-align: center; background: #1f2937; color: white;">
          <h1>Welcome to V12 Browser</h1>
          <p>The domain <strong>${hostname}</strong> is not yet registered.</p>
          <p><a href="virt://register.at" style="color: #3b82f6;">Register this domain now!</a></p>
        </body>
        </html>
      `;

      return new Response(placeholderHtml, {
        headers: { 'Content-Type': 'text/html' }
      });

    } catch (error) {
      console.error('Protocol handler error:', error);
      return new Response('Error loading content', { status: 500 });
    }
  });

  createWindow();

  // macOS: Recreate window when dock icon is clicked
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

// Quit when all windows are closed (except on macOS)
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// Intelligent navigation handler for hybrid browsing
ipcMain.handle('v12:navigate', async (event, url) => {
  try {
    if (url.startsWith('virt://')) {
      // VIRT protocol - secure internal navigation
      if (isValidVirtUrl(url)) {
        event.sender.loadURL(url);
        return { success: true, type: 'virt' };
      } else {
        return { success: false, error: 'Invalid VIRT URL' };
      }
    } else if (url.startsWith('https://')) {
      // HTTPS protocol - allow direct navigation for web browsing
      // Security: Still validate against known malicious patterns if needed
      event.sender.loadURL(url);
      return { success: true, type: 'https' };
    } else {
      // Fallback - should not reach here due to preload validation
      return { success: false, error: 'Unsupported protocol' };
    }
  } catch (error) {
    console.error('Navigation error:', error);
    return { success: false, error: 'Navigation failed' };
  }
});

ipcMain.handle('v12:get-profile', async () => {
  // TODO: Implement GitHub OAuth integration
  return {
    username: 'developer',
    displayName: 'V12 Developer',
    authenticated: true
  };
});

ipcMain.handle('v12:check-domain', async (event, domain) => {
  // TODO: Implement MongoDB domain checking with sanitized input
  console.log('V12: Checking domain availability:', domain);
  // Input is already sanitized in preload.js
  return { available: Math.random() > 0.5 }; // Mock availability check
});

ipcMain.handle('v12:register-domain', async (event, domainData) => {
  // TODO: Implement domain registration with validation
  console.log('V12: Registering domain:', domainData);
  return { success: true, message: 'Domain registered successfully' };
});

ipcMain.handle('v12:search', async (event, query) => {
  // TODO: Implement search index fetching
  console.log('V12: Searching:', query);
  return { results: [] }; // Placeholder
});

ipcMain.handle('v12:fetch-virt-content', async (event, url) => {
  // TODO: Implement VIRT content fetching from GitHub/raw sources
  console.log('V12: Fetching content:', url);
  return { content: 'Placeholder VIRT content' };
});

// Bookmark management - local JSON storage
const bookmarksPath = path.join(app.getPath('userData'), 'bookmarks.json');

ipcMain.handle('v12:get-bookmarks', async () => {
  try {
    if (fs.existsSync(bookmarksPath)) {
      const data = fs.readFileSync(bookmarksPath, 'utf8');
      const bookmarks = JSON.parse(data);
      return bookmarks;
    }
    // Return default empty structure if no bookmarks file exists
    return {
      checksum: '',
      roots: {
        bookmark_bar: {
          children: [],
          name: 'Bookmarks bar',
          type: 'folder'
        }
      },
      version: 1
    };
  } catch (error) {
    console.error('Error loading bookmarks:', error);
    return {
      checksum: '',
      roots: {
        bookmark_bar: {
          children: [],
          name: 'Bookmarks bar',
          type: 'folder'
        }
      },
      version: 1
    };
  }
});

ipcMain.handle('v12:save-bookmarks', async (event, bookmarks) => {
  try {
    // Ensure directory exists
    const userDataPath = app.getPath('userData');
    if (!fs.existsSync(userDataPath)) {
      fs.mkdirSync(userDataPath, { recursive: true });
    }

    fs.writeFileSync(bookmarksPath, JSON.stringify(bookmarks, null, 2));
    return { success: true };
  } catch (error) {
    console.error('Error saving bookmarks:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('v12:add-bookmark', async (event, bookmarkData) => {
  try {
    // Load existing bookmarks
    let bookmarks;
    if (fs.existsSync(bookmarksPath)) {
      const data = fs.readFileSync(bookmarksPath, 'utf8');
      bookmarks = JSON.parse(data);
    } else {
      // Create default structure if no bookmarks file exists
      bookmarks = {
        checksum: '',
        roots: {
          bookmark_bar: {
            children: [],
            name: 'Bookmarks bar',
            type: 'folder'
          }
        },
        version: 1
      };
    }

    // Generate unique ID
    const id = Date.now().toString();

    // Create bookmark entry in Chrome format
    const bookmarkEntry = {
      date_added: Date.now().toString(),
      id: id,
      name: bookmarkData.title || bookmarkData.url,
      type: 'url',
      url: bookmarkData.url
    };

    // Check for duplicates
    const existing = bookmarks.roots.bookmark_bar.children.find(b => b.url === bookmarkData.url);
    if (existing) {
      return { success: false, message: 'Already bookmarked' };
    }

    // Add to bookmark bar
    bookmarks.roots.bookmark_bar.children.push(bookmarkEntry);

    // Save updated bookmarks
    const userDataPath = app.getPath('userData');
    if (!fs.existsSync(userDataPath)) {
      fs.mkdirSync(userDataPath, { recursive: true });
    }
    fs.writeFileSync(bookmarksPath, JSON.stringify(bookmarks, null, 2));

    return { success: true };
  } catch (error) {
    console.error('Error adding bookmark:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('v12:remove-bookmark', async (event, bookmarkId) => {
  try {
    // Load existing bookmarks
    let bookmarks;
    if (fs.existsSync(bookmarksPath)) {
      const data = fs.readFileSync(bookmarksPath, 'utf8');
      bookmarks = JSON.parse(data);
    } else {
      return { success: false, message: 'No bookmarks file found' };
    }

    // Find and remove bookmark
    const bookmarkBar = bookmarks.roots.bookmark_bar;
    const index = bookmarkBar.children.findIndex(b => b.id === bookmarkId);

    if (index === -1) {
      return { success: false, message: 'Bookmark not found' };
    }

    bookmarkBar.children.splice(index, 1);

    // Save updated bookmarks
    const userDataPath = app.getPath('userData');
    if (!fs.existsSync(userDataPath)) {
      fs.mkdirSync(userDataPath, { recursive: true });
    }
    fs.writeFileSync(bookmarksPath, JSON.stringify(bookmarks, null, 2));

    return { success: true };
  } catch (error) {
    console.error('Error removing bookmark:', error);
    return { success: false, error: error.message };
  }
});

// Legacy IPC handlers (deprecated - use v12: prefixed versions above)
ipcMain.handle('get-user-profile', () => {
  // TODO: Implement user profile management
  return {
    username: 'developer',
    displayName: 'V12 Developer'
  };
});

ipcMain.handle('check-domain', async (event, domain) => {
  // TODO: Implement domain checking against backend
  console.log('Checking domain:', domain);
  return { available: true };
});

ipcMain.handle('register-domain', async (event, domainData) => {
  // TODO: Implement domain registration
  console.log('Registering domain:', domainData);
  return { success: true };
});

ipcMain.handle('fetch-virt-content', async (event, url) => {
  // TODO: Implement content fetching
  console.log('Fetching VIRT content:', url);
  return { content: 'Placeholder content' };
});

// Security: Prevent new window creation
app.on('web-contents-created', (event, contents) => {
  contents.on('new-window', (event, navigationUrl) => {
    event.preventDefault();
    console.log('Blocked new window creation:', navigationUrl);
  });

  contents.on('will-navigate', (event, navigationUrl) => {
    if (!navigationUrl.startsWith('virt://') && !navigationUrl.startsWith('https://')) {
      event.preventDefault();
      console.log('Blocked navigation:', navigationUrl);
    }
  });
});
