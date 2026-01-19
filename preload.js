const { contextBridge, ipcRenderer } = require('electron');

/**
 * V12 Secure API Bridge
 * Implements Defense-in-Depth by validating inputs before they ever reach the Main process.
 */
const v12API = {
    /**
     * Retrieves the GitHub-linked user profile.
     * @returns {Promise<Object>} User data or throws error.
     */
    getUserProfile: async () => {
        try {
            return await ipcRenderer.invoke('v12:get-profile');
        } catch (err) {
            throw new Error('Identity service unavailable');
        }
    },

    /**
     * Checks if a domain (e.g., 'portfolio') is available on a TLD.
     * @param {string} domain - The name to check.
     * @returns {Promise<boolean>}
     */
    checkDomain: async (domain) => {
        if (typeof domain !== 'string' || domain.length < 3) {
            throw new Error('Domain must be at least 3 characters.');
        }
        // Sanitize input before IPC - prevents NoSQL injection
        const cleanDomain = domain.toLowerCase().replace(/[^a-z0-9-]/g, '');
        return await ipcRenderer.invoke('v12:check-domain', cleanDomain);
    },

    /**
     * Intelligent navigation: routes URLs based on format
     * - virt://domain.vc → VIRT protocol (secure internal)
     * - https://domain.com → Direct HTTPS navigation
     * - domain.com → Auto-prepend https://
     * - youtube → Auto-prepend https://
     */
    navigateToUrl: async (url) => {
        if (typeof url !== 'string' || url.trim() === '') {
            throw new Error('Invalid URL: must be non-empty string');
        }

        const cleanUrl = url.trim();

        // If already a full URL, validate and send
        if (cleanUrl.startsWith('virt://') || cleanUrl.startsWith('https://')) {
            return await ipcRenderer.invoke('v12:navigate', cleanUrl);
        }

        // For plain domain names, auto-prepend https://
        // Basic domain validation (allows subdomains, common TLDs)
        if (/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(cleanUrl)) {
            return await ipcRenderer.invoke('v12:navigate', `https://${cleanUrl}`);
        }

        // Allow search terms to be treated as domains (fallback to search)
        if (/^[a-zA-Z0-9.-]+$/.test(cleanUrl)) {
            // Try as a potential domain first
            return await ipcRenderer.invoke('v12:navigate', `https://${cleanUrl}.com`);
        }

        throw new Error('Invalid URL format');
    },

    /**
     * Fetches metadata for lookin.at search results.
     */
    fetchSearchIndex: async (query) => {
        return await ipcRenderer.invoke('v12:search', query);
    },

    /**
     * Registers a new domain in the VIRT namespace.
     * @param {Object} domainData - Domain registration data
     * @returns {Promise<Object>} Registration result
     */
    registerDomain: async (domainData) => {
        if (!domainData || typeof domainData !== 'object') {
            throw new Error('Invalid domain data: must be object');
        }
        if (!domainData.name || typeof domainData.name !== 'string') {
            throw new Error('Invalid domain name: must be string');
        }
        // Sanitize domain name
        const cleanData = {
            ...domainData,
            name: domainData.name.toLowerCase().replace(/[^a-z0-9-]/g, '')
        };
        return await ipcRenderer.invoke('v12:register-domain', cleanData);
    },

    /**
     * Fetches content from a VIRT URL.
     * @param {string} url - VIRT URL to fetch
     * @returns {Promise<Object>} Content data
     */
    fetchVirtContent: async (url) => {
        if (typeof url !== 'string' || !url.startsWith('virt://')) {
            throw new Error('Invalid VIRT URL');
        }
        return await ipcRenderer.invoke('v12:fetch-virt-content', url);
    },

    /**
     * Retrieves all bookmarks from local storage.
     * @returns {Promise<Object>} Bookmarks data in Chrome format
     */
    getBookmarks: async () => {
        return await ipcRenderer.invoke('v12:get-bookmarks');
    },

    /**
     * Saves bookmarks to local storage.
     * @param {Object} bookmarks - Bookmarks data in Chrome format
     * @returns {Promise<Object>} Save result
     */
    saveBookmarks: async (bookmarks) => {
        if (!bookmarks || typeof bookmarks !== 'object') {
            throw new Error('Invalid bookmarks data: must be object');
        }
        return await ipcRenderer.invoke('v12:save-bookmarks', bookmarks);
    },

    /**
     * Adds a new bookmark to the bookmark bar.
     * @param {Object} bookmarkData - Bookmark data with url and title
     * @returns {Promise<Object>} Add result
     */
    addBookmark: async (bookmarkData) => {
        if (!bookmarkData || typeof bookmarkData !== 'object') {
            throw new Error('Invalid bookmark data: must be object');
        }
        if (!bookmarkData.url || typeof bookmarkData.url !== 'string') {
            throw new Error('Invalid bookmark URL: must be string');
        }
        return await ipcRenderer.invoke('v12:add-bookmark', bookmarkData);
    },

    /**
     * Removes a bookmark by ID.
     * @param {string} bookmarkId - Unique bookmark identifier
     * @returns {Promise<Object>} Remove result
     */
    removeBookmark: async (bookmarkId) => {
        if (!bookmarkId || typeof bookmarkId !== 'string') {
            throw new Error('Invalid bookmark ID: must be string');
        }
        return await ipcRenderer.invoke('v12:remove-bookmark', bookmarkId);
    }
};

// 1. Expose the API
contextBridge.exposeInMainWorld('electronAPI', v12API);

// 2. Lock the API to prevent runtime tampering
Object.freeze(window.electronAPI);

// 3. Final Security Strip - handles read-only properties in newer Chrome
const dangerousGlobals = ['require', 'module', 'exports', 'process', 'Buffer'];
dangerousGlobals.forEach(prop => {
    try {
        delete window[prop];
    } catch (e) {
        // Some properties might be read-only in newer Chrome versions
    }
});
