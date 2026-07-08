(function (window) {
    'use strict';

    const storage = {
        appCode: 'auth_current_app_code',
        openedAppCodes: 'auth_opened_app_codes'
    };

    const appBasePath = resolveAppBasePath();

    const state = {
        apiUrl: buildUrl('api/v1/index.php'),
        sessionUrl: buildUrl('sub_admin/admin_session.php'),
        loginUrl: buildUrl('admin/login/'),
        sessionToken: '',
        sessionKey: '',
        demoMode: false,
        adminUsername: '',
        adminSessionExpiresAt: '',
        adminProfile: null,
        currentAppCode: sessionStorage.getItem(storage.appCode) || '',
        currentAppName: '',
        openedAuthAppCodes: readOpenedAuthAppCodes(),
        authSection: 'cards',
        appConfigView: 'settings',
        remoteApiView: 'tokens',
        cloudStorageView: 'files',
        currentView: 'dashboard',
        selectedAppIds: new Set(),
        selectedCardIds: new Set(),
        selectedMessageIds: new Set(),
        selectedVariableIds: new Set(),
        selectedCardId: '',
        selectedCardDevices: [],
        remoteApiTokens: [],
        remoteApiLogs: [],
        cloudStorageSummary: null,
        cloudFiles: [],
        cloudStorageConfigs: [],
        cloudDownloadToken: null,
        remoteConfig: null,
        remoteVariables: [],
        integration: null,
        siteSettings: null,
        apps: [],
        cards: [],
        cardPagination: {page: 1, pageSize: 20, total: 0, totalPages: 1},
        messages: [],
        appMetrics: new Map(),
        filters: {
            cards: {search: '', status: '', durationCategory: ''},
            devices: {search: '', status: ''},
            messages: {range: '', action: '', status: '', risk: '', eventType: '', cardFingerprint: '', installId: '', ip: '', start: '', end: ''},
            variables: {search: '', scope: '', status: '', appId: ''},
            remoteApiTokens: {search: '', status: ''},
            remoteApiLogs: {search: '', status: '', tokenId: ''},
            cloudFiles: {search: '', provider: '', status: 'active'}
        }
    };

    const elements = {
        root: document.getElementById('auth-admin-root'),
        pageTitle: document.getElementById('page-title'),
        sideToggle: document.getElementById('side-toggle'),
        mobileMask: document.getElementById('mobile-mask'),
        logoButton: document.getElementById('admin-account-entry'),
        notice: document.getElementById('notice'),
        activeAppLabel: document.getElementById('active-app-label'),
        confirmModal: null,
        confirmMessage: null,
        appsGrid: document.getElementById('apps-grid'),
        recentActivity: document.getElementById('recent-activity'),
        activitySource: document.getElementById('activity-source'),
        messageSummary: document.getElementById('message-summary'),
        appBatchBar: document.getElementById('app-batch-bar'),
        cardBatchBar: document.getElementById('card-batch-bar'),
        messageBatchBar: document.getElementById('message-batch-bar'),
        authAppName: document.getElementById('auth-app-name'),
        authAppCode: document.getElementById('auth-app-code'),
        authAppTabs: document.getElementById('auth-app-tabs'),
        appSecret: null,
        appSecretTitle: null,
        appSecretLabel: null,
        appSecretBox: null,
        appPublicKey: null,
        copySecretButton: null,
        sdkDownloadTitle: null,
        sdkDownloadMeta: null,
        sdkTypeSelect: null,
        appBatchTitle: null,
        appBatchMeta: null,
        appBatchList: null,
        cardBatchTitle: null,
        cardBatchMeta: null,
        cardBatchList: null,
        cardRangeTitle: null,
        cardRangeForm: null,
        cardRangeDurationField: null,
        cardRangeDurationLabel: null,
        variableBatchTitle: null,
        variableBatchMeta: null,
        variableBatchList: null,
        cardActionTitle: null,
        cardActionMeta: null,
        cardActionList: null,
        variableModalTitle: null,
        variableForm: null,
        variableAppSearch: null,
        variableAppSelected: null,
        variableAppOptions: null,
        variableActionTitle: null,
        variableActionMeta: null,
        variableActionList: null,
        remoteApiTokenForm: null,
        cloudUploadForm: null,
        cloudStorageSummary: document.getElementById('cloud-storage-summary'),
        cloudStorageConfigForm: document.getElementById('cloud-storage-config-form'),
        cloudConfigState: document.getElementById('cloud-config-state'),
        selectedCardModalTitle: null,
        messageDetailBody: null,
        appIntegrationDocs: document.getElementById('app-integration-docs'),
        overviewCardStatus: document.getElementById('overview-card-status'),
        overviewDeviceStatus: document.getElementById('overview-device-status'),
        overviewLoginIpStats: document.getElementById('overview-login-ip-stats'),
        cardsOutput: null,
        customCardImportSummary: null,
        appSettingsForm: document.getElementById('app-settings-form'),
        appApiForm: document.getElementById('app-api-form'),
        appApiRoutes: document.getElementById('app-api-routes'),
        appSettingsMeta: document.getElementById('app-settings-meta'),
        appOperationsMeta: document.getElementById('app-operations-meta'),
        configForm: document.getElementById('config-form'),
        variableBatchBar: document.getElementById('variable-batch-bar'),
        siteSettingsForm: document.getElementById('site-settings-form'),
        siteBrandName: document.getElementById('site-brand-name'),
        siteBrandSubtitle: document.getElementById('site-brand-subtitle'),
        sideMascotImage: document.getElementById('side-mascot-image'),
        sideMascotText: document.getElementById('side-mascot-text'),
        documentTitle: document.getElementById('document-title'),
        adminProfileForm: document.getElementById('admin-profile-form'),
        adminProfileUsername: document.getElementById('admin-profile-username'),
        adminProfileCurrentUsername: document.getElementById('admin-profile-current-username'),
        adminProfileRememberStatus: document.getElementById('admin-profile-remember-status'),
        adminProfileRememberExpires: document.getElementById('admin-profile-remember-expires'),
        adminProfileSessionExpires: document.getElementById('admin-profile-session-expires'),
        adminProfileUpdatedAt: document.getElementById('admin-profile-updated-at'),
        adminProfileCreatedAt: document.getElementById('admin-profile-created-at'),
        adminAccountAvatar: document.getElementById('admin-account-avatar'),
        selectedCardEmpty: null,
        selectedCardContent: null,
        selectedCardFingerprint: null,
        selectedCardCreated: null,
        selectedCardStatus: null,
        selectedCardRemaining: null,
        selectedCardDevicesUsage: null,
        selectedCardOnline: null,
        selectedCardIps: null,
        selectedCardUsedAt: null,
        selectedCardDevices: null,
        filters: {
            cardSearch: document.getElementById('card-search'),
            cardStatus: document.getElementById('card-status-filter'),
            cardDuration: document.getElementById('card-duration-filter'),
            cardPageSize: document.getElementById('card-page-size'),
            deviceSearch: null,
            deviceStatus: null,
            variableSearch: document.getElementById('variable-search'),
            variableScope: document.getElementById('variable-scope-filter'),
            variableStatus: document.getElementById('variable-status-filter'),
            variableApp: document.getElementById('variable-app-filter'),
            remoteApiTokenSearch: document.getElementById('remote-api-token-search'),
            remoteApiTokenStatus: document.getElementById('remote-api-token-status-filter'),
            remoteApiLogSearch: document.getElementById('remote-api-log-search'),
            remoteApiLogStatus: document.getElementById('remote-api-log-status-filter'),
            remoteApiLogToken: document.getElementById('remote-api-log-token-filter'),
            cloudFileSearch: document.getElementById('cloud-file-search'),
            cloudFileProvider: document.getElementById('cloud-file-provider-filter'),
            cloudFileStatus: document.getElementById('cloud-file-status-filter'),
            messageRange: document.getElementById('message-range-filter'),
            messageStart: document.getElementById('message-start-date'),
            messageEnd: document.getElementById('message-end-date'),
            messageStatus: document.getElementById('message-status-filter'),
            messageRisk: document.getElementById('message-risk-filter'),
            messageAction: document.getElementById('message-action-filter'),
            messageEventType: document.getElementById('message-event-filter'),
            messageCardFingerprint: document.getElementById('message-card-filter'),
            messageInstallId: document.getElementById('message-install-filter'),
            messageIp: document.getElementById('message-ip-filter')
        },
        stats: {
            apps: document.getElementById('stat-apps'),
            cards: document.getElementById('stat-cards'),
            devices: document.getElementById('stat-devices'),
            sessions: document.getElementById('stat-sessions')
        },
        tables: {
            cards: document.getElementById('cards-table'),
            variables: document.getElementById('variables-table'),
            messages: document.getElementById('messages-table'),
            remoteApiTokens: document.getElementById('remote-api-tokens-table'),
            remoteApiLogs: document.getElementById('remote-api-logs-table'),
            cloudFiles: document.getElementById('cloud-files-table')
        },
        cardPageInfo: document.getElementById('card-page-info')
    };

    function saveSession(session) {
        state.sessionToken = session.session_token || '';
        state.sessionKey = session.session_key || '';
        state.demoMode = session.demo_mode === true;
        state.adminUsername = session.admin_username || '';
        state.adminSessionExpiresAt = session.expires_at || '';
    }

    function saveCurrentApp(appInfo) {
        const appRow = typeof appInfo === 'string'
            ? state.apps.find((row) => row.app_code === appInfo)
            : appInfo;
        state.currentAppCode = appRow?.app_code ? String(appRow.app_code) : '';
        state.currentAppName = appRow?.name || '';
        persistCurrentAppCode();
        rememberOpenedAuthApp(state.currentAppCode);
    }

    function closeAuthApp(appCode) {
        const normalizedCode = String(appCode || '').trim();
        state.openedAuthAppCodes = state.openedAuthAppCodes.filter((code) => code !== normalizedCode);
        persistOpenedAuthApps();
    }

    function pruneOpenedAuthApps(appCodes) {
        const validCodes = new Set(appCodes.map((appCode) => String(appCode || '').trim()).filter(Boolean));
        state.openedAuthAppCodes = state.openedAuthAppCodes.filter((appCode) => validCodes.has(appCode));
        if (state.currentAppCode && !validCodes.has(state.currentAppCode)) {
            saveCurrentApp('');
        }
        persistOpenedAuthApps();
    }

    function rememberOpenedAuthApp(appCode) {
        const normalizedCode = String(appCode || '').trim();
        if (!normalizedCode || state.openedAuthAppCodes.includes(normalizedCode)) {
            return;
        }
        state.openedAuthAppCodes.push(normalizedCode);
        persistOpenedAuthApps();
    }

    function persistCurrentAppCode() {
        if (state.currentAppCode) {
            sessionStorage.setItem(storage.appCode, state.currentAppCode);
            return;
        }
        sessionStorage.removeItem(storage.appCode);
    }

    function persistOpenedAuthApps() {
        if (state.openedAuthAppCodes.length > 0) {
            sessionStorage.setItem(storage.openedAppCodes, JSON.stringify(state.openedAuthAppCodes));
            return;
        }
        sessionStorage.removeItem(storage.openedAppCodes);
    }

    function readOpenedAuthAppCodes() {
        const rawCodes = sessionStorage.getItem(storage.openedAppCodes);
        if (!rawCodes) {
            return [];
        }
        try {
            const parsedCodes = JSON.parse(rawCodes);
            if (!Array.isArray(parsedCodes)) {
                throw new TypeError('Opened app storage must be an array');
            }
            return uniqueAppCodes(parsedCodes);
        } catch {
            sessionStorage.removeItem(storage.openedAppCodes);
            return [];
        }
    }

    function uniqueAppCodes(appCodes) {
        const uniqueCodes = [];
        appCodes.forEach((appCode) => {
            const normalizedCode = String(appCode || '').trim();
            if (normalizedCode && !uniqueCodes.includes(normalizedCode)) {
                uniqueCodes.push(normalizedCode);
            }
        });
        return uniqueCodes;
    }

    function buildUrl(path) {
        return appBasePath + path;
    }

    function resolveAppBasePath() {
        const scriptUrl = currentScriptUrl();
        const marker = '/frontend/admin-console/js/state.js';
        const markerIndex = scriptUrl.pathname.lastIndexOf(marker);
        if (markerIndex >= 0) {
            return scriptUrl.pathname.slice(0, markerIndex + 1);
        }
        return new URL('../../', window.location.href).pathname;
    }

    function currentScriptUrl() {
        const script = document.currentScript || document.querySelector('script[src*="frontend/admin-console/js/state.js"]');
        return new URL(script?.getAttribute('src') || '../../frontend/admin-console/js/state.js', window.location.href);
    }

    window.NetworkAuthAdmin = {state, elements, saveSession, saveCurrentApp, closeAuthApp, pruneOpenedAuthApps};
})(window);
